// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const (
	dtls13Version               = 0xfefc
	shimID                      = uint64(1)
	packetedBIOOpcode           = byte('P')
	packetedBIOHeaderSize       = 5
	maxPacketedBIODatagramSize  = 1<<16 - 1
	boringSSLX25519CurveGroupID = 29

	boringSSL13MessageTrace       = "read hs 1\nwrite hs 2\nwrite hs 8\nwrite hs 11\nwrite hs 15\nwrite hs 20\nread hs 20\nwrite ack\nread alert 1 0\n"        // nolint:lll
	boringSSL13ClientMessageTrace = "write hs 1\nread hs 2\nread hs 8\nread hs 11\nread hs 15\nread hs 20\nwrite hs 20\nread ack\nread hs 4\nread alert 1 0\n" // nolint:lll
)

var (
	errEmptyShimPath               = errors.New("bssl_shim path must not be empty")
	errUnexpectedListener          = errors.New("unexpected listener address")
	errUnexpectedShimID            = errors.New("unexpected bssl_shim ID")
	errUnexpectedPacketedBIOOpcode = errors.New("unexpected BoringSSL packeted BIO opcode")
	errPacketedBIODatagramTooLarge = errors.New("BoringSSL packeted BIO datagram is too large")
	errGeneratedCertificateEmpty   = errors.New("generated BoringSSL certificate is empty")
	errShimExitedBeforeConnect     = errors.New("bssl_shim exited before connecting")
	errShimExitedUnsuccessfully    = errors.New("bssl_shim exited unsuccessfully")
)

type packetedConn struct {
	net.Conn

	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

type boringSSLCredentials struct {
	directory       string
	certificatePath string
	privateKeyPath  string
}

type shimProcess struct {
	cancel   context.CancelFunc
	waitDone chan struct{}
	waitErr  error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

func probeBoringSSL13(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	if shimPath == "" {
		return errEmptyShimPath
	}

	credentials, err := newBoringSSLCredentials()
	if err != nil {
		return err
	}
	defer credentials.remove()

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for bssl_shim: %w", err)
	}
	defer func() { _ = listener.Close() }()

	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("%w: %q", errUnexpectedListener, listener.Addr())
	}

	process, err := startBoringSSLShim(ctx, shimPath, tcpAddress.Port, credentials, commandContext)
	if err != nil {
		return err
	}

	defer process.stop()

	connection, err := acceptShimConnection(ctx, listener, process)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()

	if err = readAndValidateShimID(ctx, connection); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		stdout,
		"PASS %s: shim TCP bootstrap connected\n",
		boringSSL13Mode,
	)

	packetedConnection := &packetedConn{Conn: connection}
	if err = runPionDTLS13Client(ctx, packetedConnection, stdout); err != nil {
		process.stop()

		return process.outputError(err)
	}
	if err = process.wait(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "PASS %s: BoringSSL acknowledged Pion's final handshake flight\n", boringSSL13Mode)

	return probeBoringSSL13PionServer(ctx, shimPath, stdout, commandContext)
}

func probeBoringSSL13PionServer(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for bssl_shim: %w", err)
	}
	defer func() { _ = listener.Close() }()

	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("%w: %q", errUnexpectedListener, listener.Addr())
	}

	process, err := startBoringSSLClientShim(ctx, shimPath, tcpAddress.Port, commandContext)
	if err != nil {
		return err
	}
	defer process.stop()

	connection, err := acceptShimConnection(ctx, listener, process)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()

	if err = readAndValidateShimID(ctx, connection); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		stdout,
		"PASS %s (Pion server / BoringSSL client): shim TCP bootstrap connected\n",
		boringSSL13Mode,
	)

	packetedConnection := &packetedConn{Conn: connection}
	if err = runPionDTLS13Server(ctx, packetedConnection, stdout); err != nil {
		process.stop()

		return process.outputError(err)
	}
	if err = process.wait(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		stdout,
		"PASS %s (Pion server / BoringSSL client): BoringSSL accepted Pion's terminal ACK\n",
		boringSSL13Mode,
	)

	return nil
}

func startBoringSSLShim(
	ctx context.Context,
	shimPath string,
	port int,
	credentials *boringSSLCredentials,
	commandContext commandContextFunc,
) (*shimProcess, error) {
	childCtx, cancelChild := context.WithCancel(ctx)
	process := &shimProcess{
		cancel:   cancelChild,
		waitDone: make(chan struct{}),
	}
	command := commandContext(
		childCtx,
		shimPath,
		"-port", strconv.Itoa(port),
		"-shim-id", strconv.FormatUint(shimID, 10),
		"-dtls",
		"-server",
		"-expect-msg-callback", boringSSL13MessageTrace,
		"-min-version", strconv.Itoa(dtls13Version),
		"-max-version", strconv.Itoa(dtls13Version),
		"-curves", strconv.Itoa(boringSSLX25519CurveGroupID),
		"-cert-file", credentials.certificatePath,
		"-key-file", credentials.privateKeyPath,
		"-no-ticket",
		"-shim-writes-first",
	)
	command.Stdout = &process.stdout
	command.Stderr = &process.stderr

	if err := command.Start(); err != nil {
		cancelChild()

		return nil, fmt.Errorf("start bssl_shim: %w", err)
	}

	go func() {
		process.waitErr = command.Wait()
		close(process.waitDone)
	}()

	return process, nil
}

func startBoringSSLClientShim(
	ctx context.Context,
	shimPath string,
	port int,
	commandContext commandContextFunc,
) (*shimProcess, error) {
	childCtx, cancelChild := context.WithCancel(ctx)
	process := &shimProcess{
		cancel:   cancelChild,
		waitDone: make(chan struct{}),
	}
	command := commandContext(
		childCtx,
		shimPath,
		"-port", strconv.Itoa(port),
		"-shim-id", strconv.FormatUint(shimID, 10),
		"-dtls",
		"-expect-msg-callback", boringSSL13ClientMessageTrace,
		"-min-version", strconv.Itoa(dtls13Version),
		"-max-version", strconv.Itoa(dtls13Version),
		"-curves", strconv.Itoa(boringSSLX25519CurveGroupID),
		"-no-ticket",
		"-shim-writes-first",
	)
	command.Stdout = &process.stdout
	command.Stderr = &process.stderr

	if err := command.Start(); err != nil {
		cancelChild()

		return nil, fmt.Errorf("start bssl_shim: %w", err)
	}

	go func() {
		process.waitErr = command.Wait()
		close(process.waitDone)
	}()

	return process, nil
}

func acceptShimConnection(
	ctx context.Context,
	listener net.Listener,
	process *shimProcess,
) (net.Conn, error) {
	type acceptResult struct {
		connection net.Conn
		err        error
	}

	accepted := make(chan acceptResult, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- acceptResult{connection: connection, err: err}
	}()

	select {
	case result := <-accepted:
		if result.err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("wait for bssl_shim TCP connection: %w", ctx.Err())
			}

			return nil, fmt.Errorf("accept bssl_shim TCP connection: %w", result.err)
		}

		return result.connection, nil
	case <-process.waitDone:
		if ctx.Err() != nil {
			return nil, fmt.Errorf("wait for bssl_shim TCP connection: %w", ctx.Err())
		}

		return nil, process.outputError(errShimExitedBeforeConnect)
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for bssl_shim TCP connection: %w", ctx.Err())
	}
}

func readAndValidateShimID(ctx context.Context, connection net.Conn) error {
	stopCloseOnCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopCloseOnCancellation()

	var encodedID [8]byte
	if _, err := io.ReadFull(connection, encodedID[:]); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("read bssl_shim ID: %w", ctx.Err())
		}

		return fmt.Errorf("read bssl_shim ID: %w", err)
	}

	receivedID := binary.LittleEndian.Uint64(encodedID[:])
	if receivedID != shimID {
		return fmt.Errorf("%w: got %d, want %d", errUnexpectedShimID, receivedID, shimID)
	}

	return nil
}

func newBoringSSLCredentials() (*boringSSLCredentials, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("generate BoringSSL certificate: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errGeneratedCertificateEmpty
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal BoringSSL private key: %w", err)
	}

	directory, err := os.MkdirTemp("", "dtls-interop-boringssl-")
	if err != nil {
		return nil, fmt.Errorf("create BoringSSL credential directory: %w", err)
	}
	credentials := &boringSSLCredentials{
		directory:       directory,
		certificatePath: filepath.Join(directory, "certificate.pem"),
		privateKeyPath:  filepath.Join(directory, "private-key.pem"),
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	if err = os.WriteFile(credentials.certificatePath, certificatePEM, 0o600); err != nil {
		credentials.remove()

		return nil, fmt.Errorf("write BoringSSL certificate: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
	if err = os.WriteFile(credentials.privateKeyPath, privateKeyPEM, 0o600); err != nil {
		credentials.remove()

		return nil, fmt.Errorf("write BoringSSL private key: %w", err)
	}

	return credentials, nil
}

func (credentials *boringSSLCredentials) remove() {
	_ = os.RemoveAll(credentials.directory)
}

func (connection *packetedConn) Read(payload []byte) (int, error) {
	connection.readMutex.Lock()
	defer connection.readMutex.Unlock()

	var header [packetedBIOHeaderSize]byte
	if _, err := io.ReadFull(connection.Conn, header[:]); err != nil {
		return 0, fmt.Errorf("read BoringSSL packeted BIO header: %w", err)
	}
	if header[0] != packetedBIOOpcode {
		return 0, fmt.Errorf("%w: got %q", errUnexpectedPacketedBIOOpcode, header[0])
	}

	encodedSize := binary.BigEndian.Uint32(header[1:])
	if encodedSize > maxPacketedBIODatagramSize {
		return 0, fmt.Errorf("%w: got %d bytes", errPacketedBIODatagramTooLarge, encodedSize)
	}

	packetSize := int(encodedSize)
	if packetSize > len(payload) {
		if _, err := io.CopyN(io.Discard, connection.Conn, int64(packetSize)); err != nil {
			return 0, fmt.Errorf("discard oversized BoringSSL packeted BIO datagram: %w", err)
		}

		return 0, fmt.Errorf("%w: got %d bytes for a %d-byte buffer", io.ErrShortBuffer, packetSize, len(payload))
	}

	read, err := io.ReadFull(connection.Conn, payload[:packetSize])
	if err != nil {
		return read, fmt.Errorf("read BoringSSL packeted BIO datagram: %w", err)
	}

	return read, nil
}

func (connection *packetedConn) Write(payload []byte) (int, error) {
	if len(payload) > maxPacketedBIODatagramSize {
		return 0, fmt.Errorf("%w: got %d bytes", errPacketedBIODatagramTooLarge, len(payload))
	}

	connection.writeMutex.Lock()
	defer connection.writeMutex.Unlock()

	frame := make([]byte, packetedBIOHeaderSize+len(payload))
	frame[0] = packetedBIOOpcode
	// The size check above bounds this conversion to 16 bits.
	binary.BigEndian.PutUint32(frame[1:packetedBIOHeaderSize], uint32(len(payload))) //nolint:gosec
	copy(frame[packetedBIOHeaderSize:], payload)

	written, err := connection.Conn.Write(frame)
	if err != nil {
		return 0, fmt.Errorf("write BoringSSL packeted BIO datagram: %w", err)
	}
	if written != len(frame) {
		return 0, fmt.Errorf("write BoringSSL packeted BIO datagram: %w", io.ErrShortWrite)
	}

	return len(payload), nil
}

func (process *shimProcess) wait(ctx context.Context) error {
	select {
	case <-process.waitDone:
		if process.waitErr != nil {
			return process.outputError(errShimExitedUnsuccessfully)
		}

		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for bssl_shim exit: %w", ctx.Err())
	}
}

func (process *shimProcess) stop() {
	process.cancel()
	<-process.waitDone
}

func (process *shimProcess) outputError(cause error) error {
	details := make([]string, 0, 3)
	if process.waitErr != nil {
		details = append(details, "process: "+process.waitErr.Error())
	}
	if output := strings.TrimSpace(process.stdout.String()); output != "" {
		details = append(details, "stdout: "+output)
	}
	if output := strings.TrimSpace(process.stderr.String()); output != "" {
		details = append(details, "stderr: "+output)
	}

	if len(details) == 0 {
		return cause
	}

	return fmt.Errorf("%w (%s)", cause, strings.Join(details, "; "))
}
