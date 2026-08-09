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
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const (
	dtls13Version               = 0xfefc
	shimID                      = uint64(1)
	packetedBIOOpcode           = byte('P')
	packetedBIOTimeoutOpcode    = byte('T')
	packetedBIOTimeoutACKOpcode = byte('t')
	packetedBIOHeaderSize       = 5
	packetedBIOTimeoutFrameSize = 9
	maxPacketedBIODatagramSize  = 1<<16 - 1
	boringSSLX25519CurveGroupID = 29

	boringSSL13MessageTrace                    = "read hs 1\nwrite hs 2\nwrite hs 8\nwrite hs 11\nwrite hs 15\nwrite hs 20\nread hs 20\nwrite ack\nread alert 1 0\n"                               // nolint:lll
	boringSSL13ClientMessageTrace              = "write hs 1\nread hs 2\nread hs 8\nread hs 11\nread hs 15\nread hs 20\nwrite hs 20\nread ack\nread hs 4\nread alert 1 0\n"                        // nolint:lll
	boringSSL13PeerKeyUpdateMessageTrace       = "read hs 1\nwrite hs 2\nwrite hs 8\nwrite hs 11\nwrite hs 15\nwrite hs 20\nread hs 20\nwrite ack\nwrite hs 24\nread ack\nread alert 1 0\n"        // nolint:lll
	boringSSL13PeerKeyUpdateClientMessageTrace = "write hs 1\nread hs 2\nread hs 8\nread hs 11\nread hs 15\nread hs 20\nwrite hs 20\nread ack\nread hs 4\nwrite hs 24\nread ack\nread alert 1 0\n" // nolint:lll
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
	timeoutACK chan struct{}
	writeCount atomic.Uint64
	writeEvent chan struct{}
	writes     []packetedWrite
}

type packetedWrite struct {
	number uint64
	size   int
}

type boringSSLCredentials struct {
	directory       string
	certificatePath string
	privateKeyPath  string
}

type boringSSLProbeOptions struct {
	boringSSLKeyUpdate bool
	pionKeyUpdate      pionKeyUpdateFunc
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
	if err := probeBoringSSL13PionClient(ctx, shimPath, stdout, commandContext); err != nil {
		return err
	}

	return probeBoringSSL13PionServer(ctx, shimPath, stdout, commandContext)
}

func probeBoringSSL13PionClient(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	return probeBoringSSL13PionClientWithOptions(
		ctx,
		shimPath,
		stdout,
		commandContext,
		boringSSLProbeOptions{},
	)
}

func probeBoringSSL13PionClientWithOptions(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
	options boringSSLProbeOptions,
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

	process, err := startBoringSSLShim(
		ctx,
		shimPath,
		tcpAddress.Port,
		credentials,
		options,
		commandContext,
	)
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
	_, _ = fmt.Fprintln(stdout, "BoringSSL server shim TCP bootstrap connected")

	packetedConnection := newPacketedConn(connection)
	if err = runPionDTLS13Client(ctx, packetedConnection, stdout, options); err != nil {
		process.stop()

		return process.outputError(err)
	}
	if err = process.wait(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "BoringSSL server acknowledged Pion's final handshake flight")

	return nil
}

func probeBoringSSL13PionServer(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	return probeBoringSSL13PionServerWithOptions(
		ctx,
		shimPath,
		stdout,
		commandContext,
		boringSSLProbeOptions{},
	)
}

func probeBoringSSL13PionServerWithOptions(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
	options boringSSLProbeOptions,
) error {
	if shimPath == "" {
		return errEmptyShimPath
	}

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

	process, err := startBoringSSLClientShim(ctx, shimPath, tcpAddress.Port, options, commandContext)
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
	_, _ = fmt.Fprintln(stdout, "BoringSSL client shim TCP bootstrap connected")

	packetedConnection := newPacketedConn(connection)
	if err = runPionDTLS13Server(ctx, packetedConnection, stdout, options); err != nil {
		process.stop()

		return process.outputError(err)
	}
	if err = process.wait(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "BoringSSL client accepted Pion's terminal ACK")

	return nil
}

func startBoringSSLShim(
	ctx context.Context,
	shimPath string,
	port int,
	credentials *boringSSLCredentials,
	options boringSSLProbeOptions,
	commandContext commandContextFunc,
) (*shimProcess, error) {
	childCtx, cancelChild := context.WithCancel(ctx)
	process := &shimProcess{
		cancel:   cancelChild,
		waitDone: make(chan struct{}),
	}
	arguments := []string{
		"-port", strconv.Itoa(port),
		"-shim-id", strconv.FormatUint(shimID, 10),
		"-dtls",
		"-server",
		"-min-version", strconv.Itoa(dtls13Version),
		"-max-version", strconv.Itoa(dtls13Version),
		"-curves", strconv.Itoa(boringSSLX25519CurveGroupID),
		"-cert-file", credentials.certificatePath,
		"-key-file", credentials.privateKeyPath,
		"-no-ticket",
		"-shim-writes-first",
	}
	messageTrace := boringSSL13MessageTrace
	if options.boringSSLKeyUpdate {
		arguments = append(arguments, "-key-update")
		messageTrace = boringSSL13PeerKeyUpdateMessageTrace
	} else if options.pionKeyUpdate != nil {
		arguments = append(arguments, "-async")
		messageTrace = ""
	}
	if messageTrace != "" {
		arguments = append(arguments, "-expect-msg-callback", messageTrace)
	}
	command := commandContext(childCtx, shimPath, arguments...)
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
	options boringSSLProbeOptions,
	commandContext commandContextFunc,
) (*shimProcess, error) {
	childCtx, cancelChild := context.WithCancel(ctx)
	process := &shimProcess{
		cancel:   cancelChild,
		waitDone: make(chan struct{}),
	}
	arguments := []string{
		"-port", strconv.Itoa(port),
		"-shim-id", strconv.FormatUint(shimID, 10),
		"-dtls",
		"-min-version", strconv.Itoa(dtls13Version),
		"-max-version", strconv.Itoa(dtls13Version),
		"-curves", strconv.Itoa(boringSSLX25519CurveGroupID),
		"-no-ticket",
		"-shim-writes-first",
	}
	messageTrace := boringSSL13ClientMessageTrace
	if options.boringSSLKeyUpdate {
		arguments = append(arguments, "-key-update")
		messageTrace = boringSSL13PeerKeyUpdateClientMessageTrace
	} else if options.pionKeyUpdate != nil {
		arguments = append(arguments, "-async")
		messageTrace = ""
	}
	if messageTrace != "" {
		arguments = append(arguments, "-expect-msg-callback", messageTrace)
	}
	command := commandContext(childCtx, shimPath, arguments...)
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

func newPacketedConn(connection net.Conn) *packetedConn {
	return &packetedConn{
		Conn:       connection,
		timeoutACK: make(chan struct{}, 1),
		writeEvent: make(chan struct{}, 1),
	}
}

func (connection *packetedConn) Read(payload []byte) (int, error) {
	connection.readMutex.Lock()
	defer connection.readMutex.Unlock()

	for {
		var opcode [1]byte
		if _, err := io.ReadFull(connection.Conn, opcode[:]); err != nil {
			return 0, fmt.Errorf("read BoringSSL packeted BIO opcode: %w", err)
		}
		switch opcode[0] {
		case packetedBIOTimeoutACKOpcode:
			select {
			case connection.timeoutACK <- struct{}{}:
			default:
			}

			continue
		case packetedBIOOpcode:
			return connection.readPacketedBIODatagram(payload)
		default:
			return 0, fmt.Errorf("%w: got %q", errUnexpectedPacketedBIOOpcode, opcode[0])
		}
	}
}

func (connection *packetedConn) readPacketedBIODatagram(payload []byte) (int, error) {
	var encodedSizeRaw [4]byte
	if _, err := io.ReadFull(connection.Conn, encodedSizeRaw[:]); err != nil {
		return 0, fmt.Errorf("read BoringSSL packeted BIO size: %w", err)
	}
	encodedSize := binary.BigEndian.Uint32(encodedSizeRaw[:])
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
	writeNumber := connection.writeCount.Add(1)
	connection.writes = append(connection.writes, packetedWrite{number: writeNumber, size: len(payload)})
	select {
	case connection.writeEvent <- struct{}{}:
	default:
	}

	return len(payload), nil
}

func (connection *packetedConn) waitForWriteSizeAfter(
	ctx context.Context,
	after uint64,
	size int,
) error {
	for {
		if connection.hasWriteSizeAfter(after, size) {
			return nil
		}

		select {
		case <-connection.writeEvent:
		case <-ctx.Done():
			return fmt.Errorf("wait for Pion packeted BIO write of %d bytes: %w", size, ctx.Err())
		}
	}
}

func (connection *packetedConn) hasWriteSizeAfter(after uint64, size int) bool {
	connection.writeMutex.Lock()
	defer connection.writeMutex.Unlock()

	for _, write := range connection.writes {
		if write.number > after && write.size == size {
			return true
		}
	}

	return false
}

func (connection *packetedConn) advanceClock(ctx context.Context, duration time.Duration) error {
	var frame [packetedBIOTimeoutFrameSize]byte
	frame[0] = packetedBIOTimeoutOpcode
	binary.BigEndian.PutUint64(frame[1:], uint64(duration)) //nolint:gosec // caller supplies a positive duration

	connection.writeMutex.Lock()
	written, err := connection.Conn.Write(frame[:])
	connection.writeMutex.Unlock()
	if err != nil {
		return fmt.Errorf("advance BoringSSL packeted BIO clock: %w", err)
	}
	if written != len(frame) {
		return fmt.Errorf("advance BoringSSL packeted BIO clock: %w", io.ErrShortWrite)
	}

	select {
	case <-connection.timeoutACK:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("advance BoringSSL packeted BIO clock: %w", ctx.Err())
	}
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
