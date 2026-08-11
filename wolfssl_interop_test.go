// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

const wolfSSLApplicationMessage = "hello wolfssl!"

type wolfSSLCIDTestCase struct {
	name              string
	pionCIDEnabled    bool
	pionReceiveCID    []byte
	wolfSSLCIDEnabled bool
	wolfSSLReceiveCID string
}

type wolfSSLProcess struct {
	cancel   context.CancelFunc
	waitDone chan struct{}
	waitErr  error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

type wolfSSLAcceptResult struct {
	connection net.Conn
	err        error
}

func TestWolfSSLDTLS13Interop(t *testing.T) {
	testCases := []wolfSSLCIDTestCase{
		{name: "NoCID"},
		{
			name:              "ZeroLengthCID",
			pionCIDEnabled:    true,
			wolfSSLCIDEnabled: true,
		},
		{
			name:              "NonZeroCID",
			pionCIDEnabled:    true,
			pionReceiveCID:    []byte("pion-cid"),
			wolfSSLCIDEnabled: true,
			wolfSSLReceiveCID: "wolf-id",
		},
		{
			name:              "PionZeroLength_WolfSSLNonZero",
			pionCIDEnabled:    true,
			wolfSSLCIDEnabled: true,
			wolfSSLReceiveCID: "wolf-id",
		},
		{
			name:              "PionNonZero_WolfSSLZeroLength",
			pionCIDEnabled:    true,
			pionReceiveCID:    []byte("pion-cid"),
			wolfSSLCIDEnabled: true,
		},
	}

	t.Run("PionClient_WolfSSLServer", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				testPionClientWolfSSLServer(t, testCase)
			})
		}
	})
	t.Run("PionServer_WolfSSLClient", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				testPionServerWolfSSLClient(t, testCase)
			})
		}
	})
}

func testPionClientWolfSSLServer(t *testing.T, testCase wolfSSLCIDTestCase) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()

	serverAddress := reserveWolfSSLAddress(t)
	serverArguments := []string{
		"-u",
		"-v", "4",
		"-p", strconv.Itoa(serverAddress.Port),
		"-d",
		"-e",
	}
	serverArguments = append(serverArguments, testCase.wolfSSLArguments()...)
	process := startWolfSSLProcess(
		t,
		ctx,
		environmentOrDefault("DTLS_INTEROP_WOLFSSL_SERVER_BIN", "wolfssl-dtls13-server"),
		serverArguments...,
	)

	clientOptions := []dtls.ClientOption{
		dtls.WithInsecureSkipVerify(true),
		dtls.WithEllipticCurves(elliptic.P256),
		dtls.WithCipherSuites(dtls.TLS_AES_128_GCM_SHA256),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	}
	if cidOption := testCase.pionCIDOption(); cidOption != nil {
		clientOptions = append(clientOptions, cidOption)
	}
	client, err := dtls.DialWithOptions(
		"udp4",
		serverAddress,
		clientOptions...,
	)
	process.requireNoError(t, "dial wolfSSL DTLS 1.3 server", err)
	t.Cleanup(func() { _ = client.Close() })

	setWolfSSLDeadline(t, ctx, client)
	process.requireNoError(t, "complete Pion DTLS 1.3 client handshake", client.HandshakeContext(ctx))
	t.Log("Pion DTLS 1.3 client handshake completed")

	writeWolfSSLMessage(t, process, client)
	readWolfSSLMessage(t, process, client)
	t.Log("wolfSSL received and echoed Pion application data")

	process.requireNoError(t, "close Pion DTLS connection", client.Close())
	process.wait(t, ctx)
	process.requireCIDNegotiation(t, testCase)
}

func testPionServerWolfSSLClient(t *testing.T, testCase wolfSSLCIDTestCase) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	serverOptions := []dtls.ServerOption{
		dtls.WithCertificates(certificate),
		dtls.WithEllipticCurves(elliptic.P256),
		dtls.WithCipherSuites(dtls.TLS_AES_128_GCM_SHA256),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	}
	if cidOption := testCase.pionCIDOption(); cidOption != nil {
		serverOptions = append(serverOptions, cidOption)
	}
	listener, err := dtls.ListenWithOptions(
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		serverOptions...,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	address, ok := listener.Addr().(*net.UDPAddr)
	require.Truef(t, ok, "unexpected Pion DTLS listener address type %T", listener.Addr())
	clientArguments := []string{
		"-h", "127.0.0.1",
		"-p", strconv.Itoa(address.Port),
		"-u",
		"-v", "4",
		"-d",
		"-x",
	}
	clientArguments = append(clientArguments, testCase.wolfSSLArguments()...)
	process := startWolfSSLProcess(
		t,
		ctx,
		environmentOrDefault("DTLS_INTEROP_WOLFSSL_CLIENT_BIN", "wolfssl-dtls13-client"),
		clientArguments...,
	)

	server := acceptWolfSSLConnection(t, ctx, listener, process)
	t.Cleanup(func() { _ = server.Close() })
	setWolfSSLDeadline(t, ctx, server)
	process.requireNoError(t, "complete Pion DTLS 1.3 server handshake", server.HandshakeContext(ctx))
	t.Log("Pion DTLS 1.3 server handshake completed")

	readWolfSSLMessage(t, process, server)
	writeWolfSSLMessage(t, process, server)
	t.Log("Pion received and echoed wolfSSL application data")

	process.wait(t, ctx)
	process.requireCIDNegotiation(t, testCase)
	process.requireNoError(t, "close Pion DTLS connection", server.Close())
}

func (testCase wolfSSLCIDTestCase) pionCIDOption() dtls.Option {
	if !testCase.pionCIDEnabled {
		return nil
	}

	cid := bytes.Clone(testCase.pionReceiveCID)

	return dtls.WithConnectionIDGenerator(func() []byte {
		return bytes.Clone(cid)
	})
}

func (testCase wolfSSLCIDTestCase) wolfSSLArguments() []string {
	if !testCase.wolfSSLCIDEnabled {
		return nil
	}

	arguments := []string{"--cid"}
	if testCase.wolfSSLReceiveCID != "" {
		arguments = append(arguments, testCase.wolfSSLReceiveCID)
	}

	return arguments
}

func startWolfSSLProcess(t *testing.T, ctx context.Context, path string, arguments ...string) *wolfSSLProcess {
	t.Helper()

	childCtx, cancelChild := context.WithCancel(ctx)
	process := &wolfSSLProcess{
		cancel:   cancelChild,
		waitDone: make(chan struct{}),
	}
	command := exec.CommandContext(childCtx, path, arguments...) //nolint:gosec // Test binary path is configurable.
	command.Stdout = &process.stdout
	command.Stderr = &process.stderr
	startErr := command.Start()
	if startErr != nil {
		cancelChild()
	}
	require.NoError(t, startErr, "start wolfSSL DTLS 1.3 process")

	go func() {
		process.waitErr = command.Wait()
		close(process.waitDone)
	}()
	t.Cleanup(process.stop)

	return process
}

func acceptWolfSSLConnection(
	t *testing.T,
	ctx context.Context,
	listener net.Listener,
	process *wolfSSLProcess,
) *dtls.Conn {
	t.Helper()

	accepted := make(chan wolfSSLAcceptResult, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- wolfSSLAcceptResult{connection: connection, err: err}
	}()

	select {
	case result := <-accepted:
		process.requireNoError(t, "accept Pion DTLS connection", result.err)
		server, ok := result.connection.(*dtls.Conn)
		require.Truef(t, ok, "unexpected Pion DTLS connection type %T", result.connection)

		return server
	case <-process.waitDone:
		require.FailNowf(t, "wolfSSL exited before the handshake", "%s", process.output())
	case <-ctx.Done():
		_ = listener.Close()
		process.stop()
		require.NoErrorf(t, ctx.Err(), "accept Pion DTLS connection%s", process.output())
	}

	return nil
}

func reserveWolfSSLAddress(t *testing.T) *net.UDPAddr {
	t.Helper()

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	address, ok := listener.LocalAddr().(*net.UDPAddr)
	require.Truef(t, ok, "unexpected wolfSSL listener address type %T", listener.LocalAddr())
	require.NoError(t, listener.Close())

	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: address.Port}
}

func setWolfSSLDeadline(t *testing.T, ctx context.Context, connection net.Conn) {
	t.Helper()

	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, connection.SetDeadline(deadline))
}

func writeWolfSSLMessage(t *testing.T, process *wolfSSLProcess, connection net.Conn) {
	t.Helper()

	written, err := connection.Write([]byte(wolfSSLApplicationMessage))
	process.requireNoError(t, "write application data", err)
	require.Equal(t, len(wolfSSLApplicationMessage), written)
}

func readWolfSSLMessage(t *testing.T, process *wolfSSLProcess, connection net.Conn) {
	t.Helper()

	received := make([]byte, len(wolfSSLApplicationMessage))
	_, err := io.ReadFull(connection, received)
	process.requireNoError(t, "read application data", err)
	require.Equal(t, wolfSSLApplicationMessage, string(received))
}

func (process *wolfSSLProcess) requireNoError(t *testing.T, operation string, err error) {
	t.Helper()
	if err == nil {
		return
	}

	process.stop()
	require.NoErrorf(t, err, "%s%s", operation, process.output())
}

func (process *wolfSSLProcess) wait(t *testing.T, ctx context.Context) {
	t.Helper()

	select {
	case <-process.waitDone:
		require.NoErrorf(t, process.waitErr, "wolfSSL exited unsuccessfully%s", process.output())
	case <-ctx.Done():
		process.stop()
		require.NoErrorf(t, ctx.Err(), "wait for wolfSSL process%s", process.output())
	}
}

func (process *wolfSSLProcess) requireCIDNegotiation(t *testing.T, testCase wolfSSLCIDTestCase) {
	t.Helper()

	output := process.stdout.String()
	if !testCase.pionCIDEnabled || !testCase.wolfSSLCIDEnabled {
		require.NotContains(t, output, "CID extension was negotiated")

		return
	}

	require.Contains(t, output, "CID extension was negotiated")
	if len(testCase.pionReceiveCID) == 0 {
		require.Contains(t, output, "other peer provided empty CID")
	} else {
		require.Contains(t, output, "Sending CID is "+hex.EncodeToString(testCase.pionReceiveCID))
	}
}

func (process *wolfSSLProcess) stop() {
	process.cancel()
	<-process.waitDone
}

func (process *wolfSSLProcess) output() string {
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
		return ""
	}

	return " (" + strings.Join(details, "; ") + ")"
}
