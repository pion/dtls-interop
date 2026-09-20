// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pion/dtls/v4"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

type openSSLProcess struct {
	stdin    io.WriteCloser
	output   openSSLOutput
	waitDone chan struct{}
}

type openSSLOutput struct {
	mutex   sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func runOpenSSLCase(t *testing.T, testCase interopCase) error {
	t.Helper()
	if testCase.version != protocol.Version1_2 {
		return fmt.Errorf("%w: OpenSSL 3 only supports DTLS 1.2", errInteropNotSupported)
	}
	switch testCase.scenario {
	case interopHandshake, interopKeyExchange, interopVersionFallback:
	case interopWebRTC:
		if testCase.role != interopPionClient {
			return fmt.Errorf("%w: OpenSSL WebRTC with Pion as server", errInteropNotImplemented)
		}
	default:
		return fmt.Errorf("%w: OpenSSL %s adapter", errInteropNotImplemented, testCase.scenario)
	}
	path := environmentOrDefault("DTLS_INTEROP_OPENSSL3_BIN", "openssl-3")
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	version, err := exec.CommandContext(ctx, path, "version").CombinedOutput() //nolint:gosec
	require.NoError(t, err, string(version))
	require.True(t, strings.HasPrefix(string(version), "OpenSSL 3."), "expected OpenSSL 3, got %s", version)
	t.Log(strings.TrimSpace(string(version)))

	if testCase.role == interopPionClient {
		testPionClientOpenSSLServer(t, path, testCase)
	} else {
		testPionServerOpenSSLClient(t, path, testCase)
	}

	return nil
}

func testPionClientOpenSSLServer(t *testing.T, path string, testCase interopCase) {
	t.Helper()
	config := pionConfigForCase(testCase)

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	var certificate tls.Certificate
	if testCase.scenario == interopWebRTC {
		var err error
		certificate, err = selfsign.GenerateSelfSigned()
		require.NoError(t, err)
	} else {
		certificate = generateOpenSSLCertificate(t)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "cert.pem")
	keyPath := filepath.Join(directory, "key.pem")
	require.NoError(t, os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificate.Certificate[0],
	}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateKey,
	}), 0o600))

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	address, ok := socket.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.NoError(t, socket.Close())
	arguments := []string{
		"s_server", "-dtls1_2", "-accept", address.String(),
		"-cert", certificatePath, "-key", keyPath, "-naccept", "1",
	}
	clientOptions := []dtls.ClientOption{
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(config.maxVersion),
	}
	// Regression for pion/dtls#841: unknown CertificateRequest signature algorithms.
	if testCase.scenario == interopWebRTC {
		arguments = append(arguments,
			"-Verify", "1", "-verify_return_error", "-CAfile", certificatePath,
			// Ed448 (0x0808) is unrecognized by Pion.
			"-client_sigalgs", "ed448:ecdsa_secp256r1_sha256",
			"-use_srtp", "SRTP_AES128_CM_SHA1_80",
		)
		clientOptions = append(clientOptions,
			dtls.WithCertificates(certificate),
			dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		)
	} else {
		arguments = append(arguments,
			"-groups", config.peerGroup.String(),
			"-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
		)
		clientOptions = append(clientOptions,
			dtls.WithEllipticCurves(config.groups...),
			dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		)
	}
	if testCase.mtu != "" {
		arguments = append(arguments, "-mtu", testCase.mtu)
	}
	process := startOpenSSLProcess(t, ctx, path, arguments...)
	// s_server flushes ACCEPT after binding its socket.
	process.waitForOutput(t, ctx, "ACCEPT\n")
	client, err := dtls.Dial("udp4", address, clientOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	exchangeOpenSSLData(t, ctx, client, process)
	if testCase.scenario == interopWebRTC {
		profile, selected := client.SelectedSRTPProtectionProfile()
		require.True(t, selected, "DTLS-SRTP profile was not negotiated")
		require.Equal(t, dtls.SRTP_AES128_CM_HMAC_SHA1_80, profile)
	}
}

func testPionServerOpenSSLClient(t *testing.T, path string, testCase interopCase) {
	t.Helper()
	config := pionConfigForCase(testCase)

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	certificate := generateOpenSSLCertificate(t)
	listener, err := dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithCertificates(certificate),
		dtls.WithEllipticCurves(config.groups...),
		dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(config.maxVersion),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	process := startOpenSSLProcess(t, ctx, path,
		"s_client", "-dtls1_2", "-connect", listener.Addr().String(), "-quiet",
		"-groups", config.peerGroup.String(),
		"-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
	)
	acceptCtx, cancelAccept := context.WithCancel(ctx)
	defer cancelAccept()
	go func() {
		select {
		case <-acceptCtx.Done():
		case <-process.waitDone:
		}
		_ = listener.Close()
	}()
	connection, err := listener.Accept()
	require.NoError(t, err, process.output.String())
	t.Cleanup(func() { _ = connection.Close() })
	server, ok := connection.(*dtls.Conn)
	require.True(t, ok)
	exchangeOpenSSLData(t, ctx, server, process)
}

func generateOpenSSLCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certificate, err := selfsign.SelfSign(key)
	require.NoError(t, err)

	return certificate
}

func exchangeOpenSSLData(t *testing.T, ctx context.Context, connection *dtls.Conn, process *openSSLProcess) {
	t.Helper()

	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, connection.SetDeadline(deadline))
	err := connection.HandshakeContext(ctx)
	require.NoError(t, err, process.output.String())
	state, ok := connection.ConnectionState()
	require.True(t, ok)
	require.Equal(t, protocol.Version1_2, state.NegotiatedVersion())

	const pionMessage = "pion-to-openssl\n"
	written, err := io.WriteString(connection, pionMessage)
	require.NoError(t, err, process.output.String())
	require.Equal(t, len(pionMessage), written)
	process.waitForOutput(t, ctx, pionMessage)

	const openSSLMessage = "openssl-to-pion\n"
	written, err = io.WriteString(process.stdin, openSSLMessage)
	require.NoError(t, err, process.output.String())
	require.Equal(t, len(openSSLMessage), written)
	received := make([]byte, len(openSSLMessage))
	_, err = io.ReadFull(connection, received)
	require.NoError(t, err, process.output.String())
	require.Equal(t, openSSLMessage, string(received))
	t.Log("DTLS 1.2 handshake and application data in both directions completed")
}

func startOpenSSLProcess(t *testing.T, ctx context.Context, path string, arguments ...string) *openSSLProcess {
	t.Helper()

	childCtx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(childCtx, path, arguments...) //nolint:gosec
	process := &openSSLProcess{
		output:   openSSLOutput{changed: make(chan struct{}, 1)},
		waitDone: make(chan struct{}),
	}
	command.Stdout = &process.output
	command.Stderr = &process.output
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
	}
	require.NoError(t, err)
	process.stdin = stdin
	err = command.Start()
	if err != nil {
		cancel()
		_ = stdin.Close()
	}
	require.NoError(t, err, "start OpenSSL 3")
	go func() {
		_ = command.Wait()
		close(process.waitDone)
	}()
	t.Cleanup(func() {
		cancel()
		_ = stdin.Close()
		<-process.waitDone
		if t.Failed() {
			t.Log(process.output.String())
		}
	})

	return process
}

func (process *openSSLProcess) waitForOutput(t *testing.T, ctx context.Context, expected string) {
	t.Helper()

	for !strings.Contains(process.output.String(), expected) {
		select {
		case <-process.output.changed:
		case <-process.waitDone:
			require.FailNowf(t, "OpenSSL exited before expected output", "want %q, got %s", expected, process.output.String())
		case <-ctx.Done():
			require.NoErrorf(t, ctx.Err(), "wait for OpenSSL output %q: %s", expected, process.output.String())
		}
	}
}

func (output *openSSLOutput) Write(payload []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()

	written, err := output.buffer.Write(payload)
	select {
	case output.changed <- struct{}{}:
	default:
	}

	return written, err
}

func (output *openSSLOutput) String() string {
	output.mutex.Lock()
	defer output.mutex.Unlock()

	return output.buffer.String()
}
