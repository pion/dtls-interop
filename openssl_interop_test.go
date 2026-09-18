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
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pion/dtls/v3"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol"
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

type openSSLServerOptions struct {
	webRTC           bool
	mtu              string
	keyExchangeGroup elliptic.Curve
}

func TestOpenSSL3DTLS12Interop(t *testing.T) {
	path := environmentOrDefault("DTLS_INTEROP_OPENSSL3_BIN", "openssl-3")
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	version, err := exec.CommandContext(ctx, path, "version").CombinedOutput() //nolint:gosec
	require.NoError(t, err, string(version))
	require.True(t, strings.HasPrefix(string(version), "OpenSSL 3."), "expected OpenSSL 3, got %s", version)
	t.Log(strings.TrimSpace(string(version)))

	t.Run("PionClient_OpenSSLServer", func(t *testing.T) {
		runOpenSSLInteropTest(t, func(t *testing.T, group elliptic.Curve) {
			testPionClientOpenSSLServer(t, path, openSSLServerOptions{keyExchangeGroup: group})
		})
	})
	// Regression coverage for https://github.com/pion/dtls/pull/841
	// OpenSSL's CertificateRequest may include signature algorithms Pion
	// does not recognize. These must not prevent the client handshake.
	t.Run("PionClient_OpenSSLServer_WebRTC", func(t *testing.T) {
		for _, test := range []struct {
			name string
			mtu  string
		}{
			{name: "DefaultMTU"},
			{name: "Fragmented", mtu: "256"},
		} {
			t.Run(test.name, func(t *testing.T) {
				testPionClientOpenSSLServer(t, path, openSSLServerOptions{webRTC: true, mtu: test.mtu})
			})
		}
	})
	t.Run("PionServer_OpenSSLClient", func(t *testing.T) {
		runOpenSSLInteropTest(t, func(t *testing.T, group elliptic.Curve) {
			testPionServerOpenSSLClient(t, path, group)
		})
	})
}

func runOpenSSLInteropTest(t *testing.T, test func(*testing.T, elliptic.Curve)) {
	t.Helper()

	for _, group := range slices.Sorted(maps.Keys(elliptic.Curves())) {
		t.Run(group.String(), func(t *testing.T) {
			if group == elliptic.X25519MLKEM768 {
				t.Skip("X25519MLKEM768 requires DTLS 1.3")
			}
			test(t, group)
		})
	}
}

func testPionClientOpenSSLServer(t *testing.T, path string, options openSSLServerOptions) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	var certificate tls.Certificate
	if options.webRTC {
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
		dtls.WithMaxVersion(protocol.Version1_2),
	}
	if options.webRTC {
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
			"-groups", options.keyExchangeGroup.String(),
			"-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
		)
		clientOptions = append(clientOptions,
			dtls.WithEllipticCurves(options.keyExchangeGroup),
			dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		)
	}
	if options.mtu != "" {
		arguments = append(arguments, "-mtu", options.mtu)
	}
	process := startOpenSSLProcess(t, ctx, path, arguments...)
	// s_server flushes ACCEPT after binding its socket.
	process.waitForOutput(t, ctx, "ACCEPT\n")
	client, err := dtls.Dial("udp4", address, clientOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	exchangeOpenSSLData(t, ctx, client, process)
	if options.webRTC {
		profile, selected := client.SelectedSRTPProtectionProfile()
		require.True(t, selected, "DTLS-SRTP profile was not negotiated")
		require.Equal(t, dtls.SRTP_AES128_CM_HMAC_SHA1_80, profile)
	}
}

func testPionServerOpenSSLClient(t *testing.T, path string, group elliptic.Curve) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	certificate := generateOpenSSLCertificate(t)
	listener, err := dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithCertificates(certificate),
		dtls.WithEllipticCurves(group),
		dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(protocol.Version1_2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	process := startOpenSSLProcess(t, ctx, path,
		"s_client", "-dtls1_2", "-connect", listener.Addr().String(), "-quiet",
		"-groups", group.String(),
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
