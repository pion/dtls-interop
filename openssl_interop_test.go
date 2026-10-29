// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
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
	"sync/atomic"
	"testing"

	"github.com/pion/dtls/v4"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

func openSSLInterop(majorVersion string) interopBackend {
	runCase := func(t *testing.T, testCase interopCase) error {
		return runOpenSSLCase(t, testCase, majorVersion)
	}
	notImplemented := skipInterop(errInteropNotImplemented, "OpenSSL adapter")

	return interopBackend{
		versions:     []protocol.Version{protocol.Version1_2},
		otherVersion: errInteropNotSupported,
		scenarios: map[interopScenario]interopRun{
			interopHandshake:        runCase,
			interopKeyExchange:      runCase,
			interopVersionFallback:  runCase,
			interopWebRTC:           runCase,
			interopKeyUpdatePion:    skipInterop(errInteropNotSupported, "requires DTLS 1.3"),
			interopKeyUpdatePeer:    skipInterop(errInteropNotSupported, "requires DTLS 1.3"),
			interopCID:              notImplemented,
			interopCIDRebinding:     notImplemented,
			interopCIDPolicyDiscard: notImplemented,
		},
	}
}

func runOpenSSLCase(t *testing.T, testCase interopCase, majorVersion string) error {
	t.Helper()
	if testCase.scenario == interopWebRTC && testCase.role != interopPionClient {
		return fmt.Errorf("%w: OpenSSL WebRTC with Pion as server", errInteropNotImplemented)
	}
	path := environmentOrDefault("DTLS_INTEROP_OPENSSL"+majorVersion+"_BIN", "openssl-"+majorVersion)
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	version, err := exec.CommandContext(ctx, path, "version").CombinedOutput() //nolint:gosec
	require.NoError(t, err, string(version))
	require.True(t, strings.HasPrefix(string(version), "OpenSSL "+majorVersion+"."),
		"expected OpenSSL %s, got %s", majorVersion, version)
	t.Log(strings.TrimSpace(string(version)))

	if testCase.role == interopPionClient {
		testPionClientOpenSSLServer(t, path, testCase)
	} else {
		testPionServerOpenSSLClient(t, path, testCase)
	}

	return nil
}

func testPionClientOpenSSLServer(t *testing.T, path string, testCase interopCase) protocol.Version {
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
			dtls.WithCipherSuites(openSSLPionCipherSuites(config.maxVersion)...),
		)
	}
	if testCase.mtu != "" {
		arguments = append(arguments, "-mtu", testCase.mtu)
	}
	process := startInteropProcess(t, ctx, path, arguments...)
	// s_server flushes ACCEPT after binding its socket.
	process.waitForOutput(t, ctx, "ACCEPT\n")
	socket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	probe := &openSSLVersionProbeConn{PacketConn: socket}
	client, err := dtls.Client(probe, address, clientOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	exchangeOpenSSLData(t, ctx, client, process, testCase)

	return protocol.Version(probe.receivedHVR.Load()) //nolint:gosec // Stored wire uint16.
}

func testPionServerOpenSSLClient(t *testing.T, path string, testCase interopCase) [32]byte {
	t.Helper()
	config := pionConfigForCase(testCase)

	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	certificate := generateOpenSSLCertificate(t)
	serverHelloRandom := make(chan [32]byte, 1)
	listener, err := dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithCertificates(certificate),
		dtls.WithEllipticCurves(config.groups...),
		dtls.WithCipherSuites(openSSLPionCipherSuites(config.maxVersion)...),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(config.maxVersion),
		dtls.WithServerHelloMessageHook(func(hello handshake.MessageServerHello) handshake.Message {
			select {
			case serverHelloRandom <- hello.Random.MarshalFixed():
			default:
			}

			return &hello
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	process := startInteropProcess(t, ctx, path,
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
	exchangeOpenSSLData(t, ctx, server, process, testCase)

	select {
	case random := <-serverHelloRandom:
		return random
	case <-ctx.Done():
		require.NoError(t, ctx.Err(), "ServerHello hook was not called")

		return [32]byte{}
	}
}

// Keep a DTLS 1.3 suite available when testing fallback.
func openSSLPionCipherSuites(maxVersion protocol.Version) []cryptosuite.ID {
	suites := []cryptosuite.ID{cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	if maxVersion == protocol.Version1_3 {
		suites = append(suites, cryptosuite.TLS_AES_128_GCM_SHA256)
	}

	return suites
}

func generateOpenSSLCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certificate, err := selfsign.SelfSign(key)
	require.NoError(t, err)

	return certificate
}

func exchangeOpenSSLData(
	t *testing.T, ctx context.Context, connection *dtls.Conn, process *interopProcess, testCase interopCase,
) {
	t.Helper()

	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, connection.SetDeadline(deadline))
	err := connection.HandshakeContext(ctx)
	require.NoError(t, err, process.output.String())
	require.NoError(t, testCase.checkConnection(connection))

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
func TestOpenSSL3VersionLifecycle(t *testing.T) { testOpenSSLVersionLifecycle(t, "3") }

func TestOpenSSL4VersionLifecycle(t *testing.T) { testOpenSSLVersionLifecycle(t, "4") }

func testOpenSSLVersionLifecycle(t *testing.T, major string) {
	t.Helper()
	path := environmentOrDefault("DTLS_INTEROP_OPENSSL"+major+"_BIN", "openssl-"+major)
	for _, mode := range []struct {
		name     string
		scenario interopScenario
	}{
		{"Single12", interopHandshake},
		{"Dual", interopVersionFallback},
	} {
		t.Run("HelloVerifyRequest10/"+mode.name, func(t *testing.T) {
			version := testPionClientOpenSSLServer(t, path, interopCase{
				version: protocol.Version1_2, role: interopPionClient, scenario: mode.scenario,
			})
			// A full handshake and application data exchange must succeed..
			require.Equal(t, protocol.Version1_0, version, "expected a DTLS 1.0 HelloVerifyRequest")
		})
	}
	t.Run("DowngradeSentinel", func(t *testing.T) {
		random := testPionServerOpenSSLClient(t, path, interopCase{
			version: protocol.Version1_2, role: interopPionServer, scenario: interopVersionFallback,
		})
		require.Equal(t, []byte("DOWNGRD\x01"), random[24:], "dual server negotiated DTLS 1.2 without downgrade sentinel")
	})
	for _, version := range []struct {
		name    string
		unknown protocol.Version
	}{
		{"Control", 0},
		{"UnknownWith12Minor", protocol.VersionFromBytes(0x0a, 0xfd)},
		{"UnknownWith13Minor", protocol.VersionFromBytes(0x0a, 0xfc)},
	} {
		t.Run("UnknownOfferedVersion/"+version.name, func(t *testing.T) {
			testOpenSSLUnknownOfferedVersion(t, path, version.unknown)
		})
	}
}

func testOpenSSLUnknownOfferedVersion(t *testing.T, path string, unknown protocol.Version) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, socket.SetDeadline(deadline))
	process := startInteropProcess(t, ctx, path,
		"s_client", "-dtls1_2", "-connect", socket.LocalAddr().String(), "-quiet",
		"-groups", "P-256", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256")
	buffer := make([]byte, 8192)
	n, peer, err := socket.ReadFrom(buffer)
	require.NoError(t, err, process.output.String())
	datagram := buffer[:n]
	if unknown != 0 {
		datagram = addUnknownOfferedVersion(t, datagram, unknown)
	}
	probe := &openSSLVersionProbeConn{
		PacketConn: socket, firstDatagram: datagram, peer: peer,
		sentHVR: make(chan protocol.Version, 1),
	}
	server, err := dtls.Server(probe, peer,
		dtls.WithCertificates(generateOpenSSLCertificate(t)),
		dtls.WithCipherSuites(openSSLPionCipherSuites(protocol.Version1_3)...),
		dtls.WithMinVersion(protocol.Version1_2), dtls.WithMaxVersion(protocol.Version1_3))
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	select {
	case version := <-probe.sentHVR:
		cancel()
		<-done
		require.Contains(t, []protocol.Version{protocol.Version1_0, protocol.Version1_2}, version)
		t.Log("Pion selected DTLS 1.2 and sent HelloVerifyRequest")
	case err := <-done:
		require.FailNowf(t, "Pion failed before sending HelloVerifyRequest", "%v: %s", err, process.output.String())
	case <-ctx.Done():
		<-done
		require.NoError(t, ctx.Err(), process.output.String())
	}
}

type openSSLVersionProbeConn struct {
	net.PacketConn
	receivedHVR   atomic.Uint32
	sentHVR       chan protocol.Version
	firstDatagram []byte
	peer          net.Addr
}

func (conn *openSSLVersionProbeConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if conn.firstDatagram != nil {
		n := copy(buffer, conn.firstDatagram)
		conn.firstDatagram = nil

		return n, conn.peer, nil
	}
	n, peer, err := conn.PacketConn.ReadFrom(buffer)
	if err == nil {
		if version := helloVerifyRequestVersion(buffer[:n]); version != 0 {
			conn.receivedHVR.Store(uint32(version))
		}
	}

	return n, peer, err
}

func (conn *openSSLVersionProbeConn) WriteTo(buffer []byte, peer net.Addr) (int, error) {
	n, err := conn.PacketConn.WriteTo(buffer, peer)
	if err == nil {
		if version := helloVerifyRequestVersion(buffer); version != 0 {
			select {
			case conn.sentHVR <- version:
			default:
			}
		}
	}

	return n, err
}

func helloVerifyRequestVersion(datagram []byte) protocol.Version {
	records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{})
	if err != nil {
		return 0
	}
	for _, raw := range records {
		record, err := recordlayer.ParseRecord(raw, 0)
		if err != nil || record.ContentType() != protocol.ContentTypeHandshake || record.Epoch() != 0 {
			continue
		}
		var message handshake.Handshake
		if message.Unmarshal(record.Payload()) == nil {
			if hello, ok := message.Message.(*handshake.MessageHelloVerifyRequest); ok {
				return hello.Version
			}
		}
	}

	return 0
}

func addUnknownOfferedVersion(t *testing.T, datagram []byte, unknown protocol.Version) []byte {
	t.Helper()
	records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Len(t, records, 1, "probe requires one unfragmented OpenSSL ClientHello")
	record, err := recordlayer.ParseRecord(records[0], 0)
	require.NoError(t, err)
	require.Equal(t, protocol.ContentTypeHandshake, record.ContentType())
	require.Zero(t, record.Epoch())
	var message handshake.Handshake
	require.NoError(t, message.Unmarshal(record.Payload()))
	hello, ok := message.Message.(*handshake.MessageClientHello)
	require.True(t, ok, "expected OpenSSL ClientHello")
	for _, value := range hello.Extensions {
		require.NotEqual(t, extension.TypeSupportedVersions, value.ExtensionType(),
			"OpenSSL DTLS 1.2 ClientHello already contains supported_versions")
	}
	hello.Extensions = append(hello.Extensions, &extension13.OfferedVersions{
		Versions: []protocol.Version{unknown, protocol.Version1_2},
	})
	payload, err := message.Marshal()
	require.NoError(t, err)
	replacement, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{
		ContentType: record.ContentType(), Version: record.Version(),
		Epoch: record.Epoch(), SequenceNumber: record.SequenceNumber(),
	}, payload)
	require.NoError(t, err)

	return replacement
}
