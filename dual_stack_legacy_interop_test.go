// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

// These tests run Pion with its default version range (DTLS 1.2 through 1.3)
// against peers that only speak DTLS 1.2. Pion sets no version, curve, or
// cipher suite options, so its ClientHello and ServerHello match what a
// default deployment puts on the wire.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dtlsv3 "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

const (
	dualStackDTLS12WireVersion = 0xfefd
	dualStackSRTPLabel         = "EXTRACTOR-dtls_srtp"
	dualStackSRTPLength        = 60
	contentTypeTLS12CID        = 25
)

type dualStackVariant string

const (
	dualStackDefault dualStackVariant = "Default"
	dualStackWebRTC  dualStackVariant = "WebRTC"
)

var dualStackSRTPProfiles = []dtls.SRTPProtectionProfile{ //nolint:gochecknoglobals
	dtls.SRTP_AEAD_AES_256_GCM, dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AES128_CM_HMAC_SHA1_80,
}

// dualStackClientOptions returns Pion's default client configuration, plus the
// options pion/webrtc sets for the WebRTC variant.
func dualStackClientOptions(variant dualStackVariant, certificate tls.Certificate) []dtls.ClientOption {
	options := []dtls.ClientOption{dtls.WithInsecureSkipVerify(true)}
	if variant == dualStackWebRTC {
		options = append(options,
			dtls.WithCertificates(certificate),
			dtls.WithSRTPProtectionProfiles(dualStackSRTPProfiles...),
			dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		)
	}

	return options
}

func dualStackServerOptions(variant dualStackVariant, certificate tls.Certificate) []dtls.ServerOption {
	options := []dtls.ServerOption{dtls.WithCertificates(certificate)}
	if variant == dualStackWebRTC {
		options = append(options,
			dtls.WithInsecureSkipVerify(true),
			dtls.WithClientAuth(dtls.RequireAnyClientCert),
			dtls.WithSRTPProtectionProfiles(dualStackSRTPProfiles...),
			dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		)
	}

	return options
}

// dualStackWire passively records plaintext handshake facts in both directions.
type dualStackWire struct {
	net.PacketConn

	mutex             sync.Mutex
	helloBody         []byte
	helloCovered      []bool
	helloRecords      int
	helloDatagrams    int
	helloVerifyVer    protocol.Version
	serverHelloSeen   bool
	serverHelloVer    protocol.Version
	serverHelloRandom [32]byte
	certificates      int
	cidRecords        int
	// drop, when set, decides whether an incoming datagram is discarded.
	drop func([]byte) bool
}

func newDualStackWire(conn net.PacketConn) *dualStackWire {
	return &dualStackWire{PacketConn: conn}
}

func (w *dualStackWire) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		n, addr, err := w.PacketConn.ReadFrom(buffer)
		if err != nil {
			return n, addr, err
		}
		w.mutex.Lock()
		drop := w.drop != nil && w.drop(buffer[:n])
		w.mutex.Unlock()
		if drop {
			continue
		}
		w.observe(buffer[:n])

		return n, addr, nil
	}
}

func (w *dualStackWire) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	w.observe(buffer)

	return w.PacketConn.WriteTo(buffer, addr)
}

func (w *dualStackWire) observe(datagram []byte) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	// A tls12_cid record's length follows the CID, so count it before unpacking.
	if len(datagram) > 0 && datagram[0] == contentTypeTLS12CID {
		w.cidRecords++

		return
	}
	records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{})
	if err != nil {
		return
	}
	datagramHasHello := false
	for _, raw := range records {
		record, err := recordlayer.ParseRecord(raw, 0)
		if err != nil || record.ContentType() != protocol.ContentTypeHandshake || record.Epoch() != 0 {
			continue
		}
		payload := record.Payload()
		for len(payload) >= handshake.HeaderLength {
			var header handshake.Header
			if header.Unmarshal(payload) != nil {
				break
			}
			end := handshake.HeaderLength + int(header.FragmentLength)
			if end > len(payload) {
				break
			}
			fragment := payload[handshake.HeaderLength:end]
			switch header.Type {
			case handshake.TypeClientHello:
				if header.MessageSequence == 0 {
					w.recordClientHelloFragment(header, fragment)
					datagramHasHello = true
				}
			case handshake.TypeHelloVerifyRequest:
				if header.FragmentOffset == 0 && len(fragment) >= 2 {
					w.helloVerifyVer = protocol.VersionFromBytes(fragment[0], fragment[1])
				}
			case handshake.TypeServerHello:
				if !w.serverHelloSeen && header.FragmentOffset == 0 && len(fragment) >= 34 {
					w.serverHelloSeen = true
					w.serverHelloVer = protocol.VersionFromBytes(fragment[0], fragment[1])
					copy(w.serverHelloRandom[:], fragment[2:34])
				}
			case handshake.TypeCertificate:
				w.certificates++
			default:
			}
			payload = payload[end:]
		}
	}
	if datagramHasHello {
		w.helloDatagrams++
	}
}

func (w *dualStackWire) recordClientHelloFragment(header handshake.Header, fragment []byte) {
	w.helloRecords++
	if w.helloBody == nil {
		w.helloBody = make([]byte, header.Length)
		w.helloCovered = make([]bool, header.Length)
	}
	if int(header.Length) != len(w.helloBody) || int(header.FragmentOffset)+len(fragment) > len(w.helloBody) {
		return
	}
	copy(w.helloBody[header.FragmentOffset:], fragment)
	for i := range fragment {
		w.helloCovered[int(header.FragmentOffset)+i] = true
	}
}

// clientHello returns the first reassembled ClientHello.
func (w *dualStackWire) clientHello(t *testing.T) *handshake.MessageClientHello {
	t.Helper()
	w.mutex.Lock()
	defer w.mutex.Unlock()
	require.NotNil(t, w.helloBody, "no ClientHello observed")
	for _, covered := range w.helloCovered {
		require.True(t, covered, "ClientHello was not fully observed")
	}
	length := uint32(len(w.helloBody)) //nolint:gosec
	header := handshake.Header{
		Type: handshake.TypeClientHello, Length: length, FragmentLength: length,
	}
	raw, err := header.Marshal()
	require.NoError(t, err)
	var message handshake.Handshake
	require.NoError(t, message.Unmarshal(append(raw, w.helloBody...)))
	hello, ok := message.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	return hello
}

type dualStackSnapshot struct {
	helloLength, helloRecords, helloDatagrams int
	helloVerifyVersion                        protocol.Version
	serverHelloSeen                           bool
	serverHelloVersion                        protocol.Version
	serverHelloRandom                         [32]byte
	certificates, cidRecords                  int
}

func (w *dualStackWire) snapshot() dualStackSnapshot {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	return dualStackSnapshot{
		helloLength: len(w.helloBody), helloRecords: w.helloRecords, helloDatagrams: w.helloDatagrams,
		helloVerifyVersion: w.helloVerifyVer,
		serverHelloSeen:    w.serverHelloSeen, serverHelloVersion: w.serverHelloVer,
		serverHelloRandom: w.serverHelloRandom,
		certificates:      w.certificates, cidRecords: w.cidRecords,
	}
}

func offeredVersions(hello *handshake.MessageClientHello) ([]protocol.Version, []string) {
	var versions []protocol.Version
	var shares []string
	for _, value := range hello.Extensions {
		switch ext := value.(type) {
		case *extension13.OfferedVersions:
			versions = ext.Versions
		case extension13.OfferedVersions:
			versions = ext.Versions
		case *extension13.ClientKeyShare:
			for _, share := range ext.Shares {
				shares = append(shares, fmt.Sprintf("%s(%dB)", share.Group, len(share.KeyExchange)))
			}
		case extension13.ClientKeyShare:
			for _, share := range ext.Shares {
				shares = append(shares, fmt.Sprintf("%s(%dB)", share.Group, len(share.KeyExchange)))
			}
		default:
		}
	}

	return versions, shares
}

// requireDualStackClient checks that Pion offered DTLS 1.3 and settled on 1.2.
func requireDualStackClient(t *testing.T, wire *dualStackWire, connection *dtls.Conn) {
	t.Helper()
	requireDTLS12(t, connection)
	versions, shares := offeredVersions(wire.clientHello(t))
	require.Contains(t, versions, protocol.Version1_3, "dual-stack ClientHello did not offer DTLS 1.3")
	require.Contains(t, versions, protocol.Version1_2, "dual-stack ClientHello did not offer DTLS 1.2")
	snapshot := wire.snapshot()
	require.True(t, snapshot.serverHelloSeen)
	require.Equal(t, protocol.Version1_2, snapshot.serverHelloVersion)
	t.Logf("Pion ClientHello: %d bytes in %d records/%d datagrams (all transmissions), supported_versions=%v, key_shares=%v",
		snapshot.helloLength, snapshot.helloRecords, snapshot.helloDatagrams, versions, shares)
	if snapshot.helloVerifyVersion != 0 {
		t.Logf("peer sent HelloVerifyRequest with version %v", snapshot.helloVerifyVersion)
	}
	t.Logf("peer ServerHello random suffix %x", snapshot.serverHelloRandom[24:])
}

// requireDualStackServer checks that Pion negotiated 1.2 and set the RFC 8446 sentinel.
func requireDualStackServer(t *testing.T, wire *dualStackWire, connection *dtls.Conn) {
	t.Helper()
	requireDTLS12(t, connection)
	snapshot := wire.snapshot()
	require.True(t, snapshot.serverHelloSeen)
	require.Equal(t, protocol.Version1_2, snapshot.serverHelloVersion)
	require.Equal(t, []byte("DOWNGRD\x01"), snapshot.serverHelloRandom[24:],
		"dual-stack server negotiated DTLS 1.2 without the downgrade sentinel")
	if snapshot.helloLength > 0 {
		versions, _ := offeredVersions(wire.clientHello(t))
		t.Logf("peer ClientHello: %d bytes, supported_versions=%v", snapshot.helloLength, versions)
	}
}

func requireDTLS12(t *testing.T, connection *dtls.Conn) {
	t.Helper()
	state, ok := connection.ConnectionState()
	require.True(t, ok)
	require.Equal(t, protocol.Version1_2, state.NegotiatedVersion())
	t.Logf("negotiated DTLS 1.2 cipher suite %v", state.CipherSuiteID)
}

func dualStackSRTPKey(t *testing.T, connection *dtls.Conn) []byte {
	t.Helper()
	profile, ok := connection.SelectedSRTPProtectionProfile()
	require.True(t, ok, "no DTLS-SRTP profile negotiated")
	state, ok := connection.ConnectionState()
	require.True(t, ok)
	key, err := state.ExportKeyingMaterial(dualStackSRTPLabel, nil, dualStackSRTPLength)
	require.NoError(t, err)
	t.Logf("DTLS-SRTP profile %v", profile)

	return key
}

func writeDualStackPEM(t *testing.T, directory, name string, certificate tls.Certificate) (string, string) {
	t.Helper()
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	certificatePath := filepath.Join(directory, name+"-cert.pem")
	keyPath := filepath.Join(directory, name+"-key.pem")
	require.NoError(t, os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificate.Certificate[0],
	}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateKey,
	}), 0o600))

	return certificatePath, keyPath
}

func dualStackCertificate(t *testing.T, kind string) tls.Certificate {
	t.Helper()
	if kind == "RSA" {
		return generateOpenSSLCertificate(t)
	}
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	return certificate
}

func listenDualStackServer(
	t *testing.T, options []dtls.ServerOption,
) (net.Listener, *dualStackWire, *net.UDPAddr) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	wire := newDualStackWire(socket)
	listener, err := dtls.Listen(wire, options...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	address, ok := socket.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	return listener, wire, address
}

func acceptDualStack(t *testing.T, ctx context.Context, listener net.Listener, peerDone <-chan struct{}, output func() string) *dtls.Conn {
	t.Helper()
	type result struct {
		connection net.Conn
		err        error
	}
	accepted := make(chan result, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- result{connection, err}
	}()
	select {
	case res := <-accepted:
		require.NoError(t, res.err, output())
		t.Cleanup(func() { _ = res.connection.Close() })
		connection, ok := res.connection.(*dtls.Conn)
		require.True(t, ok)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.NoError(t, connection.SetDeadline(deadline))

		return connection
	case <-peerDone:
		require.FailNow(t, "peer exited before Pion accepted a connection", output())
	case <-ctx.Done():
		require.FailNow(t, "timed out accepting a connection", output())
	}

	return nil
}

func dialDualStackClient(
	t *testing.T, ctx context.Context, server net.Addr, options []dtls.ClientOption,
) (*dtls.Conn, *dualStackWire) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	wire := newDualStackWire(socket)
	client, err := dtls.Client(wire, server, options...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, client.SetDeadline(deadline))

	return client, wire
}

// OpenSSL

func TestOpenSSL3DualStackLegacy(t *testing.T) { testOpenSSLDualStackLegacy(t, "3") }

func TestOpenSSL4DualStackLegacy(t *testing.T) { testOpenSSLDualStackLegacy(t, "4") }

func testOpenSSLDualStackLegacy(t *testing.T, major string) {
	t.Helper()
	path := environmentOrDefault("DTLS_INTEROP_OPENSSL"+major+"_BIN", "openssl-"+major)
	for _, test := range []struct {
		variant dualStackVariant
		cert    string
		mtu     int
	}{
		{dualStackDefault, "RSA", 0},
		{dualStackDefault, "ECDSA", 0},
		{dualStackWebRTC, "ECDSA", 0},
		{dualStackDefault, "ECDSA", 400},
	} {
		name := string(test.variant) + "/" + test.cert
		if test.mtu != 0 {
			name += "/MTU" + strconv.Itoa(test.mtu)
		}
		t.Run("PionClient/"+name, func(t *testing.T) {
			testDualStackClientOpenSSLServer(t, path, test.variant, test.cert, test.mtu)
		})
		t.Run("PionServer/"+name, func(t *testing.T) {
			testDualStackServerOpenSSLClient(t, path, test.variant, test.cert, test.mtu)
		})
	}
}

func testDualStackClientOpenSSLServer(t *testing.T, path string, variant dualStackVariant, certKind string, mtu int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	directory := t.TempDir()
	certificatePath, keyPath := writeDualStackPEM(t, directory, "server", dualStackCertificate(t, certKind))
	pionCertificate := dualStackCertificate(t, "ECDSA")
	pionCertificatePath, _ := writeDualStackPEM(t, directory, "pion", pionCertificate)

	address := reserveWolfSSLAddress(t)
	arguments := []string{
		"s_server", "-dtls1_2", "-accept", address.String(),
		"-cert", certificatePath, "-key", keyPath, "-naccept", "1",
	}
	if variant == dualStackWebRTC {
		arguments = append(arguments,
			"-Verify", "1", "-verify_return_error", "-CAfile", pionCertificatePath,
			"-use_srtp", "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80",
			"-keymatexport", dualStackSRTPLabel, "-keymatexportlen", strconv.Itoa(dualStackSRTPLength),
		)
	}
	options := dualStackClientOptions(variant, pionCertificate)
	if mtu != 0 {
		arguments = append(arguments, "-mtu", strconv.Itoa(mtu))
		options = append(options, dtls.WithMTU(mtu))
	}
	process := startInteropProcess(t, ctx, path, arguments...)
	process.waitForOutput(t, ctx, "ACCEPT\n")

	client, wire := dialDualStackClient(t, ctx, address, options)
	exchangeOpenSSLData(t, ctx, client, process, interopCase{version: protocol.Version1_2})
	requireDualStackClient(t, wire, client)
	if variant == dualStackWebRTC {
		key := dualStackSRTPKey(t, client)
		process.waitForOutput(t, ctx, "Keying material: "+strings.ToUpper(hex.EncodeToString(key)))
		require.Positive(t, wire.snapshot().certificates)
	}
}

func testDualStackServerOpenSSLClient(t *testing.T, path string, variant dualStackVariant, certKind string, mtu int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	options := dualStackServerOptions(variant, dualStackCertificate(t, certKind))
	if mtu != 0 {
		options = append(options, dtls.WithMTU(mtu))
	}
	listener, wire, address := listenDualStackServer(t, options)

	arguments := []string{"s_client", "-dtls1_2", "-connect", address.String()}
	if variant == dualStackWebRTC {
		certificatePath, keyPath := writeDualStackPEM(t, t.TempDir(), "openssl", dualStackCertificate(t, "ECDSA"))
		arguments = append(arguments,
			"-cert", certificatePath, "-key", keyPath,
			"-use_srtp", "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80",
			"-keymatexport", dualStackSRTPLabel, "-keymatexportlen", strconv.Itoa(dualStackSRTPLength),
		)
	} else {
		arguments = append(arguments, "-quiet")
	}
	if mtu != 0 {
		arguments = append(arguments, "-mtu", strconv.Itoa(mtu))
	}
	process := startInteropProcess(t, ctx, path, arguments...)
	server := acceptDualStack(t, ctx, listener, process.waitDone, process.output.String)
	exchangeOpenSSLData(t, ctx, server, process, interopCase{version: protocol.Version1_2})
	requireDualStackServer(t, wire, server)
	if variant == dualStackWebRTC {
		key := dualStackSRTPKey(t, server)
		process.waitForOutput(t, ctx, "Keying material: "+strings.ToUpper(hex.EncodeToString(key)))
	}
}

// BoringSSL (the TLS stack in Chromium's WebRTC).

func TestBoringSSLDualStackLegacy(t *testing.T) {
	for _, variant := range []dualStackVariant{dualStackDefault, dualStackWebRTC} {
		t.Run("PionClient/"+string(variant), func(t *testing.T) { testBoringSSLDualStack(t, false, variant) })
		t.Run("PionServer/"+string(variant), func(t *testing.T) { testBoringSSLDualStack(t, true, variant) })
	}
}

func testBoringSSLDualStack(t *testing.T, pionServer bool, variant dualStackVariant) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	credentials, err := newBoringSSLCredentials()
	require.NoError(t, err)
	t.Cleanup(credentials.remove)

	var listenConfig net.ListenConfig
	tcpListener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpListener.Close() })
	tcpAddress, ok := tcpListener.Addr().(*net.TCPAddr)
	require.True(t, ok)

	version := strconv.Itoa(dualStackDTLS12WireVersion)
	arguments := []string{
		"-port", strconv.Itoa(tcpAddress.Port),
		"-shim-id", strconv.FormatUint(shimID, 10),
		"-dtls",
		"-min-version", version, "-max-version", version, "-expect-version", version,
		"-shim-writes-first",
	}
	if pionServer {
		// Pion issues no resumable 1.2 session without a SessionStore.
		arguments = append(arguments, "-expect-no-session")
	} else {
		arguments = append(arguments, "-server")
	}
	if !pionServer || variant == dualStackWebRTC {
		arguments = append(arguments, "-cert-file", credentials.certificatePath, "-key-file", credentials.privateKeyPath)
	}
	if variant == dualStackWebRTC {
		arguments = append(arguments, "-srtp-profiles", "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80")
		if !pionServer {
			arguments = append(arguments, "-require-any-client-certificate")
		}
	}
	process := &shimProcess{waitDone: make(chan struct{})}
	childCtx, cancelChild := context.WithCancel(ctx)
	process.cancel = cancelChild
	command := exec.CommandContext(childCtx, //nolint:gosec
		environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"), arguments...)
	command.Stdout = &process.stdout
	command.Stderr = &process.stderr
	require.NoError(t, command.Start())
	go func() {
		process.waitErr = command.Wait()
		close(process.waitDone)
	}()
	t.Cleanup(process.stop)
	shimOutput := func() string { return process.stdout.String() + process.stderr.String() }

	connection, err := acceptShimConnection(ctx, tcpListener, process)
	require.NoError(t, err, shimOutput())
	t.Cleanup(func() { _ = connection.Close() })
	require.NoError(t, readAndValidateShimID(ctx, connection))
	packeted := newPacketedConn(connection)
	wire := newDualStackWire(packeted)

	pionCertificate := dualStackCertificate(t, "ECDSA")
	var pion *dtls.Conn
	if pionServer {
		pion, err = dtls.Server(wire, packeted.RemoteAddr(), dualStackServerOptions(variant, pionCertificate)...)
	} else {
		pion, err = dtls.Client(wire, packeted.RemoteAddr(), dualStackClientOptions(variant, pionCertificate)...)
	}
	require.NoError(t, err)
	var log bytes.Buffer
	var srtpKey []byte
	check := func(connection *dtls.Conn) error {
		if pionServer {
			requireDualStackServer(t, wire, connection)
		} else {
			requireDualStackClient(t, wire, connection)
		}
		if variant == dualStackWebRTC {
			srtpKey = dualStackSRTPKey(t, connection)
		}

		return nil
	}
	err = runPionDTLS13Exchange(ctx, pion, packeted, &log, "dual-stack", "received",
		pionDTLS13ExchangeOptions{checkConnection: check})
	t.Log(strings.TrimSpace(log.String()))
	require.NoError(t, err, shimOutput())
	require.NoError(t, process.wait(ctx), shimOutput())
	if variant == dualStackWebRTC {
		require.Len(t, srtpKey, dualStackSRTPLength)
		require.Positive(t, wire.snapshot().certificates)
	}
}

// wolfSSL example client and server pinned to DTLS 1.2 with -v 3.

func TestWolfSSLDualStackLegacy(t *testing.T) {
	for _, certKind := range []string{"RSA", "ECDSA"} {
		t.Run("PionClient/"+certKind, func(t *testing.T) { testDualStackClientWolfSSLServer(t, certKind) })
		t.Run("PionServer/"+certKind, func(t *testing.T) { testDualStackServerWolfSSLClient(t, certKind) })
	}
}

func testDualStackClientWolfSSLServer(t *testing.T, certKind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	address := reserveWolfSSLAddress(t)
	arguments := []string{"-u", "-v", "3", "-p", strconv.Itoa(address.Port), "-d", "-e"}
	if certKind == "ECDSA" {
		arguments = append(arguments, "-c", "./certs/server-ecc.pem", "-k", "./certs/ecc-key.pem")
	}
	process := startWolfSSLProcess(t, ctx,
		environmentOrDefault("DTLS_INTEROP_WOLFSSL_SERVER_BIN", "wolfssl-dtls13-server"), arguments...)

	client, wire := dialDualStackClient(t, ctx, address, dualStackClientOptions(dualStackDefault, tls.Certificate{}))
	err := client.HandshakeContext(ctx)
	process.requireNoError(t, "Pion handshake with wolfSSL DTLS 1.2 server ("+wire.snapshot().String()+")", err)
	requireDualStackClient(t, wire, client)
	writeWolfSSLMessage(t, process, client)
	readWolfSSLMessage(t, process, client)
	process.requireNoError(t, "close Pion DTLS connection", client.Close())
	process.wait(t, ctx)
	t.Log(strings.TrimSpace(process.stdout.String()))
}

func testDualStackServerWolfSSLClient(t *testing.T, certKind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	listener, wire, address := listenDualStackServer(t,
		dualStackServerOptions(dualStackDefault, dualStackCertificate(t, certKind)))
	process := startWolfSSLProcess(t, ctx,
		environmentOrDefault("DTLS_INTEROP_WOLFSSL_CLIENT_BIN", "wolfssl-dtls13-client"),
		"-h", "127.0.0.1", "-p", strconv.Itoa(address.Port), "-u", "-v", "3", "-d", "-x")
	server := acceptDualStack(t, ctx, listener, process.waitDone, process.output)
	process.requireNoError(t, "Pion handshake with wolfSSL DTLS 1.2 client", server.HandshakeContext(ctx))
	requireDualStackServer(t, wire, server)
	readWolfSSLMessage(t, process, server)
	writeWolfSSLMessage(t, process, server)
	process.wait(t, ctx)
	t.Log(strings.TrimSpace(process.stdout.String()))
}

// Mbed TLS sample programs pinned to DTLS 1.2.

func TestMbedTLSDualStackLegacy(t *testing.T) {
	t.Run("PionClient", testDualStackClientMbedTLSServer)
	t.Run("PionServer", testDualStackServerMbedTLSClient)
}

func testDualStackClientMbedTLSServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	address := reserveWolfSSLAddress(t)
	process := startInteropProcess(t, ctx,
		environmentOrDefault("DTLS_INTEROP_MBEDTLS_SERVER_BIN", "ssl_server2"),
		"server_addr=127.0.0.1", "server_port="+strconv.Itoa(address.Port),
		"force_version=dtls12", "auth_mode=none", "exchanges=1",
	)
	process.waitForOutput(t, ctx, "Waiting for a remote connection")
	client, wire := dialDualStackClient(t, ctx, address, dualStackClientOptions(dualStackDefault, tls.Certificate{}))
	err := client.HandshakeContext(ctx)
	require.NoError(t, err, wire.snapshot().String()+"\n"+process.output.String())
	requireDualStackClient(t, wire, client)

	const request = "GET /interop HTTP/1.0\r\n\r\n"
	_, err = io.WriteString(client, request)
	require.NoError(t, err)
	response := make([]byte, 2048)
	n, err := client.Read(response)
	require.NoError(t, err, process.output.String())
	require.Contains(t, string(response[:n]), "HTTP/1.0 200 OK")
	process.waitForOutput(t, ctx, request)
}

func testDualStackServerMbedTLSClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	listener, wire, address := listenDualStackServer(t,
		dualStackServerOptions(dualStackDefault, dualStackCertificate(t, "ECDSA")))
	clientPath := filepath.Join(filepath.Dir(environmentOrDefault("DTLS_INTEROP_MBEDTLS_SERVER_BIN", "ssl_server2")), "ssl_client2")
	process := startInteropProcess(t, ctx, clientPath,
		"dtls=1", "force_version=dtls12", "server_addr=127.0.0.1", "server_port="+strconv.Itoa(address.Port),
		"auth_mode=none", "exchanges=1",
	)
	server := acceptDualStack(t, ctx, listener, process.waitDone, process.output.String)
	require.NoError(t, server.HandshakeContext(ctx), process.output.String())
	requireDualStackServer(t, wire, server)

	request := make([]byte, 2048)
	n, err := server.Read(request)
	require.NoError(t, err, process.output.String())
	require.Contains(t, string(request[:n]), "GET / HTTP/1.0")
	const response = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\npion dual-stack\r\n"
	_, err = io.WriteString(server, response)
	require.NoError(t, err)
	process.waitForOutput(t, ctx, "pion dual-stack")
	select {
	case <-process.waitDone:
	case <-ctx.Done():
		require.FailNow(t, "ssl_client2 did not exit", process.output.String())
	}
	t.Log(process.output.String())
}

// Pion v3 (DTLS 1.2 only), in process.

func TestPionV3DualStackLegacy(t *testing.T) {
	for _, mode := range []string{"Default", "WebRTC", "CID", "Lossy"} {
		t.Run("PionClient/"+mode, func(t *testing.T) { testPionV3DualStack(t, false, mode) })
		t.Run("PionServer/"+mode, func(t *testing.T) { testPionV3DualStack(t, true, mode) })
	}
	t.Run("PionClient/Resumption", func(t *testing.T) { testPionV3DualStackResumption(t, false) })
	t.Run("PionServer/Resumption", func(t *testing.T) { testPionV3DualStackResumption(t, true) })
}

func pionV3PeerOptions(mode string, certificate tls.Certificate) ([]dtlsv3.ClientOption, []dtlsv3.ServerOption) {
	client := []dtlsv3.ClientOption{dtlsv3.WithInsecureSkipVerify(true)}
	server := []dtlsv3.ServerOption{dtlsv3.WithCertificates(certificate)}
	switch mode {
	case "WebRTC":
		profiles := []dtlsv3.SRTPProtectionProfile{dtlsv3.SRTP_AEAD_AES_128_GCM, dtlsv3.SRTP_AES128_CM_HMAC_SHA1_80}
		client = append(client, dtlsv3.WithCertificates(certificate), dtlsv3.WithSRTPProtectionProfiles(profiles...),
			dtlsv3.WithExtendedMasterSecret(dtlsv3.RequireExtendedMasterSecret))
		server = append(server, dtlsv3.WithInsecureSkipVerify(true), dtlsv3.WithClientAuth(dtlsv3.RequireAnyClientCert),
			dtlsv3.WithSRTPProtectionProfiles(profiles...), dtlsv3.WithExtendedMasterSecret(dtlsv3.RequireExtendedMasterSecret))
	case "CID":
		client = append(client, dtlsv3.WithConnectionIDGenerator(dtlsv3.RandomCIDGenerator(8)))
		server = append(server, dtlsv3.WithConnectionIDGenerator(dtlsv3.RandomCIDGenerator(8)))
	}

	return client, server
}

// dropFirstHandshakeCopy drops the first copy of every plaintext handshake fragment.
func dropFirstHandshakeCopy() func([]byte) bool {
	seen := map[string]bool{}

	return func(datagram []byte) bool {
		records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{})
		if err != nil {
			return false
		}
		for _, raw := range records {
			record, err := recordlayer.ParseRecord(raw, 0)
			if err != nil || record.ContentType() != protocol.ContentTypeHandshake || record.Epoch() != 0 {
				continue
			}
			var header handshake.Header
			if header.Unmarshal(record.Payload()) != nil {
				continue
			}
			key := fmt.Sprintf("%d/%d/%d", header.Type, header.MessageSequence, header.FragmentOffset)
			if seen[key] {
				return false
			}
			seen[key] = true

			return true
		}

		return false
	}
}

func loopbackPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })

	return first, second
}

type pionV3Pair struct {
	pion *dtls.Conn
	peer *dtlsv3.Conn
}

func handshakePionV3Pair(
	t *testing.T, ctx context.Context, pionServer bool,
	pionWire, peerWire *dualStackWire, pionAddress, peerAddress net.Addr,
	pionClientOptions []dtls.ClientOption, pionServerOptions []dtls.ServerOption,
	peerClientOptions []dtlsv3.ClientOption, peerServerOptions []dtlsv3.ServerOption,
) pionV3Pair {
	t.Helper()
	var pair pionV3Pair
	var err error
	if pionServer {
		pair.pion, err = dtls.Server(pionWire, peerAddress, pionServerOptions...)
		require.NoError(t, err)
		pair.peer, err = dtlsv3.ClientWithOptions(peerWire, pionAddress, peerClientOptions...)
	} else {
		pair.pion, err = dtls.Client(pionWire, peerAddress, pionClientOptions...)
		require.NoError(t, err)
		pair.peer, err = dtlsv3.ServerWithOptions(peerWire, pionAddress, peerServerOptions...)
	}
	require.NoError(t, err)
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, pair.pion.SetDeadline(deadline))
	require.NoError(t, pair.peer.SetDeadline(deadline))
	peerDone := make(chan error, 1)
	go func() { peerDone <- pair.peer.HandshakeContext(ctx) }()
	require.NoError(t, pair.pion.HandshakeContext(ctx))
	require.NoError(t, <-peerDone)
	exchangeInteropData(t, pair.pion, pair.peer, "v4-dual-to-v3")
	exchangeInteropData(t, pair.peer, pair.pion, "v3-to-v4-dual")

	return pair
}

func testPionV3DualStack(t *testing.T, pionServer bool, mode string) {
	t.Helper()
	timeout := defaultTimeout
	if mode == "Lossy" {
		timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	pionSocket, peerSocket := loopbackPair(t)
	pionWire, peerWire := newDualStackWire(pionSocket), newDualStackWire(peerSocket)
	if mode == "Lossy" {
		pionWire.drop = dropFirstHandshakeCopy()
		peerWire.drop = dropFirstHandshakeCopy()
	}
	variant := dualStackDefault
	if mode == "WebRTC" {
		variant = dualStackWebRTC
	}
	pionCertificate := dualStackCertificate(t, "ECDSA")
	pionClientOptions := dualStackClientOptions(variant, pionCertificate)
	pionServerOptions := dualStackServerOptions(variant, pionCertificate)
	if mode == "CID" {
		cid := func() []byte { return []byte("pion-cid") }
		pionClientOptions = append(pionClientOptions, dtls.WithConnectionID(cid, dtls.CIDPathMigrationReject))
		pionServerOptions = append(pionServerOptions, dtls.WithConnectionID(cid, dtls.CIDPathMigrationReject))
	}
	peerClientOptions, peerServerOptions := pionV3PeerOptions(mode, dualStackCertificate(t, "ECDSA"))

	start := time.Now()
	pair := handshakePionV3Pair(t, ctx, pionServer, pionWire, peerWire, pionSocket.LocalAddr(), peerSocket.LocalAddr(),
		pionClientOptions, pionServerOptions, peerClientOptions, peerServerOptions)
	t.Logf("handshake and data exchange took %v", time.Since(start).Round(time.Millisecond))
	if pionServer {
		requireDualStackServer(t, pionWire, pair.pion)
	} else {
		requireDualStackClient(t, pionWire, pair.pion)
	}
	switch mode {
	case "WebRTC":
		pionKey := dualStackSRTPKey(t, pair.pion)
		state, ok := pair.peer.ConnectionState()
		require.True(t, ok)
		peerKey, err := state.ExportKeyingMaterial(dualStackSRTPLabel, nil, dualStackSRTPLength)
		require.NoError(t, err)
		require.Equal(t, peerKey, pionKey, "DTLS-SRTP keying material differs")
		pionProfile, _ := pair.pion.SelectedSRTPProtectionProfile()
		peerProfile, _ := pair.peer.SelectedSRTPProtectionProfile()
		require.Equal(t, uint16(peerProfile), uint16(pionProfile))
	case "CID":
		require.Positive(t, pionWire.snapshot().cidRecords, "Pion received no tls12_cid records")
		require.Positive(t, peerWire.snapshot().cidRecords, "v3 received no tls12_cid records")
	}
}

type v3MemoryStore struct{ sync.Map }

func (s *v3MemoryStore) Set(key []byte, session dtlsv3.Session) error {
	s.Store(hex.EncodeToString(key), session)

	return nil
}

func (s *v3MemoryStore) Get(key []byte) (dtlsv3.Session, error) {
	if value, ok := s.Load(hex.EncodeToString(key)); ok {
		if session, ok := value.(dtlsv3.Session); ok {
			return session, nil
		}
	}

	return dtlsv3.Session{}, nil
}

func (s *v3MemoryStore) Del(key []byte) error {
	s.Delete(hex.EncodeToString(key))

	return nil
}

func testPionV3DualStackResumption(t *testing.T, pionServer bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	pionCertificate := dualStackCertificate(t, "ECDSA")
	peerCertificate := dualStackCertificate(t, "ECDSA")
	pionStore, peerStore := &memSessStore{}, &v3MemoryStore{}
	// The client keys sessions by server address, so the server keeps its port.
	var serverPort int
	for attempt := range 2 {
		pionSocket, peerSocket := loopbackPair(t)
		if attempt == 1 {
			// Rebind the server's port from the first connection.
			server := peerSocket
			if pionServer {
				server = pionSocket
			}
			require.NoError(t, server.Close())
			rebound, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort})
			require.NoError(t, err)
			t.Cleanup(func() { _ = rebound.Close() })
			if pionServer {
				pionSocket = rebound
			} else {
				peerSocket = rebound
			}
		} else if pionServer {
			serverPort = pionSocket.LocalAddr().(*net.UDPAddr).Port //nolint:forcetypeassert
		} else {
			serverPort = peerSocket.LocalAddr().(*net.UDPAddr).Port //nolint:forcetypeassert
		}
		pionWire, peerWire := newDualStackWire(pionSocket), newDualStackWire(peerSocket)
		pair := handshakePionV3Pair(t, ctx, pionServer, pionWire, peerWire, pionSocket.LocalAddr(), peerSocket.LocalAddr(),
			append(dualStackClientOptions(dualStackDefault, tls.Certificate{}), dtls.WithSessionStore(pionStore)),
			append(dualStackServerOptions(dualStackDefault, pionCertificate), dtls.WithSessionStore(pionStore)),
			[]dtlsv3.ClientOption{dtlsv3.WithInsecureSkipVerify(true), dtlsv3.WithSessionStore(peerStore)},
			[]dtlsv3.ServerOption{dtlsv3.WithCertificates(peerCertificate), dtlsv3.WithSessionStore(peerStore)},
		)
		requireDTLS12(t, pair.pion)
		certificates := pionWire.snapshot().certificates
		if attempt == 0 {
			require.Positive(t, certificates, "first handshake should be a full handshake")
		} else {
			require.Zero(t, certificates, "second handshake did not resume the DTLS 1.2 session")
			if pionServer {
				random := pionWire.snapshot().serverHelloRandom
				require.Equal(t, []byte("DOWNGRD\x01"), random[24:])
			}
		}
		require.NoError(t, pair.pion.Close())
		require.NoError(t, pair.peer.Close())
	}
}

// GnuTLS (no DTLS 1.3 support), pinned to DTLS 1.2 by priority string.

const gnuTLSDTLS12Priority = "NORMAL:-VERS-ALL:+VERS-DTLS1.2"

func gnuTLSBinary(name string) string {
	return filepath.Join(environmentOrDefault("DTLS_INTEROP_GNUTLS_BIN_DIR", ""), name)
}

func TestGnuTLSDualStackLegacy(t *testing.T) {
	for _, certKind := range []string{"RSA", "ECDSA"} {
		t.Run("PionClient/"+certKind, func(t *testing.T) { testDualStackClientGnuTLSServer(t, certKind) })
		t.Run("PionServer/"+certKind, func(t *testing.T) { testDualStackServerGnuTLSClient(t, certKind) })
	}
}

func testDualStackClientGnuTLSServer(t *testing.T, certKind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	certificatePath, keyPath := writeDualStackPEM(t, t.TempDir(), "server", dualStackCertificate(t, certKind))
	address := reserveWolfSSLAddress(t)
	process := startInteropProcess(t, ctx, gnuTLSBinary("gnutls-serv"),
		"--udp", "--echo", "--port", strconv.Itoa(address.Port), "--disable-client-cert",
		"--priority", gnuTLSDTLS12Priority, "--x509certfile", certificatePath, "--x509keyfile", keyPath)
	process.waitForOutput(t, ctx, "listening")
	client, wire := dialDualStackClient(t, ctx, address, dualStackClientOptions(dualStackDefault, tls.Certificate{}))
	require.NoError(t, client.HandshakeContext(ctx), process.output.String())
	requireDualStackClient(t, wire, client)
	exchangeEcho(t, client, "pion-dual-to-gnutls\n", process)
}

func testDualStackServerGnuTLSClient(t *testing.T, certKind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	listener, wire, address := listenDualStackServer(t,
		dualStackServerOptions(dualStackDefault, dualStackCertificate(t, certKind)))
	process := startInteropProcess(t, ctx, gnuTLSBinary("gnutls-cli"),
		"--udp", "--insecure", "--port", strconv.Itoa(address.Port), "--priority", gnuTLSDTLS12Priority, "127.0.0.1")
	server := acceptDualStack(t, ctx, listener, process.waitDone, process.output.String)
	require.NoError(t, server.HandshakeContext(ctx), process.output.String())
	requireDualStackServer(t, wire, server)
	exchangeStdinPeer(t, ctx, server, process, "gnutls-to-pion-dual\n", "pion-dual-to-gnutls\n")
}

func exchangeEcho(t *testing.T, connection *dtls.Conn, message string, process *interopProcess) {
	t.Helper()
	_, err := io.WriteString(connection, message)
	require.NoError(t, err)
	received := make([]byte, len(message))
	_, err = io.ReadFull(connection, received)
	require.NoError(t, err, process.output.String())
	require.Equal(t, message, string(received))
}

// exchangeStdinPeer sends through a CLI peer's stdin and expects Pion's reply on its stdout.
func exchangeStdinPeer(
	t *testing.T, ctx context.Context, connection *dtls.Conn, process *interopProcess, peerMessage, pionMessage string,
) {
	t.Helper()
	_, err := io.WriteString(process.stdin, peerMessage)
	require.NoError(t, err)
	received := make([]byte, len(peerMessage))
	_, err = io.ReadFull(connection, received)
	require.NoError(t, err, process.output.String())
	require.Equal(t, peerMessage, string(received))
	_, err = io.WriteString(connection, pionMessage)
	require.NoError(t, err)
	process.waitForOutput(t, ctx, pionMessage)
}

// NSS (Firefox's TLS stack): tstclnt as a DTLS 1.2 client.

func TestNSSDualStackLegacy(t *testing.T) {
	for _, certKind := range []string{"RSA", "ECDSA"} {
		t.Run("PionServer/"+certKind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()
			listener, wire, address := listenDualStackServer(t,
				dualStackServerOptions(dualStackDefault, dualStackCertificate(t, certKind)))
			binDir := environmentOrDefault("DTLS_INTEROP_NSS_BIN_DIR", "")
			database := "sql:" + t.TempDir()
			output, err := exec.CommandContext(ctx, filepath.Join(binDir, "certutil"), //nolint:gosec
				"-N", "--empty-password", "-d", database).CombinedOutput()
			require.NoError(t, err, string(output))
			process := startInteropProcess(t, ctx, filepath.Join(binDir, "tstclnt"), "-d", database,
				"-P", "client", "-h", "127.0.0.1", "-p", strconv.Itoa(address.Port), "-V", "tls1.2:tls1.2", "-o")
			server := acceptDualStack(t, ctx, listener, process.waitDone, process.output.String)
			require.NoError(t, server.HandshakeContext(ctx), process.output.String())
			requireDualStackServer(t, wire, server)
			exchangeStdinPeer(t, ctx, server, process, "nss-to-pion-dual\n", "pion-dual-to-nss\n")
		})
	}
}

func (s dualStackSnapshot) String() string {
	return fmt.Sprintf("ClientHello %d bytes in %d records/%d datagrams, HelloVerifyRequest seen: %t, ServerHello seen: %t",
		s.helloLength, s.helloRecords, s.helloDatagrams, s.helloVerifyVersion != 0, s.serverHelloSeen)
}
