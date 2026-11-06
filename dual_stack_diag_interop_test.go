//go:build interop

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	dtlsv3 "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

// Temporary diagnostic: isolate which ClientHello property wolfSSL's DTLS 1.2 server rejects.
func TestDiagWolfSSL12Server(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []dtls.ClientOption
	}{
		{"Only12", []dtls.ClientOption{dtls.WithMaxVersion(protocol.Version1_2)}},
		{"DualNoMLKEM", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519, elliptic.P256, elliptic.P384)}},
		{"DualDefault", nil},
		{"Only12_FragmentedMTU150", []dtls.ClientOption{dtls.WithMaxVersion(protocol.Version1_2), dtls.WithMTU(150)}},
		{"DualNoMLKEM_FragmentedMTU200", []dtls.ClientOption{
			dtls.WithEllipticCurves(elliptic.X25519, elliptic.P256, elliptic.P384), dtls.WithMTU(200),
		}},
		{"DualDefault_UnfragmentedMTU4000", []dtls.ClientOption{dtls.WithMTU(4000)}},
		{"TwoShares_MTU1200", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519)}},
		{"TwoShares_MTU1500", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519), dtls.WithMTU(1500)}},
		{"DualDefault_MTU1500", []dtls.ClientOption{dtls.WithMTU(1500)}},
	} {
		for _, version := range []string{"3", "d"} {
			t.Run(test.name+"/v"+version, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
				defer cancel()
				address := reserveWolfSSLAddress(t)
				process := startWolfSSLProcess(t, ctx,
					environmentOrDefault("DTLS_INTEROP_WOLFSSL_SERVER_BIN", "wolfssl-dtls13-server"),
					"-u", "-v", version, "-p", strconv.Itoa(address.Port), "-d", "-e")
				options := append(dualStackClientOptions(dualStackDefault, tls.Certificate{}), test.options...)
				client, wire := dialDualStackClient(t, ctx, address, options)
				err := client.HandshakeContext(ctx)
				s := wire.snapshot()
				negotiated := protocol.Version(0)
				if state, ok := client.ConnectionState(); ok {
					negotiated = state.NegotiatedVersion()
				}
				t.Logf("err=%v negotiated=%v hello=%dB records=%d datagrams=%d hvr=%v serverHello=%v",
					err, negotiated, s.helloLength, s.helloRecords, s.helloDatagrams, s.helloVerifyVersion, s.serverHelloSeen)
				process.stop()
			})
		}
	}
}

// Temporary diagnostic: does a Pion client resume a DTLS 1.2 session, by max version and server?
func TestDiagResumptionClient(t *testing.T) {
	for _, test := range []struct {
		name      string
		clientMax protocol.Version
		v4Server  bool
		serverMax protocol.Version
	}{
		{"Only12Client_v3Server", protocol.Version1_2, false, 0},
		{"DualClient_v3Server", 0, false, 0},
		{"Only12Client_v4Only12Server", protocol.Version1_2, true, protocol.Version1_2},
		{"DualClient_v4Only12Server", 0, true, protocol.Version1_2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()
			clientStore, serverStore, v3Store := &memSessStore{}, &memSessStore{}, &v3MemoryStore{}
			certificate := dualStackCertificate(t, "ECDSA")
			serverSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			serverAddress := serverSocket.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
			_ = serverSocket.Close()
			for attempt := range 2 {
				serverSocket, err := net.ListenUDP("udp4", serverAddress)
				if err != nil {
					t.Fatal(err)
				}
				clientSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				wire := newDualStackWire(clientSocket)
				clientOptions := []dtls.ClientOption{dtls.WithInsecureSkipVerify(true), dtls.WithSessionStore(clientStore)}
				if test.clientMax != 0 {
					clientOptions = append(clientOptions, dtls.WithMaxVersion(test.clientMax))
				}
				client, err := dtls.Client(wire, serverAddress, clientOptions...)
				if err != nil {
					t.Fatal(err)
				}
				var serverHandshake func(context.Context) error
				var closeServer func() error
				if test.v4Server {
					server, err := dtls.Server(serverSocket, clientSocket.LocalAddr(), dtls.WithCertificates(certificate),
						dtls.WithMaxVersion(test.serverMax), dtls.WithSessionStore(serverStore))
					if err != nil {
						t.Fatal(err)
					}
					serverHandshake, closeServer = server.HandshakeContext, server.Close
				} else {
					server, err := dtlsv3.ServerWithOptions(serverSocket, clientSocket.LocalAddr(),
						dtlsv3.WithCertificates(certificate), dtlsv3.WithSessionStore(v3Store))
					if err != nil {
						t.Fatal(err)
					}
					serverHandshake, closeServer = server.HandshakeContext, server.Close
				}
				done := make(chan error, 1)
				go func() { done <- serverHandshake(ctx) }()
				clientErr := client.HandshakeContext(ctx)
				serverErr := <-done
				hello := wire.clientHello(t)
				t.Logf("attempt %d: clientErr=%v serverErr=%v ClientHello.session_id=%dB certificates=%d",
					attempt, clientErr, serverErr, len(hello.SessionID), wire.snapshot().certificates)
				_ = client.Close()
				_ = closeServer()
				_ = serverSocket.Close()
			}
			stored := 0
			clientStore.Range(func(key, value any) bool {
				session, _ := value.(dtls.Session)
				t.Logf("client store: key=%s id=%dB ticket=%v", key, len(session.ID), session.Ticket != nil)
				stored++

				return true
			})
			t.Logf("client store entries=%d", stored)
		})
	}
}

// Temporary diagnostic: Mbed TLS ssl_server2 (DTLS 1.2) against fragmented and unfragmented ClientHellos.
func TestDiagMbedTLSServer(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []dtls.ClientOption
	}{
		{"Only12", []dtls.ClientOption{dtls.WithMaxVersion(protocol.Version1_2)}},
		{"DualNoMLKEM", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519, elliptic.P256, elliptic.P384)}},
		{"DualDefault", nil},
		{"DualNoMLKEM_FragmentedMTU200", []dtls.ClientOption{
			dtls.WithEllipticCurves(elliptic.X25519, elliptic.P256, elliptic.P384), dtls.WithMTU(200),
		}},
		{"DualDefault_UnfragmentedMTU4000", []dtls.ClientOption{dtls.WithMTU(4000)}},
		{"TwoShares_MTU1200", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519)}},
		{"TwoShares_MTU1500", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519), dtls.WithMTU(1500)}},
		{"DualDefault_MTU1500", []dtls.ClientOption{dtls.WithMTU(1500)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()
			address := reserveWolfSSLAddress(t)
			process := startInteropProcess(t, ctx,
				environmentOrDefault("DTLS_INTEROP_MBEDTLS_SERVER_BIN", "ssl_server2"),
				"server_addr=127.0.0.1", "server_port="+strconv.Itoa(address.Port),
				"force_version=dtls12", "auth_mode=none", "exchanges=1")
			process.waitForOutput(t, ctx, "Waiting for a remote connection")
			options := append(dualStackClientOptions(dualStackDefault, tls.Certificate{}), test.options...)
			client, wire := dialDualStackClient(t, ctx, address, options)
			err := client.HandshakeContext(ctx)
			s := wire.snapshot()
			t.Logf("err=%v hello=%dB records=%d hvr=%v serverHello=%v", err, s.helloLength, s.helloRecords,
				s.helloVerifyVersion, s.serverHelloSeen)
		})
	}
}

// Temporary diagnostic: is the wolfSSL failure specific to dual mode? Pion 1.3-only, default curves.
func TestDiagWolfSSL13Server(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []dtls.ClientOption
	}{
		{"Only13Default", nil},
		{"Only13NoMLKEM", []dtls.ClientOption{dtls.WithEllipticCurves(elliptic.X25519, elliptic.P256, elliptic.P384)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()
			address := reserveWolfSSLAddress(t)
			process := startWolfSSLProcess(t, ctx,
				environmentOrDefault("DTLS_INTEROP_WOLFSSL_SERVER_BIN", "wolfssl-dtls13-server"),
				"-u", "-v", "4", "-p", strconv.Itoa(address.Port), "-d", "-e")
			options := append([]dtls.ClientOption{
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
			}, test.options...)
			client, wire := dialDualStackClient(t, ctx, address, options)
			err := client.HandshakeContext(ctx)
			t.Logf("err=%v %s", err, wire.snapshot())
			process.stop()
		})
	}
}

// Temporary diagnostic: wolfSSL as the client against Pion's default (dual-stack) server.
func TestDiagWolfSSLClientVsDualServer(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{"v3_Only12", []string{"-v", "3"}},
		{"v4_Only13", []string{"-v", "4"}},
		{"vd_12or13", []string{"-v", "d"}},
		{"v4_Only13_PQC_X25519MLKEM768", []string{"-v", "4", "--pqc", "X25519MLKEM768"}},
		{"vd_12or13_PQC_X25519MLKEM768", []string{"-v", "d", "--pqc", "X25519MLKEM768"}},
	} {
		for _, certKind := range []string{"RSA", "ECDSA"} {
			t.Run(test.name+"/"+certKind, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
				defer cancel()
				listener, wire, address := listenDualStackServer(t,
					dualStackServerOptions(dualStackDefault, dualStackCertificate(t, certKind)))
				arguments := append([]string{"-h", "127.0.0.1", "-p", strconv.Itoa(address.Port), "-u", "-d", "-x"},
					test.arguments...)
				process := startWolfSSLProcess(t, ctx,
					environmentOrDefault("DTLS_INTEROP_WOLFSSL_CLIENT_BIN", "wolfssl-dtls13-client"), arguments...)
				server := acceptDualStack(t, ctx, listener, process.waitDone, process.output)
				err := server.HandshakeContext(ctx)
				negotiated := protocol.Version(0)
				if state, ok := server.ConnectionState(); ok {
					negotiated = state.NegotiatedVersion()
				}
				shares := []string{}
				if s := wire.snapshot(); s.helloLength > 0 {
					_, shares = offeredVersions(wire.clientHello(t))
				}
				t.Logf("handshake err=%v negotiated=%v wolfSSL %s key_shares=%v", err, negotiated, wire.snapshot(), shares)
				process.requireNoError(t, "Pion server handshake", err)
				readWolfSSLMessage(t, process, server)
				writeWolfSSLMessage(t, process, server)
				process.wait(t, ctx)
				t.Logf("application data both ways OK; wolfSSL exited cleanly; wolfSSL stdout: %s", process.stdout.String())
			})
		}
	}
}

// Temporary diagnostic: BoringSSL (Chromium) clients against Pion's default server.
func TestDiagBoringSSLClientVsDefaultServer(t *testing.T) {
	const dtls12, dtls13 = "65277", "65276"
	for _, test := range []struct {
		name, minVersion, maxVersion, curves string
		want                                 protocol.Version
	}{
		{"Dual_DefaultCurves", dtls12, dtls13, "", protocol.Version1_3},
		{"Dual_X25519MLKEM768", dtls12, dtls13, "4588", protocol.Version1_3},
		{"Only13_DefaultCurves", dtls13, dtls13, "", protocol.Version1_3},
		{"Only13_X25519MLKEM768", dtls13, dtls13, "4588", protocol.Version1_3},
		{"Only12_DefaultCurves", dtls12, dtls12, "", protocol.Version1_2},
	} {
		for _, variant := range []dualStackVariant{dualStackDefault, dualStackWebRTC} {
			t.Run(test.name+"/"+string(variant), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
				defer cancel()
				credentials, err := newBoringSSLCredentials()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(credentials.remove)
				var listenConfig net.ListenConfig
				tcpListener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tcpListener.Close() })
				arguments := []string{
					"-port", strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port), //nolint:forcetypeassert
					"-shim-id", strconv.FormatUint(shimID, 10), "-dtls",
					"-min-version", test.minVersion, "-max-version", test.maxVersion,
					"-expect-version", strconv.Itoa(int(test.want)),
					"-shim-writes-first", "-expect-no-session",
				}
				if test.curves != "" {
					arguments = append(arguments, "-curves", test.curves)
				}
				if variant == dualStackWebRTC {
					arguments = append(arguments, "-cert-file", credentials.certificatePath,
						"-key-file", credentials.privateKeyPath, "-srtp-profiles", "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80")
				}
				process := &shimProcess{waitDone: make(chan struct{})}
				childCtx, cancelChild := context.WithCancel(ctx)
				process.cancel = cancelChild
				command := exec.CommandContext(childCtx, //nolint:gosec
					environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"), arguments...)
				command.Stdout, command.Stderr = &process.stdout, &process.stderr
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				go func() { process.waitErr = command.Wait(); close(process.waitDone) }()
				t.Cleanup(process.stop)
				output := func() string { return process.stdout.String() + process.stderr.String() }
				connection, err := acceptShimConnection(ctx, tcpListener, process)
				if err != nil {
					t.Fatal(err, output())
				}
				t.Cleanup(func() { _ = connection.Close() })
				if err := readAndValidateShimID(ctx, connection); err != nil {
					t.Fatal(err)
				}
				packeted := newPacketedConn(connection)
				wire := newDualStackWire(packeted)
				pion, err := dtls.Server(wire, packeted.RemoteAddr(),
					dualStackServerOptions(variant, dualStackCertificate(t, "ECDSA"))...)
				if err != nil {
					t.Fatal(err)
				}
				var log bytes.Buffer
				var negotiated protocol.Version
				err = runPionDTLS13Exchange(ctx, pion, packeted, &log, "default-server", "received",
					pionDTLS13ExchangeOptions{checkConnection: func(c *dtls.Conn) error {
						state, _ := c.ConnectionState()
						negotiated = state.NegotiatedVersion()

						return nil
					}})
				shares := []string{}
				if wire.snapshot().helloLength > 0 {
					_, shares = offeredVersions(wire.clientHello(t))
				}
				t.Logf("err=%v negotiated=%v want=%v key_shares=%v %s", err, negotiated, test.want, shares, wire.snapshot())
				if err != nil {
					t.Fatal(err, output())
				}
				if waitErr := process.wait(ctx); waitErr != nil {
					t.Fatal(waitErr, output())
				}
				if negotiated != test.want {
					t.Fatalf("negotiated %v, want %v", negotiated, test.want)
				}
			})
		}
	}
}

// Temporary diagnostic: NSS (Firefox) tstclnt against Pion's default server.
func TestDiagNSSClientVsDefaultServer(t *testing.T) {
	for _, test := range []struct {
		name, versions, groups string
		want                   protocol.Version
	}{
		{"Dual_DefaultGroups", "tls1.2:tls1.3", "", protocol.Version1_3},
		{"Only13_DefaultGroups", "tls1.3:tls1.3", "", protocol.Version1_3},
		{"Dual_MLKEMFirst", "tls1.2:tls1.3", "mlkem768x25519,x25519,P256", protocol.Version1_3},
		{"Only13_MLKEMOnly", "tls1.3:tls1.3", "mlkem768x25519", protocol.Version1_3},
		{"Only12_DefaultGroups", "tls1.2:tls1.2", "", protocol.Version1_2},
	} {
		for _, certKind := range []string{"RSA", "ECDSA"} {
			t.Run(test.name+"/"+certKind, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
				defer cancel()
				listener, wire, address := listenDualStackServer(t,
					dualStackServerOptions(dualStackDefault, dualStackCertificate(t, certKind)))
				binDir := environmentOrDefault("DTLS_INTEROP_NSS_BIN_DIR", "")
				database := "sql:" + t.TempDir()
				if out, err := exec.CommandContext(ctx, filepath.Join(binDir, "certutil"), //nolint:gosec
					"-N", "--empty-password", "-d", database).CombinedOutput(); err != nil {
					t.Fatal(err, string(out))
				}
				arguments := []string{"-d", database, "-P", "client", "-h", "127.0.0.1",
					"-p", strconv.Itoa(address.Port), "-V", test.versions, "-o"}
				if test.groups != "" {
					arguments = append(arguments, "-I", test.groups)
				}
				process := startInteropProcess(t, ctx, filepath.Join(binDir, "tstclnt"), arguments...)
				server := acceptDualStack(t, ctx, listener, process.waitDone, process.output.String)
				err := server.HandshakeContext(ctx)
				negotiated := protocol.Version(0)
				if state, ok := server.ConnectionState(); ok {
					negotiated = state.NegotiatedVersion()
				}
				shares := []string{}
				if wire.snapshot().helloLength > 0 {
					_, shares = offeredVersions(wire.clientHello(t))
				}
				t.Logf("err=%v negotiated=%v want=%v key_shares=%v %s", err, negotiated, test.want, shares, wire.snapshot())
				if err != nil {
					t.Fatal(err, process.output.String())
				}
				if negotiated != test.want {
					t.Fatalf("negotiated %v, want %v", negotiated, test.want)
				}
				exchangeStdinPeer(t, ctx, server, process, "nss-to-pion\n", "pion-to-nss\n")
			})
		}
	}
}

// Temporary diagnostic: DTLS 1.2 CID (RFC 9146) between Pion's dual-stack config and Mbed TLS 3.6.
func TestDiagMbedTLSCID(t *testing.T) {
	mbedDir := filepath.Dir(environmentOrDefault("DTLS_INTEROP_MBEDTLS_SERVER_BIN", "ssl_server2"))
	for _, test := range []struct {
		name    string
		pionCID []byte // nil: CID disabled in Pion
		pionOn  bool
		mbedCID string // hex; "" with mbedOn means zero-length
		mbedOn  bool
	}{
		{"BothNonZero", []byte("pion-cid"), true, "beef01", true},
		{"PionZeroLength_MbedNonZero", []byte{}, true, "beef01", true},
		{"PionNonZero_MbedZeroLength", []byte("pion-cid"), true, "", true},
		{"PionOnly", []byte("pion-cid"), true, "", false},
		{"MbedOnly", nil, false, "beef01", true},
	} {
		for _, pionServer := range []bool{false, true} {
			role := "PionClient"
			if pionServer {
				role = "PionServer"
			}
			t.Run(role+"/"+test.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
				defer cancel()
				cidArgs := []string{"cid=0"}
				if test.mbedOn {
					cidArgs = []string{"cid=1", "cid_val=" + test.mbedCID}
				}
				var cidOption []dtls.ClientOption
				var cidServerOption []dtls.ServerOption
				if test.pionOn {
					cid := test.pionCID
					generator := func() []byte { return append([]byte{}, cid...) }
					cidOption = append(cidOption, dtls.WithConnectionID(generator, dtls.CIDPathMigrationReject))
					cidServerOption = append(cidServerOption, dtls.WithConnectionID(generator, dtls.CIDPathMigrationReject))
				}
				var wire *dualStackWire
				var process *interopProcess
				if !pionServer {
					address := reserveWolfSSLAddress(t)
					process = startInteropProcess(t, ctx, filepath.Join(mbedDir, "ssl_server2"), append([]string{
						"server_addr=127.0.0.1", "server_port=" + strconv.Itoa(address.Port),
						"force_version=dtls12", "auth_mode=none", "exchanges=1",
					}, cidArgs...)...)
					process.waitForOutput(t, ctx, "Waiting for a remote connection")
					var client *dtls.Conn
					client, wire = dialDualStackClient(t, ctx, address,
						append(dualStackClientOptions(dualStackDefault, tls.Certificate{}), cidOption...))
					if err := client.HandshakeContext(ctx); err != nil {
						t.Fatal(err, wire.snapshot(), process.output.String())
					}
					if _, err := client.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 2048)
					n, err := client.Read(buf)
					if err != nil || !bytes.Contains(buf[:n], []byte("200 OK")) {
						t.Fatal(err, string(buf[:n]), process.output.String())
					}
				} else {
					listener, w, address := listenDualStackServer(t,
						append(dualStackServerOptions(dualStackDefault, dualStackCertificate(t, "ECDSA")), cidServerOption...))
					wire = w
					process = startInteropProcess(t, ctx, filepath.Join(mbedDir, "ssl_client2"), append([]string{
						"dtls=1", "force_version=dtls12", "server_addr=127.0.0.1",
						"server_port=" + strconv.Itoa(address.Port), "auth_mode=none", "exchanges=1",
					}, cidArgs...)...)
					server := acceptDualStack(t, ctx, listener, process.waitDone, process.output.String)
					if err := server.HandshakeContext(ctx); err != nil {
						t.Fatal(err, process.output.String())
					}
					buf := make([]byte, 2048)
					n, err := server.Read(buf)
					if err != nil || !bytes.Contains(buf[:n], []byte("GET /")) {
						t.Fatal(err, string(buf[:n]), process.output.String())
					}
					if _, err := server.Write([]byte("HTTP/1.0 200 OK\r\n\r\npion\r\n")); err != nil {
						t.Fatal(err)
					}
					process.waitForOutput(t, ctx, "pion")
				}
				peerCIDLines := []string{}
				for _, line := range strings.Split(process.output.String(), "\n") {
					if strings.Contains(line, "CID") {
						peerCIDLines = append(peerCIDLines, strings.TrimSpace(line))
					}
				}
				t.Logf("OK: tls12_cid records seen by Pion (both directions)=%d; Mbed TLS says: %v",
					wire.snapshot().cidRecords, peerCIDLines)
			})
		}
	}
}

// Temporary diagnostic: which key shares each ClientHello (by message_seq) carries.
type keyShareWire struct {
	net.PacketConn

	mutex  sync.Mutex
	bodies map[uint16][]byte
}

func (w *keyShareWire) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	w.mutex.Lock()
	records, _ := recordlayer.UnpackDatagram(buffer, recordlayer.UnpackDatagramConfig{})
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
			if header.Type == handshake.TypeClientHello {
				body := w.bodies[header.MessageSequence]
				if len(body) != int(header.Length) {
					body = make([]byte, header.Length)
				}
				copy(body[header.FragmentOffset:], payload[handshake.HeaderLength:end])
				w.bodies[header.MessageSequence] = body
			}
			payload = payload[end:]
		}
	}
	w.mutex.Unlock()

	return w.PacketConn.WriteTo(buffer, addr)
}

func (w *keyShareWire) describe() string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	out := ""
	for sequence := uint16(0); sequence < 4; sequence++ {
		body, ok := w.bodies[sequence]
		if !ok {
			continue
		}
		var hello handshake.MessageClientHello
		if err := hello.Unmarshal(body); err != nil {
			out += fmt.Sprintf(" CH%d(%dB, unparsed: %v)", sequence, len(body), err)

			continue
		}
		var groups []string
		for _, value := range hello.Extensions {
			if shares, ok := value.(*extension13.ClientKeyShare); ok {
				for _, share := range shares.Shares {
					groups = append(groups, share.Group.String())
				}
			}
		}
		out += fmt.Sprintf(" CH%d(%dB shares=%v cookie=%t session_id=%dB)", sequence, len(body), groups, len(hello.Cookie) > 0, len(hello.SessionID))
	}

	return out
}

var (
	keyShareDefaultCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519, elliptic.P256, elliptic.P384}
	keyShareMLKEMSecond   = []elliptic.Curve{elliptic.X25519, elliptic.X25519MLKEM768, elliptic.P256, elliptic.P384}
)

func dialKeyShareClient(t *testing.T, ctx context.Context, server net.Addr, options []dtls.ClientOption) (*dtls.Conn, *keyShareWire) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	wire := &keyShareWire{PacketConn: socket, bodies: map[uint16][]byte{}}
	client, err := dtls.Client(wire, server, options...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	deadline, _ := ctx.Deadline()
	require.NoError(t, client.SetDeadline(deadline))

	return client, wire
}

// Pion client -> Pion server: which shares go out, and does ML-KEM still win?
func TestDiagKeySharePionToPion(t *testing.T) {
	for _, test := range []struct {
		name                 string
		clientCurves, server []elliptic.Curve
	}{
		{"ClientDefault_ServerDefault", keyShareDefaultCurves, keyShareDefaultCurves},
		{"ClientMLKEMSecond_ServerDefault", keyShareMLKEMSecond, keyShareDefaultCurves},
		{"ClientMLKEMSecond_ServerMLKEMSecond", keyShareMLKEMSecond, keyShareMLKEMSecond},
		{"ClientDefault_ServerMLKEMSecond", keyShareDefaultCurves, keyShareMLKEMSecond},
		{"ClientDefault_ServerP256Only", keyShareDefaultCurves, []elliptic.Curve{elliptic.P256}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()
			certificate := dualStackCertificate(t, "ECDSA")
			listener, _, address := listenDualStackServer(t, []dtls.ServerOption{
				dtls.WithCertificates(certificate), dtls.WithEllipticCurves(test.server...),
			})
			accepted := make(chan *dtls.Conn, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					accepted <- nil

					return
				}
				server, _ := connection.(*dtls.Conn)
				_ = server.HandshakeContext(ctx)
				accepted <- server
			}()
			client, wire := dialKeyShareClient(t, ctx, address, []dtls.ClientOption{
				dtls.WithInsecureSkipVerify(true), dtls.WithEllipticCurves(test.clientCurves...),
			})
			err := client.HandshakeContext(ctx)
			server := <-accepted
			negotiated := protocol.Version(0)
			if state, ok := client.ConnectionState(); ok {
				negotiated = state.NegotiatedVersion()
			}
			t.Logf("err=%v version=%v%s", err, negotiated, wire.describe())
			require.NoError(t, err)
			if server != nil {
				go func() { _, _ = io.Copy(io.Discard, server) }()
				_ = server.Close()
			}
		})
	}
}

// Pion client -> wolfSSL / Mbed TLS servers with the new share rule.
func TestDiagKeyShareLegacyServers(t *testing.T) {
	for _, curves := range []struct {
		name   string
		curves []elliptic.Curve
	}{
		{"Default", keyShareDefaultCurves},
		{"MLKEMSecond", keyShareMLKEMSecond},
	} {
		for _, wolfVersion := range []string{"3", "4", "d"} {
			t.Run("wolfSSL_v"+wolfVersion+"/"+curves.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
				defer cancel()
				address := reserveWolfSSLAddress(t)
				process := startWolfSSLProcess(t, ctx,
					environmentOrDefault("DTLS_INTEROP_WOLFSSL_SERVER_BIN", "wolfssl-dtls13-server"),
					"-u", "-v", wolfVersion, "-p", strconv.Itoa(address.Port), "-d", "-e")
				options := append(dualStackClientOptions(dualStackDefault, tls.Certificate{}), dtls.WithEllipticCurves(curves.curves...))
				if wolfVersion == "4" {
					options = append(options, dtls.WithMinVersion(protocol.Version1_3))
				}
				client, wire := dialKeyShareClient(t, ctx, address, options)
				err := client.HandshakeContext(ctx)
				negotiated := protocol.Version(0)
				if state, ok := client.ConnectionState(); ok {
					negotiated = state.NegotiatedVersion()
				}
				t.Logf("err=%v version=%v%s", err, negotiated, wire.describe())
				process.stop()
			})
		}
		t.Run("MbedTLS/"+curves.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()
			address := reserveWolfSSLAddress(t)
			process := startInteropProcess(t, ctx,
				environmentOrDefault("DTLS_INTEROP_MBEDTLS_SERVER_BIN", "ssl_server2"),
				"server_addr=127.0.0.1", "server_port="+strconv.Itoa(address.Port),
				"force_version=dtls12", "auth_mode=none", "exchanges=1")
			process.waitForOutput(t, ctx, "Waiting for a remote connection")
			options := append(dualStackClientOptions(dualStackDefault, tls.Certificate{}), dtls.WithEllipticCurves(curves.curves...))
			client, wire := dialKeyShareClient(t, ctx, address, options)
			err := client.HandshakeContext(ctx)
			t.Logf("err=%v%s", err, wire.describe())
		})
	}
}

// Temporary diagnostic: a cached DTLS 1.2 session ID offered to DTLS 1.3 servers.
type anyKeyStore struct {
	mutex   sync.Mutex
	session dtls.Session
}

func (s *anyKeyStore) Set(_ []byte, session dtls.Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.session = session

	return nil
}

func (s *anyKeyStore) Get([]byte) (dtls.Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.session, nil
}

func (s *anyKeyStore) Del([]byte) error { return nil }

func cacheDTLS12Session(t *testing.T, store *anyKeyStore) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	certificate := dualStackCertificate(t, "ECDSA")
	listener, _, address := listenDualStackServer(t, []dtls.ServerOption{
		dtls.WithCertificates(certificate), dtls.WithMaxVersion(protocol.Version1_2), dtls.WithSessionStore(&anyKeyStore{}),
	})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			server, _ := connection.(*dtls.Conn)
			_ = server.HandshakeContext(ctx)
			go func() { _, _ = io.Copy(io.Discard, server) }()
		}
	}()
	client, _ := dialKeyShareClient(t, ctx, address, []dtls.ClientOption{
		dtls.WithInsecureSkipVerify(true), dtls.WithSessionStore(store),
	})
	require.NoError(t, client.HandshakeContext(ctx))
	require.NotEmpty(t, store.session.ID)
}

func TestDiagCachedSession12ToDTLS13Servers(t *testing.T) {
	t.Run("wolfSSL_v4", func(t *testing.T) {
		store := &anyKeyStore{}
		cacheDTLS12Session(t, store)
		ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
		defer cancel()
		address := reserveWolfSSLAddress(t)
		process := startWolfSSLProcess(t, ctx,
			environmentOrDefault("DTLS_INTEROP_WOLFSSL_SERVER_BIN", "wolfssl-dtls13-server"),
			"-u", "-v", "4", "-p", strconv.Itoa(address.Port), "-d", "-e")
		defer process.stop()
		client, wire := dialKeyShareClient(t, ctx, address, []dtls.ClientOption{
			dtls.WithInsecureSkipVerify(true), dtls.WithSessionStore(store),
		})
		err := client.HandshakeContext(ctx)
		negotiated := protocol.Version(0)
		if state, ok := client.ConnectionState(); ok {
			negotiated = state.NegotiatedVersion()
		}
		t.Logf("err=%v version=%v%s", err, negotiated, wire.describe())
		require.NoError(t, err)
		require.Equal(t, protocol.Version1_3, negotiated)
	})
}
