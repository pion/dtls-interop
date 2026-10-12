// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPionV4PSK(t *testing.T) { //nolint:cyclop,maintidx
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ClientIdentity         []byte
		pskCount               int
		selectedPSK            int
		pskHash                crypto.Hash
		unusedHash             crypto.Hash
		skipRetry              bool
		pskOnly                bool
		noCommonGroup          bool
		keyShareRetry          bool
		wantSuite              cryptosuite.ID
		cipherSuites           []cryptosuite.ID
		minVersion             protocol.Version
		maxVersion             protocol.Version
		ClientVerifyConnection func(*dtls.State) error
		ServerVerifyConnection func(*dtls.State) error
		WantFail               bool
		ExpectedServerErr      string
		ExpectedClientErr      string
	}{
		{
			Name:           "DTLS 1.3",
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "prefer DHE with key share retry",
			ClientIdentity: []byte("dhe"),
			keyShareRetry:  true,
			skipRetry:      true,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "psk_ke",
			ClientIdentity: []byte("ke"),
			pskOnly:        true,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "psk_ke SHA384 without retry",
			ClientIdentity: []byte("ke"),
			pskOnly:        true,
			pskHash:        crypto.SHA384,
			skipRetry:      true,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_256_GCM_SHA384},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "psk_ke without common group",
			ClientIdentity: []byte("ke"),
			noCommonGroup:  true,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "DTLS 1.3 selects second PSK",
			ClientIdentity: []byte("Client Identity"),
			pskCount:       2,
			selectedPSK:    1,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "DTLS 1.3 selects last PSK",
			ClientIdentity: []byte("Client Identity"),
			pskCount:       3,
			selectedPSK:    2,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
		},
		{
			Name:           "Dual version selects second PSK",
			ClientIdentity: []byte("Client Identity"),
			pskCount:       2,
			selectedPSK:    1,
			cipherSuites: []cryptosuite.ID{
				cryptosuite.TLS_AES_128_GCM_SHA256,
				cryptosuite.TLS_PSK_WITH_AES_128_CCM_8,
			},
			minVersion: protocol.Version1_2,
			maxVersion: protocol.Version1_3,
		},
		{
			Name:           "SHA384",
			ClientIdentity: []byte("sha384"),
			pskHash:        crypto.SHA384,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_256_GCM_SHA384},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
			wantSuite:      cryptosuite.TLS_AES_256_GCM_SHA384,
		},
		{
			Name:           "SHA384 without retry",
			ClientIdentity: []byte("sha384"),
			pskHash:        crypto.SHA384,
			skipRetry:      true,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_256_GCM_SHA384},
			minVersion:     protocol.Version1_3,
			maxVersion:     protocol.Version1_3,
			wantSuite:      cryptosuite.TLS_AES_256_GCM_SHA384,
		},
		{
			Name:           "Mixed hashes select SHA384",
			ClientIdentity: []byte("sha384"),
			pskHash:        crypto.SHA384,
			pskCount:       2,
			selectedPSK:    1,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256, cryptosuite.TLS_AES_256_GCM_SHA384},
			minVersion:     protocol.Version1_3, maxVersion: protocol.Version1_3, wantSuite: cryptosuite.TLS_AES_256_GCM_SHA384,
		},
		{
			Name:           "Mixed hashes select SHA256",
			ClientIdentity: []byte("sha256"),
			pskHash:        crypto.SHA256,
			unusedHash:     crypto.SHA384,
			pskCount:       2,
			selectedPSK:    1,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_AES_256_GCM_SHA384, cryptosuite.TLS_AES_128_GCM_SHA256},
			minVersion:     protocol.Version1_3, maxVersion: protocol.Version1_3, wantSuite: cryptosuite.TLS_AES_128_GCM_SHA256,
		},
		{
			Name: "Dual version SHA384", ClientIdentity: []byte("sha384"), pskHash: crypto.SHA384, pskCount: 2, selectedPSK: 1,
			cipherSuites: []cryptosuite.ID{
				cryptosuite.TLS_AES_128_GCM_SHA256,
				cryptosuite.TLS_AES_256_GCM_SHA384,
				cryptosuite.TLS_PSK_WITH_AES_128_CCM_8,
			},
			minVersion: protocol.Version1_2, maxVersion: protocol.Version1_3, wantSuite: cryptosuite.TLS_AES_256_GCM_SHA384,
		},
		{
			Name:           "DTLS 1.2 uses first PSK",
			ClientIdentity: []byte("Client Identity"),
			pskCount:       2,
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "DTLS 1.2",
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "Server verify connection fails",
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_PSK_WITH_AES_128_CCM_8},
			ServerVerifyConnection: func(*dtls.State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: errExample.Error(),
			ExpectedClientErr: alert.BadCertificate.String(),
		},
		{
			Name:           "Client verify connection fails",
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_PSK_WITH_AES_128_CCM_8},
			ClientVerifyConnection: func(*dtls.State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: alert.BadCertificate.String(),
			ExpectedClientErr: errExample.Error(),
		},
		{
			Name:           "TLS_PSK_WITH_AES_128_CBC_SHA256",
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "Client identity empty",
			ClientIdentity: []byte{},
			cipherSuites:   []cryptosuite.ID{cryptosuite.TLS_PSK_WITH_AES_128_CCM_8},
		},
	} {
		if test.minVersion == 0 {
			test.minVersion, test.maxVersion = protocol.Version1_2, protocol.Version1_2
		}
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			type result struct {
				c   *dtls.Conn
				err error
			}
			clientRes := make(chan result, 1)

			count := max(test.pskCount, 1)
			psks := make([]dtls.PSK, count)
			for i := range psks {
				psks[i] = dtls.PSK{
					Identity: fmt.Appendf(nil, "unused-%d", i),
					Key:      []byte("unused secret"),
					Hash:     test.unusedHash,
				}
			}
			psks[test.selectedPSK] = dtls.PSK{
				Identity: test.ClientIdentity,
				Key:      []byte{0xAB, 0xC1, 0x23},
				Hash:     test.pskHash,
			}
			clientCalls := 0
			ca, cb := packetPipe()
			go func() {
				clientOpts := []dtls.ClientOption{
					dtls.WithPSK(func() ([]dtls.PSK, error) {
						clientCalls++

						return psks, nil
					}, nil),
					dtls.WithCipherSuites(test.cipherSuites...),
					dtls.WithMinVersion(test.minVersion),
					dtls.WithMaxVersion(test.maxVersion),
				}
				if test.keyShareRetry {
					clientOpts = append(
						clientOpts,
						dtls.WithClientHelloMessageHook(func(hello handshake.MessageClientHello) handshake.Message {
							for _, value := range hello.Extensions {
								if share, ok := value.(*extension13.ClientKeyShare); ok && len(share.Shares) > 1 {
									share.Shares = nil
								}
							}

							return &hello
						}),
					)
				}
				if test.pskOnly {
					clientOpts = append(
						clientOpts,
						dtls.WithClientHelloMessageHook(func(hello handshake.MessageClientHello) handshake.Message {
							hello.Extensions = slices.DeleteFunc(hello.Extensions, func(value extension.Value) bool {
								return value.ExtensionType() == extension.TypeKeyShare || value.ExtensionType() == extension.TypeSupportedGroups
							})
							for _, value := range hello.Extensions {
								if modes, ok := value.(*extension13.PSKKeyExchangeModes); ok {
									modes.Modes = []extension13.PSKKeyExchangeMode{extension13.PSKKE}
								}
							}

							return &hello
						}),
					)
				}
				if test.noCommonGroup {
					clientOpts = append(clientOpts, dtls.WithEllipticCurves(elliptic.X25519))
				}
				if test.ClientVerifyConnection != nil {
					clientOpts = append(clientOpts, dtls.WithVerifyConnection(test.ClientVerifyConnection))
				}

				c, err := testClient(ctx, ca, ca.RemoteAddr(), clientOpts, false)
				clientRes <- result{c, err}
			}()

			serverOpts := []dtls.ServerOption{
				dtls.WithInsecureSkipVerifyHello(test.skipRetry),
				dtls.WithPSK(nil, func(identities [][]byte) (*dtls.PSK, error) {
					for _, identity := range identities {
						if bytes.Equal(identity, test.ClientIdentity) {
							return &dtls.PSK{Identity: identity, Key: []byte{0xAB, 0xC1, 0x23}, Hash: test.pskHash}, nil
						}
					}

					return nil, errTestPSKInvalidIdentity
				}),
				dtls.WithCipherSuites(test.cipherSuites...),
				dtls.WithMinVersion(test.minVersion),
				dtls.WithMaxVersion(test.maxVersion),
			}
			if test.noCommonGroup {
				serverOpts = append(serverOpts, dtls.WithEllipticCurves(elliptic.P256))
			}
			if test.ServerVerifyConnection != nil {
				serverOpts = append(serverOpts, dtls.WithVerifyConnection(test.ServerVerifyConnection))
			}

			server, err := testServer(ctx, cb, cb.RemoteAddr(), serverOpts, false)
			if test.WantFail {
				res := <-clientRes
				assert.Error(t, err)
				assert.True(
					t,
					strings.Contains(err.Error(), test.ExpectedServerErr),
					"TestPSK: Server expected error mismatch",
				)
				assert.Error(t, res.err, "TestPSK: Client expected error mismatch")
				assert.True(
					t,
					strings.Contains(res.err.Error(), test.ExpectedClientErr),
					"TestPSK: Client expeected error mismatch",
				)

				return
			}
			assert.NoError(t, err)

			state, ok := server.ConnectionState()
			assert.True(t, ok, "TestPSK: Server ConnectionState failed")
			if test.wantSuite != 0 {
				assert.Equal(t, test.wantSuite, state.CipherSuiteID)
			}

			actualPSKIdentityHint := state.IdentityHint
			assert.Equal(t, test.ClientIdentity, actualPSKIdentityHint, "TestPSK: Server ClientPSKIdentity Mismatch")

			defer func() {
				_ = server.Close()
			}()

			res := <-clientRes
			assert.NoError(t, res.err)
			assert.Equal(t, 1, clientCalls)
			assertPionPayload(t, server, res.c, []byte("PSK application data"))
			assert.NoError(t, res.c.Close())
		})
	}
}

func TestPionV4ConnectionID(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	clientCID := []byte{5, 77, 33, 24, 93, 27, 45, 81}
	serverCID := []byte{64, 24, 73, 2, 17, 96, 38, 59}
	cidEcho := func(echo []byte) func() []byte {
		return func() []byte {
			return echo
		}
	}
	tests := map[string]struct {
		clientOpts         []dtls.ClientOption
		serverOpts         []dtls.ServerOption
		clientConnectionID []byte
		serverConnectionID []byte
	}{
		"BidirectionalConnectionIDs": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionID(
				cidEcho(clientCID),
				dtls.CIDPathMigrationReject,
			)},
			serverOpts: []dtls.ServerOption{dtls.WithConnectionID(
				cidEcho(serverCID),
				dtls.CIDPathMigrationReject,
			)},
			clientConnectionID: clientCID,
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyClientSends": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionID(cidEcho(nil), dtls.CIDPathMigrationReject)},
			serverOpts: []dtls.ServerOption{dtls.WithConnectionID(
				cidEcho(serverCID),
				dtls.CIDPathMigrationReject,
			)},
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyServerSends": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionID(
				cidEcho(clientCID),
				dtls.CIDPathMigrationReject,
			)},
			serverOpts:         []dtls.ServerOption{dtls.WithConnectionID(cidEcho(nil), dtls.CIDPathMigrationReject)},
			clientConnectionID: clientCID,
		},
		"ClientDoesNotSupport": {
			serverOpts: []dtls.ServerOption{dtls.WithConnectionID(cidEcho(serverCID), dtls.CIDPathMigrationReject)},
		},
		"ServerDoesNotSupport": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionID(cidEcho(clientCID), dtls.CIDPathMigrationReject)},
		},
		"NeitherSupport": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			type result struct {
				c   *dtls.Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, ca, ca.RemoteAddr(), tt.clientOpts, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, cb, cb.RemoteAddr(), tt.serverOpts, true)
			assert.NoError(t, err)

			res := <-c
			assert.NoError(t, res.err)
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()

			clientSaved := serializedSnapshot(t, connectionState(t, res.c))
			serverSaved := serializedSnapshot(t, connectionState(t, server))
			assert.Equal(t, tt.clientConnectionID, clientSaved.LocalConnectionID)
			assert.Equal(t, tt.serverConnectionID, clientSaved.RemoteConnectionID)
			assert.Equal(t, tt.serverConnectionID, serverSaved.LocalConnectionID)
			assert.Equal(t, tt.clientConnectionID, serverSaved.RemoteConnectionID)
			assert.False(t, clientSaved.RRCNegotiated)
			assert.False(t, serverSaved.RRCNegotiated)
			assertPionPayload(t, server, res.c, []byte("server CID data"))
			assertPionPayload(t, res.c, server, []byte("client CID data"))
		})
	}
}

func TestPionV4DTLS13HandshakeAndApplicationData(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(10 * time.Second).Stop()

	ca, cb := packetPipe()

	// Setup client
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	clientCID := []byte("client-cid")
	serverCID := []byte("server-cid")

	client, err := dtls.Client(
		ca,
		ca.RemoteAddr(),
		dtls.WithCertificates(clientCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithConnectionID(func() []byte { return clientCID }, dtls.CIDPathMigrationReject),
	)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	assert.False(t, ok)

	// Setup server
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	server, err := dtls.Server(
		cb,
		cb.RemoteAddr(),
		dtls.WithCertificates(serverCert),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithConnectionID(func() []byte { return serverCID }, dtls.CIDPathMigrationReject),
	)
	assert.NoError(t, err)
	defer func() {
		_ = server.Close()
	}()

	_, ok = server.ConnectionState()
	assert.False(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorChannel := make(chan error, 2)
	go func() {
		errorChannel <- client.HandshakeContext(ctx)
	}()
	go func() {
		errorChannel <- server.HandshakeContext(ctx)
	}()
	require.NoError(t, <-errorChannel)
	require.NoError(t, <-errorChannel)
	// CID negotiation is verified on the wire by TestPionV4ConnectionID.

	_, ok = client.ConnectionState()
	require.True(t, ok)
	serverState, ok := server.ConnectionState()
	require.True(t, ok)
	assert.Equal(t, clientCert.Certificate, serverState.PeerCertificates)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))

	clientPayload := []byte("client to server")
	n, err := client.Write(clientPayload)
	require.NoError(t, err)
	require.Equal(t, len(clientPayload), n)
	buf := make([]byte, 64)
	n, err = server.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, clientPayload, buf[:n])

	serverPayload := []byte("server to client")
	n, err = server.Write(serverPayload)
	require.NoError(t, err)
	require.Equal(t, len(serverPayload), n)
	n, err = client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, serverPayload, buf[:n])

	require.NoError(t, client.UpdateKeys(ctx, dtls.KeyUpdateOptions{RequestPeerUpdate: true}))
	updatedClientPayload := []byte("client to server after KeyUpdate")
	n, err = client.Write(updatedClientPayload)
	require.NoError(t, err)
	require.Equal(t, len(updatedClientPayload), n)
	n, err = server.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, updatedClientPayload, buf[:n])

	updatedServerPayload := []byte("server to client after KeyUpdate")
	n, err = server.Write(updatedServerPayload)
	require.NoError(t, err)
	require.Equal(t, len(updatedServerPayload), n)
	n, err = client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, updatedServerPayload, buf[:n])
}

func TestPionV4DTLS13HelloRetryRequestRetransmissionAndReordering(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(10 * time.Second).Stop()

	for _, testCase := range []struct {
		name          string
		impairNetwork func(*test.Bridge)
	}{
		{
			name: "RetransmitDroppedClientHello2",
			impairNetwork: func(br *test.Bridge) {
				br.DropNextNWrites(0, 1)
			},
		},
		{
			name: "ReorderClientHello2Retransmission",
			impairNetwork: func(br *test.Bridge) {
				br.ReorderNextNWrites(0, 2)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testDTLS13HelloRetryRequestNetworkRecovery(t, testCase.impairNetwork)
		})
	}
}

func testDTLS13HelloRetryRequestNetworkRecovery(
	t *testing.T,
	impairNetwork func(*test.Bridge),
) {
	t.Helper()

	const retryInterval = 20 * time.Millisecond
	curves := []elliptic.Curve{elliptic.X25519, elliptic.P256}
	br := test.NewBridge()

	var initialClientHellos, retryClientHellos, retryClientHelloWrites atomic.Int32
	clientTransport := &connWithCallback{
		packetTestConn: &packetTestConn{Conn: br.GetConn0(), remoteAddr: br.GetConn1().LocalAddr()},
		onWrite: func(raw []byte) {
			if datagramContainsHandshake(raw, handshake.TypeClientHello, 1) {
				if retryClientHelloWrites.Add(1) == 1 {
					impairNetwork(br)
				}
			}
		},
	}
	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	client, err := dtls.Client(
		clientTransport,
		clientTransport.RemoteAddr(),
		dtls.WithCertificates(clientCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithEllipticCurves(curves...),
		dtls.WithFlightInterval(retryInterval),
		dtls.WithDisableRetransmitBackoff(true),
		dtls.WithClientHelloMessageHook(func(clientHello handshake.MessageClientHello) handshake.Message {
			for i, ext := range clientHello.Extensions {
				keyShare, ok := ext.(*extension13.ClientKeyShare)
				if !ok {
					continue
				}

				if len(keyShare.Shares) == len(curves) {
					initialClientHellos.Add(1)
					extensions := clientHello.Extensions
					extensions[i] = &extension13.ClientKeyShare{}
					clientHello.Extensions = extensions
				} else {
					retryClientHellos.Add(1)
					require.Len(t, keyShare.Shares, 1)
					assert.Equal(t, elliptic.X25519, keyShare.Shares[0].Group)
				}
			}

			return &clientHello
		}),
	)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	server, err := dtls.Server(
		&packetTestConn{Conn: br.GetConn1(), remoteAddr: br.GetConn0().LocalAddr()},
		br.GetConn0().LocalAddr(),
		dtls.WithCertificates(serverCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithInsecureSkipVerifyHello(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithEllipticCurves(curves...),
		dtls.WithFlightInterval(retryInterval),
		dtls.WithDisableRetransmitBackoff(true),
	)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handshakeResults := make(chan error, 2)
	go func() { handshakeResults <- client.HandshakeContext(ctx) }()
	go func() { handshakeResults <- server.HandshakeContext(ctx) }()

	waitForBridgePacket(t, br, 0)
	deliverNextBridgePacket(t, br)
	waitForBridgePacket(t, br, 1)
	br.Tick()

	waitForBridgeHandshakes(t, ctx, br, handshakeResults)

	assert.Equal(t, protocol.Version1_3, connectionState(t, client).NegotiatedVersion())
	assert.Equal(t, protocol.Version1_3, connectionState(t, server).NegotiatedVersion())
	assert.GreaterOrEqual(t, initialClientHellos.Load(), int32(1))
	assert.GreaterOrEqual(t, retryClientHellos.Load(), int32(1))
	assert.GreaterOrEqual(t, retryClientHelloWrites.Load(), int32(2))

	assertDTLSApplicationDataOverBridge(t, br, client, server, []byte("client data after HRR retry"))
	assertDTLSApplicationDataOverBridge(t, br, server, client, []byte("server data after HRR retry"))
}

func TestPionV4EllipticCurveConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name            string
		ConfigCurves    []elliptic.Curve
		HandshakeCurves []elliptic.Curve
	}{
		{
			Name:            "Curve defaulting",
			ConfigCurves:    nil,
			HandshakeCurves: nil,
		},
		{
			Name:            "Single curve",
			ConfigCurves:    []elliptic.Curve{elliptic.X25519},
			HandshakeCurves: []elliptic.Curve{elliptic.X25519},
		},
		{
			Name:            "Multiple curves",
			ConfigCurves:    []elliptic.Curve{elliptic.P384, elliptic.X25519},
			HandshakeCurves: []elliptic.Curve{elliptic.P384, elliptic.X25519},
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := packetPipe()
		var advertised []elliptic.Curve
		type result struct {
			c   *dtls.Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			opts := []dtls.ClientOption{
				dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithClientHelloMessageHook(func(hello handshake.MessageClientHello) handshake.Message {
					for _, value := range hello.Extensions {
						if groups, ok := value.(*extension.SupportedGroups); ok {
							advertised = append([]elliptic.Curve(nil), groups.Groups...)
						}
					}

					return &hello
				}),
			}
			if len(test.ConfigCurves) > 0 {
				opts = append(opts, dtls.WithEllipticCurves(test.ConfigCurves...))
			}
			client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, true)
			resultCh <- result{client, err}
		}()

		opts := []dtls.ServerOption{dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
		if len(test.ConfigCurves) > 0 {
			opts = append(opts, dtls.WithEllipticCurves(test.ConfigCurves...))
		}
		server, err := testServer(ctx, cb, cb.RemoteAddr(), opts, true)
		assert.NoError(t, err)

		res := <-resultCh
		if len(test.ConfigCurves) != 0 {
			assert.Equal(t, test.ConfigCurves, advertised)
		} else {
			assert.NotEmpty(t, advertised)
		}
		assert.NoError(t, res.err, "Client error")

		defer func() {
			assert.NoError(t, server.Close())
			assert.NoError(t, res.c.Close())
		}()
	}
}

func TestPionV4ClientCertificateTypes(t *testing.T) {
	ecCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	rsaCert, err := selfsign.SelfSign(rsaKey)
	assert.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	edCert, err := selfsign.SelfSign(edKey)
	assert.NoError(t, err)
	for _, tc := range []struct {
		name  string
		types []clientcertificate.Type
		certs []tls.Certificate
		want  [][]byte
	}{
		{
			"RSA request with EC certificate",
			[]clientcertificate.Type{clientcertificate.RSASign},
			[]tls.Certificate{ecCert},
			nil,
		},
		{
			"EC request with RSA certificate",
			[]clientcertificate.Type{clientcertificate.ECDSASign},
			[]tls.Certificate{rsaCert},
			nil,
		},
		{
			"select matching certificate",
			[]clientcertificate.Type{clientcertificate.RSASign},
			[]tls.Certificate{ecCert, rsaCert},
			rsaCert.Certificate,
		},
		{
			"matching EC certificate",
			[]clientcertificate.Type{clientcertificate.ECDSASign},
			[]tls.Certificate{ecCert},
			ecCert.Certificate,
		},
		{
			"matching Ed25519 certificate",
			[]clientcertificate.Type{clientcertificate.ECDSASign},
			[]tls.Certificate{edCert},
			edCert.Certificate,
		},
		{
			"RSA request with Ed25519 certificate",
			[]clientcertificate.Type{clientcertificate.RSASign},
			[]tls.Certificate{edCert},
			nil,
		},
		{"unknown certificate type", []clientcertificate.Type{255}, []tls.Certificate{ecCert}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, callback := range []bool{false, true} {
				clientOpts := []dtls.ClientOption{
					dtls.WithInsecureSkipVerify(true),
					dtls.WithMaxVersion(protocol.Version1_2),
					dtls.WithCertificates(tc.certs...),
				}
				if callback {
					clientOpts = append(
						clientOpts,
						dtls.WithGetClientCertificate(func(info *dtls.CertificateRequestInfo) (
							*tls.Certificate,
							error,
						) {
							assert.NotNil(t, info.CertificateTypes)
							for i := range tc.certs {
								if info.SupportsCertificate(&tc.certs[i]) == nil {
									return &tc.certs[i], nil
								}
							}

							return &tls.Certificate{}, nil
						}),
					)
				}
				client, server := handshakePair(t, clientOpts, []dtls.ServerOption{
					dtls.WithCertificates(ecCert),
					dtls.WithMaxVersion(protocol.Version1_2),
					dtls.WithClientAuth(dtls.RequestClientCert),
					dtls.WithCertificateRequestMessageHook(func(req handshake.MessageCertificateRequest) handshake.Message {
						req.CertificateTypes = tc.types

						return &req
					}),
				})
				assert.NoError(t, client.configErr)
				assert.NoError(t, server.configErr)
				assert.NoError(t, client.handshakeError)
				assert.NoError(t, server.handshakeError)
				state, ok := server.conn.ConnectionState()
				assert.True(t, ok)
				assert.Equal(t, tc.want, state.PeerCertificates)
			}
		})
	}
}

func TestPionV4SupportedGroups(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	supportedGroups := elliptic.Curves()
	require.Contains(t, supportedGroups, elliptic.X25519MLKEM768)
	expectedGroups := make([]elliptic.Curve, 0, len(supportedGroups))
	for group := range supportedGroups {
		expectedGroups = append(expectedGroups, group)
	}
	slices.Sort(expectedGroups)
	slices.Reverse(expectedGroups)

	type result struct {
		conn *dtls.Conn
		err  error
	}
	clientResult := make(chan result, 1)
	var advertised []elliptic.Curve
	ca, cb := packetPipe()

	go func() {
		client, err := testClient(
			ctx,
			ca,
			ca.RemoteAddr(),
			[]dtls.ClientOption{
				dtls.WithCipherSuites(cryptosuite.TLS_AES_128_GCM_SHA256),
				dtls.WithEllipticCurves(expectedGroups...),
				dtls.WithClientHelloMessageHook(func(hello handshake.MessageClientHello) handshake.Message {
					for _, value := range hello.Extensions {
						if groups, ok := value.(*extension.SupportedGroups); ok {
							advertised = append([]elliptic.Curve(nil), groups.Groups...)
						}
					}

					return &hello
				}),
				dtls.WithMinVersion(protocol.Version1_3),
				dtls.WithMaxVersion(protocol.Version1_3),
			},
			false,
		)
		clientResult <- result{conn: client, err: err}
	}()

	server, err := testServer(
		ctx,
		cb,
		cb.RemoteAddr(),
		[]dtls.ServerOption{
			dtls.WithCipherSuites(cryptosuite.TLS_AES_128_GCM_SHA256),
			dtls.WithMinVersion(protocol.Version1_3),
			dtls.WithMaxVersion(protocol.Version1_3),
		},
		true,
	)
	client := <-clientResult
	defer func() {
		if server != nil {
			assert.NoError(t, server.Close())
		}
		if client.conn != nil {
			assert.NoError(t, client.conn.Close())
		}
	}()

	require.NoError(t, err)
	require.NoError(t, client.err)
	require.Equal(t, expectedGroups, advertised, "groups in supported_groups mismatch")
}

func TestPionV4DualStackVersionNegotiationSendsClassifiedAlerts(t *testing.T) {
	t.Run("server rejects illegal ClientHello extensions", func(t *testing.T) {
		ca, cb := packetPipe()
		defer func() {
			_ = ca.Close()
			_ = cb.Close()
		}()

		certificate, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		server, err := dtls.Server(
			cb,
			cb.RemoteAddr(),
			dtls.WithCertificates(certificate),
			dtls.WithMinVersion(protocol.Version1_2),
			dtls.WithMaxVersion(protocol.Version1_3),
		)
		require.NoError(t, err)
		defer func() { _ = server.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- server.HandshakeContext(ctx) }()

		raw := marshalVersionNegotiationRecord(t, &handshake.MessageClientHello{
			Version:            protocol.Version1_2,
			CipherSuiteIDs:     []uint16{uint16(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
			CompressionMethods: []*protocol.CompressionMethod{protocol.CompressionMethods()[0]},
			Extensions: []extension.Value{
				extension.Raw{Type: 0xfefe},
				extension.Raw{Type: 0xfefe},
			},
		})
		_, err = ca.Write(raw)
		require.NoError(t, err)

		assert.Equal(t, alert.IllegalParameter, readVersionNegotiationAlert(t, ca))
		assertInteropError(t, <-result, expectedTextError("duplicate extension"))
	})

	t.Run("client rejects unexpected response", func(t *testing.T) {
		ca, cb := packetPipe()
		defer func() {
			_ = ca.Close()
			_ = cb.Close()
		}()

		client, err := dtls.Client(
			cb,
			cb.RemoteAddr(),
			dtls.WithInsecureSkipVerify(true),
			dtls.WithMinVersion(protocol.Version1_2),
			dtls.WithMaxVersion(protocol.Version1_3),
		)
		require.NoError(t, err)
		defer func() { _ = client.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- client.HandshakeContext(ctx) }()

		require.NoError(t, ca.SetReadDeadline(time.Now().Add(time.Second)))
		_, err = ca.Read(make([]byte, 8192)) // Initial ClientHello.
		require.NoError(t, err)
		_, err = ca.Write(marshalVersionNegotiationRecord(t, &handshake.MessageFinished{VerifyData: []byte{0x01}}))
		require.NoError(t, err)

		assert.Equal(t, alert.UnexpectedMessage, readVersionNegotiationAlert(t, ca))
		assertInteropError(t, <-result, expectedTextError("unexpected handshake message"))
	})
}

func marshalVersionNegotiationRecord(t *testing.T, message handshake.Message) []byte {
	t.Helper()

	raw, err := marshalTestRecord(recordlayer.RecordConfig{Version: protocol.Version1_2}, &handshake.Handshake{
		Message: message,
	})
	require.NoError(t, err)

	return raw
}

func readVersionNegotiationAlert(t *testing.T, conn net.Conn) alert.Description {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	for {
		raw := make([]byte, 8192)
		n, err := conn.Read(raw)
		require.NoError(t, err)
		records, err := recordlayer.UnpackDatagram(raw[:n], recordlayer.UnpackDatagramConfig{})
		require.NoError(t, err)
		for _, rawRecord := range records {
			header, parseErr := recordlayer.ParseRecord(rawRecord, 0)
			require.NoError(t, parseErr)
			if header.ContentType() != protocol.ContentTypeAlert {
				continue
			}

			var dtlsAlert alert.Alert
			require.NoError(t, dtlsAlert.Unmarshal(rawRecord[len(header.HeaderBytes()):]))

			return dtlsAlert.Description
		}
	}
}

func TestPionV4HandshakeDiscardsProtectedRecordWithoutRequiredCID(t *testing.T) { //nolint:cyclop
	lim := test.TimeOut(20 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	tests := []struct {
		name    string
		version protocol.Version
	}{
		{name: "DTLS12", version: protocol.Version1_2},
		{name: "DTLS13", version: protocol.Version1_3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			clientCID := []byte("client-cid")
			serverCID := []byte("server-cid")

			type result struct {
				c   *dtls.Conn
				err error
			}
			clientResult := make(chan result, 1)
			injectionResult := make(chan error, 1)
			ca, cb := packetPipe()
			clientTransport := &connWithCallback{packetTestConn: ca}

			var injected atomic.Bool
			clientTransport.onWrite = func(datagram []byte) {
				records, _ := recordlayer.UnpackDatagram(
					datagram,
					recordlayer.UnpackDatagramConfig{TargetVersion: tt.version, CIDLength: len(serverCID)},
				)
				for _, record := range records {
					contentType := protocol.ContentType(record[0])
					hasCID := contentType == protocol.ContentTypeConnectionID ||
						protocol.IsDTLS13Ciphertext(contentType) && record[0]&0x10 != 0
					if !hasCID || !injected.CompareAndSwap(
						false,
						true,
					) {
						continue
					}

					var invalidRecord []byte
					if tt.version == protocol.Version1_3 {
						invalidRecord = append(invalidRecord, record[0]&^0x10)
						invalidRecord = append(invalidRecord, record[1+len(serverCID):]...)
					} else {
						invalidRecord = append(invalidRecord, byte(protocol.ContentTypeHandshake))
						invalidRecord = append(invalidRecord, record[1:11]...)
						invalidRecord = append(invalidRecord, record[11+len(serverCID):]...)
					}

					strictRecords, strictErr := recordlayer.UnpackDatagram(
						invalidRecord,
						recordlayer.UnpackDatagramConfig{
							TargetVersion: tt.version,
							CIDLength:     len(serverCID),
							CIDRequired:   true,
						},
					)
					if len(strictRecords) != 0 || !errorTreeContains(strictErr, "invalid dtls ciphertext header") {
						injectionResult <- fmt.Errorf(
							"CID-less clone was not rejected by strict scanner: records=%d, err=%w",
							len(strictRecords),
							strictErr,
						)

						return
					}

					_, err := ca.Write(invalidRecord)
					injectionResult <- err

					return
				}
			}

			go func() {
				client, err := testClient(
					ctx,
					clientTransport,
					clientTransport.RemoteAddr(),
					[]dtls.ClientOption{
						dtls.WithMinVersion(tt.version),
						dtls.WithMaxVersion(tt.version),
						dtls.WithConnectionID(
							func() []byte { return bytes.Clone(clientCID) },
							dtls.CIDPathMigrationReject,
						),
					},
					true,
				)
				clientResult <- result{client, err}
			}()

			server, serverErr := testServer(
				ctx,
				cb,
				cb.RemoteAddr(),
				[]dtls.ServerOption{
					dtls.WithMinVersion(tt.version),
					dtls.WithMaxVersion(tt.version),
					dtls.WithConnectionID(func() []byte { return bytes.Clone(serverCID) }, dtls.CIDPathMigrationReject),
				},
				true,
			)
			client := <-clientResult

			defer func() {
				if server != nil {
					assert.NoError(t, server.Close())
				}
				if client.c != nil {
					assert.NoError(t, client.c.Close())
				}
			}()

			require.NoError(t, serverErr)
			require.NoError(t, client.err)
			require.True(t, injected.Load(), "handshake did not send a CID-bearing protected record")
			require.NoError(t, <-injectionResult)

			payload := []byte("connection survived CID-less protected record")
			n, err := client.c.Write(payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
			readBuffer := make([]byte, len(payload))
			n, err = server.Read(readBuffer)
			require.NoError(t, err)
			require.Equal(t, payload, readBuffer[:n])
		})
	}
}
