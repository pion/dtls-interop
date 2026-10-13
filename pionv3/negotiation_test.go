// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"

	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

func TestPionV3PSK(t *testing.T) { testPSK12(t) }

func TestPionV3ConnectionID(t *testing.T) {
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
			clientOpts: []dtls.ClientOption{dtls.WithConnectionIDGenerator(
				cidEcho(clientCID),
			)},
			serverOpts: []dtls.ServerOption{dtls.WithConnectionIDGenerator(
				cidEcho(serverCID),
			)},
			clientConnectionID: clientCID,
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyClientSends": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionIDGenerator(cidEcho(nil))},
			serverOpts: []dtls.ServerOption{dtls.WithConnectionIDGenerator(
				cidEcho(serverCID),
			)},
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyServerSends": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionIDGenerator(
				cidEcho(clientCID),
			)},
			serverOpts:         []dtls.ServerOption{dtls.WithConnectionIDGenerator(cidEcho(nil))},
			clientConnectionID: clientCID,
		},
		"ClientDoesNotSupport": {
			serverOpts: []dtls.ServerOption{dtls.WithConnectionIDGenerator(cidEcho(serverCID))},
		},
		"ServerDoesNotSupport": {
			clientOpts: []dtls.ClientOption{dtls.WithConnectionIDGenerator(cidEcho(clientCID))},
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

func TestPionV3EllipticCurveConfiguration(t *testing.T) {
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
				dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithClientHelloMessageHook(func(hello handshake.MessageClientHello) handshake.Message {
					for _, value := range hello.Extensions {
						if groups, ok := value.(*extension.SupportedEllipticCurves); ok {
							advertised = append([]elliptic.Curve(nil), groups.EllipticCurves...)
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

		opts := []dtls.ServerOption{dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
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
