// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func parseRecord(raw []byte, _ int) (recordlayer.Header, error) {
	var header recordlayer.Header
	err := header.Unmarshal(raw)
	return header, err
}

type psk struct{ Identity, Key []byte }
type pskClientCallback func() ([]psk, error)
type pskServerCallback func([][]byte) (*psk, error)

func withPSK(client pskClientCallback, server pskServerCallback) dtls.Option {
	return dtls.WithPSK(func(hint []byte) ([]byte, error) {
		if client != nil {
			keys, err := client()
			if err != nil {
				return nil, err
			}
			return keys[0].Key, nil
		}
		key, err := server([][]byte{hint})
		if err != nil {
			return nil, err
		}
		return key.Key, nil
	})
}

// V3 accepts one key and an identity hint rather than v4's list of PSKs.
func testPSK12(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		identity                   []byte
		suite                      dtls.CipherSuiteID
		clientVerify, serverVerify func(*dtls.State) error
	}{
		{name: "DTLS 1.2", identity: []byte("Client Identity"), suite: dtls.TLS_PSK_WITH_AES_128_CCM_8},
		{name: "TLS_PSK_WITH_AES_128_CBC_SHA256", identity: []byte("Client Identity"), suite: dtls.TLS_PSK_WITH_AES_128_CBC_SHA256},
		{name: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", identity: []byte("Client Identity"), suite: dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256},
		{name: "Client identity empty", identity: []byte{}, suite: dtls.TLS_PSK_WITH_AES_128_CCM_8},
		{name: "Server verify connection fails", identity: []byte("Client Identity"), suite: dtls.TLS_PSK_WITH_AES_128_CCM_8, serverVerify: func(*dtls.State) error { return errExample }},
		{name: "Client verify connection fails", identity: []byte("Client Identity"), suite: dtls.TLS_PSK_WITH_AES_128_CCM_8, clientVerify: func(*dtls.State) error { return errExample }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			ca, cb := packetPipe()
			defer ca.Close()
			defer cb.Close()
			key := []byte{0xAB, 0xC1, 0x23}
			// Config preserves an empty, non-nil identity; WithPSKIdentityHint copies it to nil in v3.
			client, err := dtls.Client(ca, ca.RemoteAddr(), &dtls.Config{
				PSK: func([]byte) ([]byte, error) { return key, nil }, PSKIdentityHint: tc.identity,
				CipherSuites: []dtls.CipherSuiteID{tc.suite}, VerifyConnection: tc.clientVerify,
			})
			require.NoError(t, err)
			defer client.Close()
			var got []byte
			server, err := dtls.ServerWithOptions(cb, cb.RemoteAddr(),
				dtls.WithPSK(func(hint []byte) ([]byte, error) { got = hint; return key, nil }),
				dtls.WithCipherSuites(tc.suite), dtls.WithVerifyConnection(func(state *dtls.State) error {
					if tc.serverVerify != nil {
						return tc.serverVerify(state)
					}
					return nil
				}),
			)
			require.NoError(t, err)
			defer server.Close()
			clientErr := make(chan error, 1)
			go func() { clientErr <- client.HandshakeContext(ctx) }()
			serverErr := server.HandshakeContext(ctx)
			err = <-clientErr
			if tc.clientVerify != nil {
				require.ErrorContains(t, err, errExample.Error())
				require.ErrorContains(t, serverErr, "BadCertificate")
				return
			}
			if tc.serverVerify != nil {
				require.ErrorContains(t, serverErr, errExample.Error())
				require.ErrorContains(t, err, "BadCertificate")
				return
			}
			require.NoError(t, serverErr)
			require.NoError(t, err)
			require.Equal(t, tc.identity, got)
			assertPionPayload(t, server, client, []byte("PSK application data"))
		})
	}
}
