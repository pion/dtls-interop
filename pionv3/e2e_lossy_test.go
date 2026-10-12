// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"

	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	transportTest "github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	flightInterval   = time.Millisecond * 100
	lossyTestTimeout = 30 * time.Second
)

type bridgePacketConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *bridgePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)

	return n, c.remoteAddr, err
}

func (c *bridgePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

func TestPionV3E2ELossy(t *testing.T) {
	report := transportTest.CheckRoutines(t)
	defer report()

	type runResult struct {
		dtlsConn *dtls.Conn
		err      error
	}

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	for _, test := range []struct {
		LossChanceRange             int
		DoClientAuth                bool
		CipherSuites                []dtls.CipherSuiteID
		MTU                         int
		DisableServerFlightInterval bool
	}{
		{
			LossChanceRange: 0,
		},
		{
			LossChanceRange: 10,
		},
		{
			LossChanceRange: 20,
		},
		{
			LossChanceRange: 50,
		},
		{
			LossChanceRange: 0,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 10,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 20,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 50,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 0,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 10,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 20,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 50,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 10,
			MTU:             100,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 20,
			MTU:             100,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 50,
			MTU:             100,
			DoClientAuth:    true,
		},

		{
			LossChanceRange:             10,
			DisableServerFlightInterval: true,
		},
		{
			LossChanceRange:             20,
			DisableServerFlightInterval: true,
		},
		{
			LossChanceRange:             50,
			DisableServerFlightInterval: true,
		},
	} {
		var name strings.Builder
		fmt.Fprintf(&name, "Loss%d_MTU%d", test.LossChanceRange, test.MTU)
		if test.DoClientAuth {
			name.WriteString("_WithCliAuth")
		}
		for _, ciph := range test.CipherSuites {
			name.WriteString("_With" + ciph.String())
		}
		if test.DisableServerFlightInterval {
			name.WriteString("_WithNoServerFlightInterval")
		}

		test := test
		t.Run(name.String(), func(t *testing.T) {
			lim := transportTest.TimeOut(lossyTestTimeout + time.Second)
			defer lim.Stop()

			chosenLoss := test.LossChanceRange
			ctx, cancel := context.WithTimeout(t.Context(), lossyTestTimeout)
			defer cancel()
			serverDone := make(chan runResult)
			clientDone := make(chan runResult)
			br := transportTest.NewBridge()
			clientTransport := &bridgePacketConn{Conn: br.GetConn0(), remoteAddr: br.GetConn1().LocalAddr()}
			serverTransport := &bridgePacketConn{Conn: br.GetConn1(), remoteAddr: br.GetConn0().LocalAddr()}

			var lossEnabled atomic.Bool
			lossEnabled.Store(true)
			filter := func([]byte) bool {
				return !lossEnabled.Load() || rand.IntN(100) >= chosenLoss
			}
			br.Filter(0, filter)
			br.Filter(1, filter)

			go func() {
				clientOpts := []dtls.ClientOption{
					dtls.WithFlightInterval(flightInterval),
					dtls.WithInsecureSkipVerify(true),
					dtls.WithDisableRetransmitBackoff(true),
				}
				if len(test.CipherSuites) > 0 {
					clientOpts = append(clientOpts, dtls.WithCipherSuites(test.CipherSuites...))
				}
				if test.MTU > 0 {
					clientOpts = append(clientOpts, dtls.WithMTU(test.MTU))
				}

				if test.DoClientAuth {
					clientOpts = append(clientOpts, dtls.WithCertificates(clientCert))
				}

				client, startupErr := dtls.ClientWithOptions(clientTransport, clientTransport.remoteAddr, clientOpts...)
				if startupErr == nil {
					startupErr = client.HandshakeContext(ctx)
				}
				clientDone <- runResult{client, startupErr}
			}()

			go func() {
				serverOpts := []dtls.ServerOption{
					dtls.WithCertificates(serverCert),
					dtls.WithFlightInterval(flightInterval),
					dtls.WithDisableRetransmitBackoff(true),
				}
				if len(test.CipherSuites) > 0 {
					serverOpts = append(serverOpts, dtls.WithCipherSuites(test.CipherSuites...))
				}
				if test.MTU > 0 {
					serverOpts = append(serverOpts, dtls.WithMTU(test.MTU))
				}

				if test.DoClientAuth {
					serverOpts = append(serverOpts, dtls.WithClientAuth(dtls.RequireAnyClientCert))
				}

				if test.DisableServerFlightInterval {
					serverOpts = append(serverOpts, dtls.WithFlightInterval(time.Hour))
				}

				server, startupErr := dtls.ServerWithOptions(serverTransport, serverTransport.remoteAddr, serverOpts...)
				if startupErr == nil {
					startupErr = server.HandshakeContext(ctx)
				}
				serverDone <- runResult{server, startupErr}
			}()

			testTimer := time.NewTimer(lossyTestTimeout)
			defer testTimer.Stop()
			var serverConn, clientConn *dtls.Conn
			type readResult struct {
				payload []byte
				err     error
			}
			clientRead := make(chan readResult, 1)
			serverRead := make(chan readResult, 1)
			var readers sync.WaitGroup
			startRead := func(conn *dtls.Conn, size int, results chan<- readResult) {
				// Read drives responses to retransmitted final flights after Handshake returns.
				readers.Add(1)
				go func() {
					defer readers.Done()
					payload := make([]byte, size)
					_, err := io.ReadFull(conn, payload)
					results <- readResult{payload: payload, err: err}
				}()
			}
			const clientPayload = "after loss"
			const serverPayload = "reply after loss"
			defer func() {
				// Join both handshakes even when the case times out.
				cancel()
				if serverDone != nil {
					serverConn = (<-serverDone).dtlsConn
				}
				if clientDone != nil {
					clientConn = (<-clientDone).dtlsConn
				}
				if serverConn != nil {
					assert.NoError(t, serverConn.Close())
				}
				if clientConn != nil {
					assert.NoError(t, clientConn.Close())
				}
				readers.Wait()
			}()

			for serverConn == nil || clientConn == nil {
				br.Tick()
				select {
				case serverResult := <-serverDone:
					serverDone = nil
					serverConn = serverResult.dtlsConn
					if serverResult.err != nil {
						assert.Failf(
							t,
							"Fail, serverError",
							"clientComplete(%t) serverComplete(%t) LossChance(%d) error(%v)",
							clientConn != nil,
							serverConn != nil,
							chosenLoss,
							serverResult.err,
						)

						return
					}
					startRead(serverConn, len(clientPayload), serverRead)
				case clientResult := <-clientDone:
					clientDone = nil
					clientConn = clientResult.dtlsConn
					if clientResult.err != nil {
						assert.Failf(
							t,
							"Fail, clientError",
							"clientComplete(%t) serverComplete(%t) LossChance(%d) error(%v)",
							clientConn != nil,
							serverConn != nil,
							chosenLoss,
							clientResult.err,
						)

						return
					}
					startRead(clientConn, len(serverPayload), clientRead)
				case <-testTimer.C:
					assert.Failf(
						t,
						"Test expired",
						"clientComplete(%t) serverComplete(%t) LossChance(%d)",
						clientConn != nil,
						serverConn != nil,
						chosenLoss,
					)

					return
				case <-time.After(10 * time.Millisecond):
				}
			}
			lossEnabled.Store(false)
			_, err := clientConn.Write([]byte(clientPayload))
			require.NoError(t, err)
			_, err = serverConn.Write([]byte(serverPayload))
			require.NoError(t, err)
			for clientRead != nil || serverRead != nil {
				br.Tick()
				select {
				case result := <-clientRead:
					require.NoError(t, result.err)
					require.Equal(t, serverPayload, string(result.payload))
					clientRead = nil
				case result := <-serverRead:
					require.NoError(t, result.err)
					require.Equal(t, clientPayload, string(result.payload))
					serverRead = nil
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
		})
	}
}
