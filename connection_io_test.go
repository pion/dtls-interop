// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop && !js

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestPionV4ContextConfig(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err)

	// Dummy listener
	listen, err := net.ListenUDP("udp", addrListen)
	assert.NoError(t, err)
	defer func() {
		_ = listen.Close()
	}()
	addr, ok := listen.LocalAddr().(*net.UDPAddr)
	assert.True(t, ok)

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(cert),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(cert),
	}

	dials := map[string]struct {
		f func() (func() (net.Conn, error), func())
	}{
		"Dial": {
			f: func() (func() (net.Conn, error), func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := dtls.Dial("udp", addr, clientOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						cancel()
					}
			},
		},
		"Client": {
			f: func() (func() (net.Conn, error), func()) {
				ca, _ := packetPipe()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := dtls.Client(ca, ca.RemoteAddr(), clientOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						_ = ca.Close()
						cancel()
					}
			},
		},
		"Server": {
			f: func() (func() (net.Conn, error), func()) {
				ca, _ := packetPipe()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := dtls.Server(ca, ca.RemoteAddr(), serverOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						_ = ca.Close()
						cancel()
					}
			},
		},
	}

	type dialResult struct {
		err         error
		ok          bool
		completedAt time.Time
	}

	for name, dial := range dials {
		t.Run(name, func(t *testing.T) {
			done := make(chan dialResult, 1)
			startedAt := time.Now()

			go func() {
				d, cancel := dial.f()
				conn, err := d()
				defer cancel()
				var netError net.Error
				if err == nil {
					_ = conn.Close()
				}

				done <- dialResult{
					err:         err,
					ok:          errors.As(err, &netError) && netError.Temporary(), //nolint:staticcheck
					completedAt: time.Now(),
				}
			}()

			const earlyCancelWindow = 20 * time.Millisecond
			time.Sleep(earlyCancelWindow)

			assertResult := func(result dialResult) {
				assert.GreaterOrEqual(
					t,
					result.completedAt.Sub(startedAt),
					earlyCancelWindow,
					"Invalid cancel timing",
				)
				if !result.ok {
					assert.Fail(t, "Dial failed with unexpected error", "err: %v", result.err)
				}
			}

			select {
			case result := <-done:
				assertResult(result)

				return
			default:
			}

			select {
			case result := <-done:
				assertResult(result)
			case <-time.After(time.Second):
				assert.Fail(t, "Dial did not finish after context cancellation")
			}
		})
	}
}

const nettestBasicIOCloseDelay = 50 * time.Millisecond

func TestPionV4NetTest(t *testing.T) {
	lim := test.TimeOut(time.Minute*1 + time.Second*10)
	defer lim.Stop()

	var makePipeCalls atomic.Int32

	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		c1, c2, err = pipeMemory()
		if err != nil {
			return nil, nil, nil, err
		}

		if makePipeCalls.Add(1) == 1 {
			c1 = &delayedCloseConn{Conn: c1, delay: nettestBasicIOCloseDelay}
			c2 = &delayedCloseConn{Conn: c2, delay: nettestBasicIOCloseDelay}
		}

		var stopOnce sync.Once
		stop = func() {
			stopOnce.Do(func() {
				_ = c1.Close()
				_ = c2.Close()
			})
		}

		return c1, c2, stop, nil
	})
}

type delayedCloseConn struct {
	net.Conn
	delay time.Duration

	closeOnce sync.Once
	closeErr  error
}

func (c *delayedCloseConn) Close() error {
	c.closeOnce.Do(func() {
		time.Sleep(c.delay)
		c.closeErr = c.Conn.Close()
	})

	return c.closeErr
}

// Hold the challenge on the new path until the old address has been checked.
// Releasing it lets the real client authenticate and answer it without exposing
// either endpoint's traffic keys or constructing protected records in the test.
func TestPionV4ListenConnectionIDRebindingRequiresRRC(t *testing.T) {
	for name, versions := range map[string][3]protocol.Version{
		"DTLS12":            {protocol.Version1_2, protocol.Version1_2, protocol.Version1_2},
		"DualStackToDTLS12": {protocol.Version1_3, protocol.Version1_2, protocol.Version1_2},
		"DTLS13":            {protocol.Version1_3, protocol.Version1_3, protocol.Version1_3},
	} {
		t.Run(name, func(t *testing.T) {
			cert, err := selfsign.GenerateSelfSigned()
			require.NoError(t, err)
			listener, err := dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
				dtls.WithCertificates(cert), dtls.WithMinVersion(versions[2]), dtls.WithMaxVersion(versions[1]),
				dtls.WithConnectionID(dtls.RandomCIDGenerator(8), dtls.CIDPathMigrationRRC))
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			pair := startCIDListenerPair(t, listener, dtls.WithInsecureSkipVerify(true),
				dtls.WithMinVersion(versions[2]), dtls.WithMaxVersion(versions[0]),
				dtls.WithConnectionID(dtls.RandomCIDGenerator(8), dtls.CIDPathMigrationRRC))
			require.NoError(t, <-pair.clientDone)
			require.NoError(t, <-pair.serverDone)
			require.Equal(t, versions[2], connectionState(t, pair.client).NegotiatedVersion())
			require.Equal(t, versions[2], connectionState(t, pair.server).NegotiatedVersion())
			oldAddr := pair.server.RemoteAddr().String()
			gate := make(chan struct{})
			pair.proxy.replyGate.Store(&gate)
			pair.proxy.rebindPath()
			assertPionPayload(t, pair.client, pair.server, []byte("rebound"))
			select {
			case <-pair.proxy.replyBlocked:
			case <-time.After(time.Second):
				require.FailNow(t, "no challenge sent to the rebound path")
			}
			require.Equal(t, oldAddr, pair.server.RemoteAddr().String())
			close(gate)
			pair.proxy.replyGate.Store(nil)
			require.Eventually(
				t,
				func() bool { return pair.server.RemoteAddr().String() == pair.proxy.rebound.LocalAddr().String() },
				time.Second,
				time.Millisecond,
			)
			assertPionPayload(t, pair.client, pair.server, []byte("validated"))
			assertPionPayload(t, pair.server, pair.client, []byte("new path"))
			require.NoError(t, pair.proxy.err())
		})
	}
}
