// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop && !js

package pionv3

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

func TestPionV3ContextConfig(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err)

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
						conn, err := dtls.DialWithOptions("udp", addr, clientOpts...)
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
						conn, err := dtls.ClientWithOptions(ca, ca.RemoteAddr(), clientOpts...)
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
						conn, err := dtls.ServerWithOptions(ca, ca.RemoteAddr(), serverOpts...)
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
					ok:          errors.As(err, &netError) && netError.Temporary(),
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
