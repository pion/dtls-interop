// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPionV4SessionResume(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("resumed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *dtls.Conn
			err error
		}
		clientRes := make(chan result, 1)

		ss := &memSessStore{}

		id, _ := hex.DecodeString("9b9fc92255634d9fb109febed42166717bb8ded8c738ba71bc7f2a0d9dae0306")
		secret, _ := hex.DecodeString("2e942a37aca5241deb2295b5fcedac221c7078d2503d2b62aeb4" +
			"8c880d7da73c001238b708559686b9da6e829c05ead7")
		clientCID := []byte{0xc1}
		serverCID := []byte{0x51}

		s := dtls.Session{ID: id, Secret: secret}

		ca, cb := packetPipe()

		_ = ss.Set(id, s)
		_ = ss.Set([]byte(ca.RemoteAddr().String()+"_example.com"), s)

		go func() {
			opts := []dtls.ClientOption{
				dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithServerName("example.com"),
				dtls.WithSessionStore(ss),
				dtls.WithConnectionID(func() []byte { return clientCID }, dtls.CIDPathMigrationReject),
				dtls.WithMTU(100),
			}
			c, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false)
			clientRes <- result{c, err}
		}()

		opts := []dtls.ServerOption{
			dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			dtls.WithServerName("example.com"),
			dtls.WithSessionStore(ss),
			dtls.WithConnectionID(func() []byte { return serverCID }, dtls.CIDPathMigrationReject),
			dtls.WithMTU(100),
		}
		server, err := testServer(ctx, cb, cb.RemoteAddr(), opts, true)
		assert.NoError(t, err)

		state, ok := server.ConnectionState()
		assert.True(t, ok)

		actualSessionID := state.SessionID
		actualMasterSecret := serializedSnapshot(t, &state).MasterSecret
		assert.Equal(t, actualSessionID, id, "TestSessionResumption SessionID mismatch")
		assert.Equal(t, actualMasterSecret, secret, "TestSessionResumption masterSecret mismatch")
		serverCommon := serializedSnapshot(t, &state)
		assert.Equal(t, serverCID, serverCommon.LocalConnectionID)
		assert.Equal(t, clientCID, serverCommon.RemoteConnectionID)

		defer func() {
			assert.NoError(t, server.Close())
		}()

		res := <-clientRes
		assert.NoError(t, res.err)
		clientCommon := serializedSnapshot(t, connectionState(t, res.c))
		assert.Equal(t, clientCID, clientCommon.LocalConnectionID)
		assert.Equal(t, serverCID, clientCommon.RemoteConnectionID)
		assert.NoError(t, res.c.Close())
	})

	t.Run("new session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *dtls.Conn
			err error
		}
		clientRes := make(chan result, 1)

		s1 := &memSessStore{}
		s2 := &memSessStore{}

		ca, cb := packetPipe()
		go func() {
			opts := []dtls.ClientOption{
				dtls.WithServerName("example.com"),
				dtls.WithSessionStore(s1),
			}
			c, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false)
			clientRes <- result{c, err}
		}()

		server, err := testServer(ctx, cb, cb.RemoteAddr(), []dtls.ServerOption{dtls.WithSessionStore(s2)}, true)
		assert.NoError(t, err)

		state, ok := server.ConnectionState()
		assert.True(t, ok)
		actualSessionID := state.SessionID
		actualMasterSecret := serializedSnapshot(t, &state).MasterSecret
		ss, _ := s2.Get(actualSessionID)
		assert.Equal(t, actualMasterSecret, ss.Secret, "TestSessionResumption masterSecret mismatch")

		defer func() {
			assert.NoError(t, server.Close())
		}()

		res := <-clientRes
		assert.NoError(t, res.err)

		cs, _ := s1.Get([]byte(ca.RemoteAddr().String() + "_example.com"))
		assert.Equal(t, actualMasterSecret, cs.Secret, "TestSessionResumption mismatch")
		assert.NoError(t, res.c.Close())
	})
}

type memSessStore struct {
	sync.Map
}

func (ms *memSessStore) Set(key []byte, s dtls.Session) error {
	k := hex.EncodeToString(key)
	ms.Store(k, s)

	return nil
}

func (ms *memSessStore) Get(key []byte) (dtls.Session, error) {
	k := hex.EncodeToString(key)

	v, ok := ms.Load(k)
	if !ok {
		return dtls.Session{}, nil
	}

	s, ok := v.(dtls.Session)
	if !ok {
		return dtls.Session{}, nil
	}

	return s, nil
}

func (ms *memSessStore) Del(key []byte) error {
	k := hex.EncodeToString(key)
	ms.Delete(k)

	return nil
}

type savedStateFields struct {
	MasterSecret                          []byte
	LocalConnectionID, RemoteConnectionID []byte
	RRCNegotiated                         bool
}

func serializedSnapshot(t *testing.T, state *dtls.State) savedStateFields {
	t.Helper()
	raw, err := state.MarshalBinary()
	require.NoError(t, err)
	var saved savedStateFields
	require.NoError(t, gob.NewDecoder(bytes.NewReader(raw)).Decode(&saved))

	return saved
}

func TestPionV4ConnectionStateRoleAndVersion(t *testing.T) {
	for _, test := range []struct {
		name    string
		version protocol.Version
	}{
		{"DTLS1.2", protocol.Version1_2},
		{"DTLS1.3", protocol.Version1_3},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			type result struct {
				c   *dtls.Conn
				err error
			}
			resultCh := make(chan result, 1)

			go func() {
				client, err := testClient(
					ctx,
					ca,
					ca.RemoteAddr(),
					[]dtls.ClientOption{dtls.WithMinVersion(test.version), dtls.WithMaxVersion(test.version)},
					true,
				)
				resultCh <- result{client, err}
			}()

			server, err := testServer(
				ctx,
				cb,
				cb.RemoteAddr(),
				[]dtls.ServerOption{dtls.WithMinVersion(test.version), dtls.WithMaxVersion(test.version)},
				true,
			)
			require.NoError(t, err)

			res := <-resultCh
			require.NoError(t, res.err)

			defer func() {
				require.NoError(t, res.c.Close())
				require.NoError(t, server.Close())
			}()

			clientState, ok := res.c.ConnectionState()
			require.True(t, ok)
			serverState, ok := server.ConnectionState()
			require.True(t, ok)

			require.Equal(t, dtls.RoleClient, clientState.Role())
			require.Equal(t, dtls.RoleServer, serverState.Role())
			require.True(t, clientState.NegotiatedVersion() == test.version)
			require.True(t, serverState.NegotiatedVersion() == test.version)
			require.NotNil(t, clientState.KeyUsage)
			require.NotNil(t, serverState.KeyUsage)
			require.Equal(t, uint64(23726566), clientState.KeyUsage.RecommendedLimits.MaxSealedRecords)
			if test.version == protocol.Version1_2 {
				require.Equal(t, uint64(1<<28), clientState.KeyUsage.RecommendedLimits.MaxAuthenticationFailures)
			}
		})
	}
}

var (
	errMessageMismatch        = errors.New("messages mismatch")
	errInvalidConnectionState = errors.New("failed to get connection state")
)

func TestPionV4ResumeClient(t *testing.T) {
	DoTestResume(t, resumeClient, resumeServer)
}

func TestPionV4ResumeServer(t *testing.T) {
	DoTestResume(t, resumeServer, resumeClient)
}

func resumeClient(conn net.PacketConn, rAddr net.Addr, opts []dtls.Option) (*dtls.Conn, error) {
	clientOpts := make([]dtls.ClientOption, len(opts))
	for i, opt := range opts {
		clientOpts[i] = opt
	}

	return dtls.Client(conn, rAddr, clientOpts...)
}

func resumeServer(conn net.PacketConn, rAddr net.Addr, opts []dtls.Option) (*dtls.Conn, error) {
	serverOpts := make([]dtls.ServerOption, len(opts))
	for i, opt := range opts {
		serverOpts[i] = opt
	}

	return dtls.Server(conn, rAddr, serverOpts...)
}

func fatal(t *testing.T, errChan chan error, err error) {
	t.Helper()

	close(errChan)
	assert.NoError(t, err)
}

//nolint:cyclop
func DoTestResume(
	t *testing.T,
	newLocal,
	newRemote func(net.PacketConn, net.Addr, []dtls.Option) (*dtls.Conn, error),
) {
	t.Helper()

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	// Generate connections
	localConn1, rc1 := packetPipe()
	localConn2, rc2 := packetPipe()
	remoteConn := &backupConn{}
	remoteConn.curr.Store(rc1)

	// Launch remote in another goroutine
	errChan := make(chan error, 1)
	defer func() {
		err = <-errChan
		assert.NoError(t, err)
	}()
	opts := []dtls.Option{
		dtls.WithCertificates(certificate),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	}
	go func() {
		var remote *dtls.Conn
		var errR error
		remote, errR = newRemote(remoteConn, rc1.RemoteAddr(), opts)
		if errR != nil {
			errChan <- errR
		}

		// Loop of read write
		for range 2 {
			recv := make([]byte, 1024)
			var n int
			n, errR = remote.Read(recv)
			assert.NoError(t, errR)

			if _, errR = remote.Write(recv[:n]); errR != nil {
				errChan <- errR
			}
		}
		errChan <- nil
	}()

	var local *dtls.Conn
	local, err = newLocal(localConn1, localConn1.RemoteAddr(), opts)
	if err != nil {
		fatal(t, errChan, err)
	}
	defer func() {
		_ = local.Close()
	}()

	// Test write and read
	message := []byte("Hello")
	if _, err = local.Write(message); err != nil {
		fatal(t, errChan, err)
	}

	recv := make([]byte, 1024)
	var n int
	n, err = local.Read(recv)
	if err != nil {
		fatal(t, errChan, err)
	}

	if !bytes.Equal(message, recv[:n]) {
		fatal(t, errChan, fmt.Errorf("%w: %s != %s", errMessageMismatch, message, recv[:n]))
	}

	if err = localConn1.Close(); err != nil {
		fatal(t, errChan, err)
	}
	// Select the replacement transport, then wake any read on the old pipe.
	remoteConn.curr.Store(rc2)
	if err = rc1.Close(); err != nil {
		fatal(t, errChan, err)
	}

	// Serialize and deserialize state
	state, ok := local.ConnectionState()
	if !ok {
		fatal(t, errChan, errInvalidConnectionState)
	}
	var b []byte
	b, err = state.MarshalBinary()
	if err != nil {
		fatal(t, errChan, err)
	}
	deserialized := &dtls.State{}
	if err = deserialized.UnmarshalBinary(b); err != nil {
		fatal(t, errChan, err)
	}

	// Resume dtls connection
	var resumed net.Conn
	resumed, err = dtls.Resume(
		deserialized,
		localConn2,
		localConn2.RemoteAddr(),
		opts...,
	)
	if err != nil {
		fatal(t, errChan, err)
	}
	defer func() {
		_ = resumed.Close()
	}()

	// Test write and read on resumed connection
	if _, err = resumed.Write(message); err != nil {
		fatal(t, errChan, err)
	}

	recv = make([]byte, 1024)
	n, err = resumed.Read(recv)
	if err != nil {
		fatal(t, errChan, err)
	}

	if !bytes.Equal(message, recv[:n]) {
		fatal(t, errChan, fmt.Errorf("%w: %s != %s", errMessageMismatch, message, recv[:n]))
	}
}

type backupConn struct {
	curr atomic.Pointer[packetTestConn]
}

func (b *backupConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	curr := b.curr.Load()
	n, addr, err = curr.ReadFrom(data)
	if err != nil && curr != b.curr.Load() {
		return b.ReadFrom(data)
	}

	return n, addr, err
}

func (b *backupConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	return b.curr.Load().WriteTo(data, addr)
}

func (b *backupConn) Close() error {
	return nil
}

func (b *backupConn) LocalAddr() net.Addr {
	return b.curr.Load().LocalAddr()
}

func (b *backupConn) SetDeadline(deadline time.Time) error {
	return b.curr.Load().SetDeadline(deadline)
}

func (b *backupConn) SetReadDeadline(deadline time.Time) error {
	return b.curr.Load().SetReadDeadline(deadline)
}

func (b *backupConn) SetWriteDeadline(deadline time.Time) error {
	return b.curr.Load().SetWriteDeadline(deadline)
}
