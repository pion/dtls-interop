// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"

	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPionV3SessionResume(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	t.Run("resumed", func(t *testing.T) {
		t.Skip("Pion v3 does not negotiate connection IDs during session resumption")

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
				dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithServerName("example.com"),
				dtls.WithSessionStore(ss),
				dtls.WithConnectionIDGenerator(func() []byte { return clientCID }),
				dtls.WithMTU(100),
			}
			c, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false)
			clientRes <- result{c, err}
		}()

		opts := []dtls.ServerOption{
			dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			dtls.WithServerName("example.com"),
			dtls.WithSessionStore(ss),
			dtls.WithConnectionIDGenerator(func() []byte { return serverCID }),
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
