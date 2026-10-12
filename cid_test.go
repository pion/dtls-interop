// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startCIDListenerPair(t *testing.T, listener net.Listener, opts ...dtls.ClientOption) cidListenerPair {
	t.Helper()

	return startCIDListenerPairWithProxy(t, listener, true, opts...)
}

func startCIDListenerPairWithProxy(
	t *testing.T,
	listener net.Listener,
	useProxy bool,
	opts ...dtls.ClientOption,
) cidListenerPair {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	var proxy *rebindingProxy
	remote := listener.Addr()
	if useProxy {
		address, ok := listener.Addr().(*net.UDPAddr)
		require.True(t, ok)
		proxy = newRebindingProxy(t, address)
		remote = proxy.address()
	}
	clientTransport := &cidOperationTransport{PacketConn: socket}
	client, err := dtls.Client(clientTransport, remote, opts...)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	pair := cidListenerPair{
		transport:  clientTransport,
		proxy:      proxy,
		client:     client,
		clientDone: make(chan error, 1),
		serverDone: make(chan error, 1),
		cancel:     cancel,
	}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- acceptResult{conn, acceptErr}
	}()
	go func() { pair.clientDone <- client.HandshakeContext(ctx) }()
	select {
	case result := <-accepted:
		assert.NoError(t, result.err)
		t.Cleanup(func() { _ = result.conn.Close() })
		var ok bool
		pair.server, ok = result.conn.(*dtls.Conn)
		assert.True(t, ok)
	case <-ctx.Done():
		assert.NoError(t, ctx.Err())
	}
	go func() { pair.serverDone <- pair.server.HandshakeContext(ctx) }()

	return pair
}

func TestPionV4ListenConnectionIDFragmentedServerHello(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	for versionName, version := range map[string]protocol.Version{
		"DTLS12": protocol.Version1_2,
		"DTLS13": protocol.Version1_3,
	} {
		t.Run(versionName, func(t *testing.T) {
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			assert.NoError(t, err)
			transport := &fragmentedServerHelloConn{PacketConn: socket}
			listener, err := dtls.Listen(transport,
				dtls.WithCertificates(certificate), dtls.WithMinVersion(version), dtls.WithMaxVersion(version), dtls.WithMTU(48),
				dtls.WithInsecureSkipVerifyHello(true),
				dtls.WithConnectionID(func() []byte { return []byte("server-cid") }, dtls.CIDPathMigrationUnsafe),
			)
			assert.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			pair := startCIDListenerPair(t, listener,
				dtls.WithInsecureSkipVerify(true), dtls.WithMinVersion(version), dtls.WithMaxVersion(version), dtls.WithMTU(48),
				dtls.WithConnectionID(func() []byte { return []byte("client-cid") }, dtls.CIDPathMigrationUnsafe),
			)
			assert.NoError(t, <-pair.clientDone)
			assert.NoError(t, <-pair.serverDone)
			assert.True(t, transport.fragmented.Load(), "ServerHello must actually be fragmented")
			assertCIDListenerRebinding(t, pair)
		})
	}
}

func TestPionV4ListenConnectionIDCollisionPreservesAssociation(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	for versionName, version := range map[string]protocol.Version{
		"DTLS12": protocol.Version1_2,
		"DTLS13": protocol.Version1_3,
	} {
		t.Run(versionName, func(t *testing.T) {
			listener, err := dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
				dtls.WithCertificates(certificate), dtls.WithMinVersion(version), dtls.WithMaxVersion(version),
				dtls.WithConnectionID(func() []byte { return []byte("shared-cid") }, dtls.CIDPathMigrationUnsafe),
			)
			assert.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			opts := []dtls.ClientOption{
				dtls.WithInsecureSkipVerify(true), dtls.WithMinVersion(version), dtls.WithMaxVersion(version),
				dtls.WithConnectionID(dtls.OnlySendCIDGenerator(), dtls.CIDPathMigrationUnsafe),
			}
			first := startCIDListenerPair(t, listener, opts...)
			assert.NoError(t, <-first.clientDone)
			assert.NoError(t, <-first.serverDone)
			second := startCIDListenerPair(t, listener, opts...)
			assertInteropError(
				t,
				<-second.serverDone,
				expectedTextError("connection ID already belongs to another connection"),
			)
			second.cancel()
			assert.Error(t, <-second.clientDone)
			_ = second.server.Close()
			_ = second.client.Close()
			assertCIDListenerData(t, first.client, first.server)
			assertCIDListenerData(t, first.server, first.client)
			assertCIDListenerRebinding(t, first)
		})
	}
}

func assertCIDListenerData(t *testing.T, sender, receiver *dtls.Conn) {
	t.Helper()
	payload := []byte("association data")
	_, err := sender.Write(payload)
	assert.NoError(t, err)
	assert.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 64)
	n, err := receiver.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, payload, buffer[:n])
}

func newPathTestPair(
	t *testing.T,
	cidOption dtls.Option,
) (
	*dtls.Conn,
	*dtls.Conn,
	*cidOperationTransport,
	*cidOperationTransport,
) {
	t.Helper()
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverTransport := &cidOperationTransport{PacketConn: socket}
	listener, err := dtls.Listen(serverTransport,
		dtls.WithCertificates(certificate), dtls.WithInsecureSkipVerifyHello(true),
		dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithFlightInterval(20*time.Millisecond), cidOption)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	pair := startCIDListenerPairWithProxy(t, listener, false, dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithFlightInterval(20*time.Millisecond), cidOption)
	require.NoError(t, <-pair.clientDone)
	require.NoError(t, <-pair.serverDone)

	return pair.client, pair.server, pair.transport, serverTransport
}

func addTestPath(t *testing.T, conn *dtls.Conn) (*dtls.Path, *cidOperationTransport) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	transport := &cidOperationTransport{PacketConn: socket}
	path, err := conn.AddPath(transport)
	require.NoError(t, err)

	return path, transport
}

func TestPionV4PathMigration(t *testing.T) {
	for name, migrateServer := range map[string]bool{"Client": false, "Server": true} {
		t.Run(name, func(t *testing.T) {
			client, server, clientTransport, serverTransport := newPathTestPair(
				t,
				dtls.WithConnectionID(dtls.RandomCIDGenerator(8), dtls.CIDPathMigrationRRC),
			)
			originalTransport := clientTransport
			mover, peer := client, server
			if migrateServer {
				mover, peer = server, client
				originalTransport = serverTransport
			}
			oldAddr := mover.LocalAddr()
			assertPathPayload(t, mover, peer, "original path")
			oldCID := lastOutgoingCID(t, originalTransport)
			path, socket := addTestPath(t, mover)
			assertInteropError(t, path.Switch(), expectedTextError("path has not been validated"))
			socket.dropNext.Store(true)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, path.Probe(ctx))
			assert.False(t, socket.dropNext.Load(), "lost probes are retried")
			assert.Equal(t, oldAddr, mover.LocalAddr())
			assert.Never(t, func() bool {
				return oldAddr.String() != peer.RemoteAddr().String()
			}, 50*time.Millisecond, time.Millisecond, "probing must not move the peer")
			socket.dropAll.Store(true)
			retryCtx, cancelRetry := context.WithTimeout(ctx, 50*time.Millisecond)
			assert.ErrorIs(t, path.Probe(retryCtx), context.DeadlineExceeded)
			cancelRetry()
			assertInteropError(t, path.Switch(), expectedTextError("path has not been validated"))
			socket.dropAll.Store(false)
			require.NoError(t, path.Probe(ctx))
			assertPathPayload(t, mover, peer, "original path remains usable after probing")
			assert.Equal(t, oldCID, lastOutgoingCID(t, originalTransport), "probing must not rotate the active path")
			socket.mu.Lock()
			var candidateCID []byte
			for _, raw := range socket.outgoing {
				record, parseErr := recordlayer.ParseRecord(raw, 8)
				assert.NoError(t, parseErr)
				if candidateCID == nil {
					candidateCID = bytes.Clone(record.ConnectionID())
					assert.NotEmpty(t, candidateCID)
					assert.NotEqual(t, oldCID, candidateCID)
				}
				assert.Equal(t, candidateCID, record.ConnectionID(), "probes use the candidate CID on the wire")
			}
			socket.mu.Unlock()
			require.NoError(t, path.Switch())
			assert.Equal(t, socket.LocalAddr(), mover.LocalAddr())
			assertInteropError(t, path.Close(), expectedTextError("path is in use"))
			assertPathPayload(t, mover, peer, "migrated")
			require.Eventually(t, func() bool {
				return peer.RemoteAddr().String() == socket.LocalAddr().String()
			}, time.Second, time.Millisecond)
			assertPathPayload(t, peer, mover, "reply")
			next, nextSocket := addTestPath(t, mover)
			require.NoError(t, next.Probe(ctx))
			require.NoError(t, next.Switch())
			require.NoError(t, path.Close())
			assertPathPayload(t, mover, peer, "second migration")
			require.NoError(t, mover.Close())
			assert.ErrorIs(t, path.Probe(ctx), dtls.ErrConnClosed)
			assert.ErrorIs(t, path.Switch(), dtls.ErrConnClosed)
			_, _, err := nextSocket.ReadFrom(make([]byte, 1))
			assert.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

func assertPathPayload(t *testing.T, sender, receiver *dtls.Conn, payload string) {
	t.Helper()
	_, err := sender.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 64)
	n, err := receiver.Read(buffer)
	require.NoError(t, err)
	assert.Equal(t, payload, string(buffer[:n]))
}

type cidListenerPair struct {
	transport              *cidOperationTransport
	proxy                  *rebindingProxy
	client, server         *dtls.Conn
	clientDone, serverDone chan error
	cancel                 context.CancelFunc
}

type fragmentedServerHelloConn struct {
	net.PacketConn
	fragmented atomic.Bool
}

type cidOperationTransport struct {
	net.PacketConn
	dropNext atomic.Bool
	dropAll  atomic.Bool
	mu       sync.Mutex
	outgoing [][]byte
}

func (c *fragmentedServerHelloConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	recordHeader, parseErr := recordlayer.ParseRecord(packet, 0)
	var handshakeHeader handshake.Header
	if parseErr == nil && recordHeader.ContentType() == protocol.ContentTypeHandshake &&
		handshakeHeader.Unmarshal(packet[len(recordHeader.HeaderBytes()):]) == nil &&
		handshakeHeader.Type == handshake.TypeServerHello && handshakeHeader.FragmentLength < handshakeHeader.Length {
		c.fragmented.Store(true)
	}

	return c.PacketConn.WriteTo(packet, addr)
}

func (c *cidOperationTransport) WriteTo(packet []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.outgoing = append(c.outgoing, bytes.Clone(packet))
	c.mu.Unlock()
	if c.dropAll.Load() || c.dropNext.CompareAndSwap(true, false) {
		return len(packet), nil
	}

	return c.PacketConn.WriteTo(packet, addr)
}

func assertCIDListenerRebinding(t *testing.T, pair cidListenerPair) {
	t.Helper()
	pair.proxy.rebindPath()
	assertPathPayload(t, pair.client, pair.server, "rebound association")
	assert.Eventually(
		t,
		func() bool { return pair.proxy.rebound.LocalAddr().String() == pair.server.RemoteAddr().String() },
		time.Second,
		time.Millisecond,
	)
}

func lastOutgoingCID(t *testing.T, transport *cidOperationTransport) []byte {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	require.NotEmpty(t, transport.outgoing)
	record, err := recordlayer.ParseRecord(transport.outgoing[len(transport.outgoing)-1], 8)
	require.NoError(t, err)

	return bytes.Clone(record.ConnectionID())
}
