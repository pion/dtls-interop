// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"io"
	"net"
	"testing"

	dtlsv3 "github.com/pion/dtls/v3"
	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestPionV3DTLS12Interop(t *testing.T) {
	for _, mode := range []struct {
		name       string
		maxVersion protocol.Version
	}{
		{"DTLS13Enabled", protocol.Version1_3},
		{"DTLS13Disabled", protocol.Version1_2},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for _, role := range []string{"client", "server"} {
				t.Run(role, func(t *testing.T) { testPionV3Interop(t, role, mode.maxVersion) })
			}
		})
	}
}

func testPionV3Interop(t *testing.T, role string, maxVersion protocol.Version) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()

	var listenConfig net.ListenConfig
	socket, err := listenConfig.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	peerSocket, err := listenConfig.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = peerSocket.Close() })
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	var connection *dtls.Conn
	var peer *dtlsv3.Conn
	if role == "client" {
		connection, err = dtls.Client(socket, peerSocket.LocalAddr(),
			dtls.WithInsecureSkipVerify(true),
			dtls.WithMinVersion(protocol.Version1_2), dtls.WithMaxVersion(maxVersion))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		peer, err = dtlsv3.ServerWithOptions(peerSocket, socket.LocalAddr(),
			dtlsv3.WithCertificates(certificate))
	} else {
		connection, err = dtls.Server(socket, peerSocket.LocalAddr(),
			dtls.WithCertificates(certificate),
			dtls.WithMinVersion(protocol.Version1_2), dtls.WithMaxVersion(maxVersion))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		peer, err = dtlsv3.ClientWithOptions(peerSocket, socket.LocalAddr(),
			dtlsv3.WithInsecureSkipVerify(true))
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, connection.SetDeadline(deadline))
	require.NoError(t, peer.SetDeadline(deadline))

	peerHandshake := make(chan error, 1)
	go func() { peerHandshake <- peer.HandshakeContext(ctx) }()
	require.NoError(t, connection.HandshakeContext(ctx))
	require.NoError(t, <-peerHandshake)
	state, ok := connection.ConnectionState()
	require.True(t, ok)
	require.Equal(t, protocol.Version1_2, state.NegotiatedVersion())

	exchangePionV3Data(t, connection, peer, "v4-to-v3")
	exchangePionV3Data(t, peer, connection, "v3-to-v4")
}

func exchangePionV3Data(t *testing.T, sender, receiver net.Conn, message string) {
	t.Helper()
	written, err := io.WriteString(sender, message)
	require.NoError(t, err)
	require.Equal(t, len(message), written)
	received := make([]byte, len(message))
	_, err = io.ReadFull(receiver, received)
	require.NoError(t, err)
	require.Equal(t, message, string(received))
}
