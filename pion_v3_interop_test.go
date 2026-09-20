// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	dtlsv3 "github.com/pion/dtls/v3"
	ellipticv3 "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func runPionV3Case(t *testing.T, testCase interopCase) error {
	t.Helper()
	if testCase.version != protocol.Version1_2 {
		return fmt.Errorf("%w: Pion v3 only supports DTLS 1.2", errInteropNotSupported)
	}
	switch testCase.scenario {
	case interopHandshake, interopKeyExchange, interopVersionFallback:
		testPionV3Interop(t, testCase)
	default:
		return fmt.Errorf("%w: Pion v3 %s adapter", errInteropNotImplemented, testCase.scenario)
	}

	return nil
}

func testPionV3Interop(t *testing.T, testCase interopCase) {
	t.Helper()
	config := pionConfigForCase(testCase)
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
	if testCase.role == interopPionClient {
		connection, err = dtls.Client(socket, peerSocket.LocalAddr(),
			dtls.WithInsecureSkipVerify(true),
			dtls.WithEllipticCurves(config.groups...),
			dtls.WithMinVersion(testCase.version), dtls.WithMaxVersion(config.maxVersion))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		peer, err = dtlsv3.ServerWithOptions(peerSocket, socket.LocalAddr(),
			dtlsv3.WithCertificates(certificate),
			dtlsv3.WithEllipticCurves(ellipticv3.Curve(config.peerGroup)))
	} else {
		connection, err = dtls.Server(socket, peerSocket.LocalAddr(),
			dtls.WithCertificates(certificate),
			dtls.WithEllipticCurves(config.groups...),
			dtls.WithMinVersion(testCase.version), dtls.WithMaxVersion(config.maxVersion))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		peer, err = dtlsv3.ClientWithOptions(peerSocket, socket.LocalAddr(),
			dtlsv3.WithInsecureSkipVerify(true),
			dtlsv3.WithEllipticCurves(ellipticv3.Curve(config.peerGroup)))
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
