// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"net"
	"testing"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func pionV4Interop() interopBackend {
	notImplemented := skipInterop(errInteropNotImplemented, "Pion v4 adapter")

	return interopBackend{
		versions:     []protocol.Version{protocol.Version1_2, protocol.Version1_3},
		otherVersion: errInteropNotSupported,
		scenarios: map[interopScenario]interopRun{
			interopHandshake:        testPionV4Interop,
			interopKeyExchange:      testPionV4Interop,
			interopVersionFallback:  testPionV4Interop,
			interopKeyUpdatePion:    notImplemented,
			interopKeyUpdatePeer:    notImplemented,
			interopCID:              notImplemented,
			interopCIDRebinding:     notImplemented,
			interopCIDPolicyDiscard: notImplemented,
			interopWebRTC:           notImplemented,
		},
	}
}

func testPionV4Interop(t *testing.T, testCase interopCase) error {
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

	var connection, peer *dtls.Conn
	if testCase.role == interopPionClient {
		connection, err = dtls.Client(socket, peerSocket.LocalAddr(),
			dtls.WithInsecureSkipVerify(true),
			dtls.WithEllipticCurves(config.groups...),
			dtls.WithMinVersion(testCase.version), dtls.WithMaxVersion(config.maxVersion))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		peer, err = dtls.Server(peerSocket, socket.LocalAddr(),
			dtls.WithCertificates(certificate),
			dtls.WithEllipticCurves(config.peerGroup),
			dtls.WithMinVersion(testCase.version), dtls.WithMaxVersion(testCase.version))
	} else {
		connection, err = dtls.Server(socket, peerSocket.LocalAddr(),
			dtls.WithCertificates(certificate),
			dtls.WithEllipticCurves(config.groups...),
			dtls.WithMinVersion(testCase.version), dtls.WithMaxVersion(config.maxVersion))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		peer, err = dtls.Client(peerSocket, socket.LocalAddr(),
			dtls.WithInsecureSkipVerify(true),
			dtls.WithEllipticCurves(config.peerGroup),
			dtls.WithMinVersion(testCase.version), dtls.WithMaxVersion(testCase.version))
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
	require.NoError(t, testCase.checkConnection(connection))
	require.NoError(t, testCase.checkConnection(peer))

	exchangeInteropData(t, connection, peer, "pion-to-peer")
	exchangeInteropData(t, peer, connection, "peer-to-pion")

	return nil
}
