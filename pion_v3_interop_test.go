// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"net"
	"testing"

	dtlsv3 "github.com/pion/dtls/v3"
	ellipticv3 "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func pionV3Interop() interopBackend {
	notImplemented := skipInterop(errInteropNotImplemented, "Pion v3 adapter")

	return interopBackend{
		versions:     []protocol.Version{protocol.Version1_2},
		otherVersion: errInteropNotSupported,
		scenarios: map[interopScenario]interopRun{
			interopHandshake:        testPionV3Interop,
			interopKeyExchange:      testPionV3Interop,
			interopVersionFallback:  testPionV3Interop,
			interopKeyUpdatePion:    skipInterop(errInteropNotSupported, "requires DTLS 1.3"),
			interopKeyUpdatePeer:    skipInterop(errInteropNotSupported, "requires DTLS 1.3"),
			interopCID:              notImplemented,
			interopCIDRebinding:     notImplemented,
			interopCIDPolicyDiscard: notImplemented,
			interopWebRTC:           notImplemented,
		},
	}
}

func testPionV3Interop(t *testing.T, testCase interopCase) error {
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
	require.NoError(t, testCase.checkConnection(connection))

	exchangeInteropData(t, connection, peer, "v4-to-v3")
	exchangeInteropData(t, peer, connection, "v3-to-v4")

	return nil
}
