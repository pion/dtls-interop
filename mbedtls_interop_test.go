// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func mbedTLSInterop() interopBackend {
	notImplemented := skipInterop(errInteropNotImplemented, "Mbed TLS adapter")

	return interopBackend{
		version:      protocol.Version1_2,
		otherVersion: errInteropNotSupported,
		scenarios: map[interopScenario]interopRun{
			interopHandshake:        runMbedTLSCase,
			interopKeyExchange:      notImplemented,
			interopVersionFallback:  notImplemented,
			interopKeyUpdatePion:    skipInterop(errInteropNotSupported, "requires DTLS 1.3"),
			interopKeyUpdatePeer:    skipInterop(errInteropNotSupported, "requires DTLS 1.3"),
			interopCID:              notImplemented,
			interopCIDRebinding:     notImplemented,
			interopCIDPolicyDiscard: notImplemented,
			interopWebRTC:           notImplemented,
		},
	}
}

func runMbedTLSCase(t *testing.T, testCase interopCase) error {
	t.Helper()
	if testCase.role != interopPionClient {
		return fmt.Errorf("%w: Mbed TLS with Pion as server", errInteropNotImplemented)
	}
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	address, ok := socket.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.NoError(t, socket.Close())
	process := startInteropProcess(t, ctx,
		environmentOrDefault("DTLS_INTEROP_MBEDTLS_SERVER_BIN", "ssl_server2"),
		"server_addr=127.0.0.1", "server_port="+strconv.Itoa(address.Port),
		"force_version=dtls12", "auth_mode=none", "exchanges=1",
	)
	process.waitForOutput(t, ctx, "Waiting for a remote connection")
	client, err := dtls.Dial("udp4", address,
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(protocol.Version1_2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, client.HandshakeContext(ctx), process.output.String())
	require.NoError(t, testCase.checkConnection(client))

	const request = "GET /interop HTTP/1.0\r\n\r\n"
	written, err := io.WriteString(client, request)
	require.NoError(t, err)
	require.Equal(t, len(request), written)
	response := make([]byte, 2048)
	n, err := client.Read(response)
	require.NoError(t, err, process.output.String())
	require.Contains(t, string(response[:n]), "HTTP/1.0 200 OK")
	process.waitForOutput(t, ctx, request)

	return nil
}
