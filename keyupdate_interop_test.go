// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"io"
	"testing"

	"github.com/pion/dtls/v3"
)

func TestBoringSSLDTLS13KeyUpdateInterop(t *testing.T) {
	tests := []struct {
		name  string
		probe func(context.Context, string, io.Writer, commandContextFunc) error
	}{
		{
			name:  "BoringSSLInitiated/PionClient_BoringSSLServer",
			probe: probeBoringSSL13PeerKeyUpdatePionClient,
		},
		{
			name:  "BoringSSLInitiated/PionServer_BoringSSLClient",
			probe: probeBoringSSL13PeerKeyUpdatePionServer,
		},
		{
			name:  "PionInitiated/PionClient_BoringSSLServer",
			probe: probeBoringSSL13PionKeyUpdatePionClient,
		},
		{
			name:  "PionInitiated/PionServer_BoringSSLClient",
			probe: probeBoringSSL13PionKeyUpdatePionServer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runBoringSSLInteropTest(t, test.probe)
		})
	}
}

func probeBoringSSL13PeerKeyUpdatePionClient(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	return probeBoringSSL13PionClientWithOptions(
		ctx,
		shimPath,
		stdout,
		commandContext,
		boringSSLProbeOptions{boringSSLKeyUpdate: true},
	)
}

func probeBoringSSL13PeerKeyUpdatePionServer(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	return probeBoringSSL13PionServerWithOptions(
		ctx,
		shimPath,
		stdout,
		commandContext,
		boringSSLProbeOptions{boringSSLKeyUpdate: true},
	)
}

func probeBoringSSL13PionKeyUpdatePionClient(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	return probeBoringSSL13PionClientWithOptions(
		ctx,
		shimPath,
		stdout,
		commandContext,
		boringSSLProbeOptions{pionKeyUpdate: updatePionKeys},
	)
}

func probeBoringSSL13PionKeyUpdatePionServer(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	return probeBoringSSL13PionServerWithOptions(
		ctx,
		shimPath,
		stdout,
		commandContext,
		boringSSLProbeOptions{pionKeyUpdate: updatePionKeys},
	)
}

func updatePionKeys(ctx context.Context, connection *dtls.Conn) error {
	return connection.UpdateKeys(ctx, dtls.KeyUpdateOptions{RequestPeerUpdate: true})
}
