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
		name    string
		probe   func(context.Context, string, io.Writer, commandContextFunc, boringSSLProbeOptions) error
		options boringSSLProbeOptions
	}{
		{
			name:    "BoringSSLInitiated/PionClient_BoringSSLServer",
			probe:   probeBoringSSL13PionClientWithOptions,
			options: boringSSLProbeOptions{boringSSLKeyUpdate: true},
		},
		{
			name:    "BoringSSLInitiated/PionServer_BoringSSLClient",
			probe:   probeBoringSSL13PionServerWithOptions,
			options: boringSSLProbeOptions{boringSSLKeyUpdate: true},
		},
		{
			name:    "PionInitiated/PionClient_BoringSSLServer",
			probe:   probeBoringSSL13PionClientWithOptions,
			options: boringSSLProbeOptions{pionKeyUpdate: updatePionKeys},
		},
		{
			name:    "PionInitiated/PionServer_BoringSSLClient",
			probe:   probeBoringSSL13PionServerWithOptions,
			options: boringSSLProbeOptions{pionKeyUpdate: updatePionKeys},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runBoringSSLInteropTest(t, test.probe, test.options)
		})
	}
}

func updatePionKeys(ctx context.Context, connection *dtls.Conn) error {
	return connection.UpdateKeys(ctx, dtls.KeyUpdateOptions{RequestPeerUpdate: true})
}
