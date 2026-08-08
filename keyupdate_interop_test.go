// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"io"
	"testing"
)

func TestBoringSSLDTLS13KeyUpdateInterop(t *testing.T) {
	tests := []struct {
		name  string
		probe func(context.Context, string, io.Writer, commandContextFunc) error
	}{
		{
			name:  "PionClient_BoringSSLServer",
			probe: probeBoringSSL13KeyUpdatePionClient,
		},
		{
			name:  "PionServer_BoringSSLClient",
			probe: probeBoringSSL13KeyUpdatePionServer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runBoringSSLInteropTest(t, test.probe)
		})
	}
}

func probeBoringSSL13KeyUpdatePionClient(
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
		boringSSLProbeOptions{keyUpdate: true},
	)
}

func probeBoringSSL13KeyUpdatePionServer(
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
		boringSSLProbeOptions{keyUpdate: true},
	)
}
