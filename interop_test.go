// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"io"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/stretchr/testify/require"
)

func TestBoringSSLDTLS13Interop(t *testing.T) {
	tests := []struct {
		name  string
		probe func(context.Context, string, io.Writer, commandContextFunc, boringSSLProbeOptions) error
	}{
		{
			name:  "PionClient_BoringSSLServer",
			probe: probeBoringSSL13PionClientWithOptions,
		},
		{
			name:  "PionServer_BoringSSLClient",
			probe: probeBoringSSL13PionServerWithOptions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runBoringSSLInteropTest(t, test.probe, boringSSLProbeOptions{})
		})
	}
}

func runBoringSSLInteropTest(
	t *testing.T,
	probe func(context.Context, string, io.Writer, commandContextFunc, boringSSLProbeOptions) error,
	options boringSSLProbeOptions,
) {
	t.Helper()

	for _, group := range slices.Sorted(maps.Keys(elliptic.Curves())) {
		t.Run(group.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
			defer cancel()

			groupOptions := options
			groupOptions.keyExchangeGroup = group
			var output bytes.Buffer
			err := probe(
				ctx,
				environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"),
				&output,
				exec.CommandContext,
				groupOptions,
			)
			if output.Len() != 0 {
				t.Log(strings.TrimSpace(output.String()))
			}
			require.NoError(t, err)
		})
	}
}
