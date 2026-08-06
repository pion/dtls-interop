// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoringSSLDTLS13Interop(t *testing.T) {
	tests := []struct {
		name  string
		probe func(context.Context, string, io.Writer, commandContextFunc) error
	}{
		{
			name:  "PionClient_BoringSSLServer",
			probe: probeBoringSSL13PionClient,
		},
		{
			name:  "PionServer_BoringSSLClient",
			probe: probeBoringSSL13PionServer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runBoringSSLInteropTest(t, test.probe)
		})
	}
}

func runBoringSSLInteropTest(
	t *testing.T,
	probe func(context.Context, string, io.Writer, commandContextFunc) error,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var output bytes.Buffer
	err := probe(
		ctx,
		environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"),
		&output,
		exec.CommandContext,
	)
	if output.Len() != 0 {
		t.Log(strings.TrimSpace(output.String()))
	}
	require.NoError(t, err)
}
