// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnvilInterop(t *testing.T) {
	binary := environmentOrDefault("DTLS_INTEROP_ANVIL_BIN", "tls-anvil")
	_, err := exec.LookPath(binary)
	if err != nil && os.Getenv("DTLS_INTEROP_ANVIL_BIN") == "" && os.Getenv("DTLS_INTEROP_RUNNER") != "anvil" {
		t.Skip("TLS-Anvil is not installed; use the anvil Devenv shell or DTLS_INTEROP_ANVIL_BIN")
	}
	require.NoError(t, err)
	versions := []string{anvilVersion12, anvilVersion13}
	if version := os.Getenv("DTLS_INTEROP_ANVIL_VERSION"); version != "" {
		versions = []string{version}
	} else if os.Getenv("DTLS_INTEROP_ANVIL_PROFILE") != "" {
		versions = []string{anvilVersion12}
	}
	for _, version := range versions {
		t.Run("DTLS"+version, func(t *testing.T) {
			var output bytes.Buffer
			err := run(context.Background(), []string{"-mode", "anvil", "-anvil-version", version}, &output, exec.CommandContext)
			t.Log(output.String())
			require.NoError(t, err)
		})
	}
}
