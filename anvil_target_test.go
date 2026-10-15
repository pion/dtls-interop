// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestAnvilTarget(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) { testAnvilTarget(t, version) })
	}
}

func TestAnvil13Process(t *testing.T) {
	outputDir := t.TempDir()
	profilePath := filepath.Join(outputDir, "handshake.json")
	require.NoError(t, os.WriteFile(profilePath, []byte(`{"testIds":["8446-jVohiUKi4u"]}`), 0o600))
	err := runAnvil(context.Background(), anvilOptions{
		binary: "fake-anvil", profile: profilePath, outputDir: outputDir, version: "1.3",
	}, io.Discard, func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		require.Equal(t, "-dtls13", args[0])
		require.Contains(t, args, "2")

		return exec.CommandContext(ctx, "sh", "-c",
			`printf '%s' '{"STRICTLY_SUCCEEDED":["8446-jVohiUKi4u"]}' > result_map.json`)
	})
	require.NoError(t, err)
	profiles, err := filepath.Glob(filepath.Join(outputDir, "dtls13-*", "profile.json"))
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	profile, err := readAnvilProfile(profiles[0], "1.3")
	require.NoError(t, err)
	require.Equal(t, []string{"8446-jVohiUKi4u"}, profile.TestIDs)
}

func testAnvilTarget(t *testing.T, version protocol.Version) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := listenAnvilTarget(version)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- serveAnvilTarget(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case serverErr := <-done:
			require.NoError(t, serverErr)
		case <-time.After(time.Second):
			require.Fail(t, "Anvil target did not stop")
		}
	})
	address, err := net.ResolveUDPAddr("udp4", listener.Addr().String())
	require.NoError(t, err)

	for range 2 {
		client, err := dtls.Dial("udp4", address,
			dtls.WithInsecureSkipVerify(true),
			dtls.WithMinVersion(version), dtls.WithMaxVersion(version),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })
		require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
		require.NoError(t, client.HandshakeContext(ctx))
		state, ok := client.ConnectionState()
		require.True(t, ok)
		require.Equal(t, version, state.NegotiatedVersion())
		exchangeInteropData(t, client, client, "Anvil UDP echo")
	}
}

func TestAnvilProcessFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		script string
		want   string
	}{
		{"nonzero exit", "exit 7", "exit status 7"},
		{"missing report", "exit 0", "read TLS-Anvil results"},
		{
			"failed report with zero exit",
			`printf '%s' '{"FULLY_FAILED":["cookie"]}' > result_map.json`, "FULLY_FAILED: cookie",
		},
		{"cancel", "exec sleep 60", "context deadline exceeded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			outputDir := t.TempDir()
			err := runAnvil(ctx, anvilOptions{binary: "fake-anvil", outputDir: outputDir}, io.Discard,
				func(ctx context.Context, name string, args ...string) *exec.Cmd {
					require.Equal(t, "fake-anvil", name)
					require.Contains(t, args, "-dtls")
					require.Contains(t, args, "-disableTcpDump")

					return exec.CommandContext(ctx, "sh", "-c", test.script) //nolint:gosec
				})
			require.ErrorContains(t, err, test.want)
			reports, err := filepath.Glob(filepath.Join(outputDir, "dtls12-*", "anvil.log"))
			require.NoError(t, err)
			require.Len(t, reports, 1, "retain logs even when the process fails")
		})
	}
}
