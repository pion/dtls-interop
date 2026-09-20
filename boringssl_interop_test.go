// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/protocol"
)

func boringSSLInterop() interopBackend {
	notImplemented := skipInterop(errInteropNotImplemented, "BoringSSL adapter")

	return interopBackend{
		version:      protocol.Version1_3,
		otherVersion: errInteropNotImplemented,
		scenarios: map[interopScenario]interopRun{
			interopHandshake:        runBoringSSLCase,
			interopKeyExchange:      runBoringSSLCase,
			interopKeyUpdatePion:    runBoringSSLCase,
			interopKeyUpdatePeer:    runBoringSSLCase,
			interopVersionFallback:  notImplemented,
			interopCID:              notImplemented,
			interopCIDRebinding:     notImplemented,
			interopCIDPolicyDiscard: notImplemented,
			interopWebRTC:           notImplemented,
		},
	}
}

func runBoringSSLCase(t *testing.T, testCase interopCase) error {
	t.Helper()
	config := pionConfigForCase(testCase)
	options := boringSSLProbeOptions{
		keyExchangeGroup:      config.peerGroup,
		pionKeyExchangeGroups: config.groups,
		checkConnection:       testCase.checkConnection,
	}
	if testCase.scenario == interopKeyUpdatePion {
		options.pionKeyUpdate = updatePionKeys
	}
	options.boringSSLKeyUpdate = testCase.scenario == interopKeyUpdatePeer
	probe := probeBoringSSL13PionClientWithOptions
	if testCase.role == interopPionServer {
		probe = probeBoringSSL13PionServerWithOptions
	}
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	var output bytes.Buffer
	err := probe(ctx, environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"),
		&output, exec.CommandContext, options)
	if output.Len() != 0 {
		t.Log(strings.TrimSpace(output.String()))
	}

	return err
}

func updatePionKeys(ctx context.Context, connection *dtls.Conn) error {
	return connection.UpdateKeys(ctx, dtls.KeyUpdateOptions{RequestPeerUpdate: true})
}
