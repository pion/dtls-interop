// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestStandardInteropCases(t *testing.T) {
	names := map[string]bool{}
	for _, testCase := range standardInteropCases() {
		require.False(t, names[testCase.name], "duplicate case %s", testCase.name)
		names[testCase.name] = true
	}
	for _, version := range []string{"DTLS12", "DTLS13"} {
		for _, role := range []interopRole{interopPionClient, interopPionServer} {
			for group := range elliptic.Curves() {
				for _, mode := range []string{"WithFallback", "WithoutFallback"} {
					name := version + "/" + string(role) + "/KeyExchange/" + mode + "/" + group.String()
					require.True(t, names[name], "missing case %s", name)
				}
			}
		}
	}
}

func TestInteropBackendDispatch(t *testing.T) {
	for _, test := range []struct {
		name       string
		scenario   interopScenario
		version    protocol.Version
		versionErr error
		wantErr    error
		wantRun    bool
	}{
		{"supported", interopHandshake, protocol.Version1_3, nil, nil, true},
		{"unsupported", interopHandshake, protocol.Version1_2, errInteropNotSupported, errInteropNotSupported, false},
		{"unimplemented", interopHandshake, protocol.Version1_2, errInteropNotImplemented, errInteropNotImplemented, false},
		{"unknown scenario", "NewScenario", protocol.Version1_2, nil, errInteropUnregistered, false},
		{
			"unknown scenario on skipped version", "NewScenario", protocol.Version1_2,
			errInteropNotSupported, errInteropUnregistered, false,
		},
		{"undeclared version", interopHandshake, protocol.Version1_2, nil, errInteropUnregistered, false},
		{"protocol restriction", interopKeyUpdatePion, protocol.Version1_2, nil, errInteropNotSupported, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ran := false
			run := func(*testing.T, interopCase) error {
				ran = true

				return nil
			}
			backend := interopBackend{
				version:      protocol.Version1_3,
				otherVersion: test.versionErr,
				scenarios:    map[interopScenario]interopRun{interopHandshake: run, interopKeyUpdatePion: run},
			}
			err := backend.run(t, interopCase{scenario: test.scenario, version: test.version})
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, test.wantRun, ran)
		})
	}
}
