// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"maps"
	"slices"
	"testing"

	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

type pionCaseConfig struct {
	groups     []elliptic.Curve
	peerGroup  elliptic.Curve
	maxVersion protocol.Version
}

func pionConfigForCase(testCase interopCase) pionCaseConfig {
	config := pionCaseConfig{
		peerGroup:  testCase.group,
		maxVersion: testCase.version,
	}
	if config.peerGroup == 0 {
		config.peerGroup = elliptic.P256
	}
	if testCase.scenario == interopVersionFallback {
		config.maxVersion = protocol.Version1_3
	}
	config.groups = []elliptic.Curve{config.peerGroup}
	if testCase.groupFallback {
		for _, group := range slices.Sorted(maps.Keys(elliptic.Curves())) {
			if group == config.peerGroup ||
				(testCase.version == protocol.Version1_2 && group == elliptic.X25519MLKEM768) {
				continue
			}
			config.groups = append(config.groups, group)
		}
	}

	return config
}

func TestPionCaseGroups(t *testing.T) {
	for _, testCase := range standardInteropCases() {
		if testCase.scenario != interopKeyExchange || testCase.support() != nil {
			continue
		}
		config := pionConfigForCase(testCase)
		require.Equal(t, testCase.group, config.peerGroup)
		require.Equal(t, testCase.group, config.groups[0])
		if testCase.groupFallback {
			require.Greater(t, len(config.groups), 1, testCase.name)
		} else {
			require.Equal(t, []elliptic.Curve{testCase.group}, config.groups, testCase.name)
		}
		if testCase.version == protocol.Version1_2 {
			require.NotContains(t, config.groups, elliptic.X25519MLKEM768)
		}
	}
}

func TestPionCaseVersionBounds(t *testing.T) {
	for _, testCase := range standardInteropCases() {
		config := pionConfigForCase(testCase)
		if testCase.scenario == interopVersionFallback {
			require.Equal(t, protocol.Version1_3, config.maxVersion)
		} else {
			require.Equal(t, testCase.version, config.maxVersion)
		}
	}
}
