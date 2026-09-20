// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

var (
	errInteropNotSupported   = errors.New("not supported")
	errInteropNotImplemented = errors.New("not implemented")
)

type interopScenario string

const (
	interopHandshake        interopScenario = "Handshake"
	interopKeyExchange      interopScenario = "KeyExchange"
	interopVersionFallback  interopScenario = "VersionFallback"
	interopKeyUpdatePion    interopScenario = "KeyUpdate/PionInitiated"
	interopKeyUpdatePeer    interopScenario = "KeyUpdate/PeerInitiated"
	interopCID              interopScenario = "CID"
	interopCIDRebinding     interopScenario = "CID/Rebinding"
	interopCIDPolicyDiscard interopScenario = "CID/PolicyDiscard"
	interopWebRTC           interopScenario = "WebRTC"
)

type interopRole string

const (
	interopPionClient interopRole = "PionClient"
	interopPionServer interopRole = "PionServer"
)

type interopCIDOptions struct {
	name           string
	pionCIDEnabled bool
	pionReceiveCID []byte
	peerCIDEnabled bool
	peerReceiveCID string
}

// interopCase describes behavior.
type interopCase struct {
	name          string
	scenario      interopScenario
	version       protocol.Version
	role          interopRole
	group         elliptic.Curve
	groupFallback bool
	cid           interopCIDOptions
	mtu           string
}

type interopBackend func(*testing.T, interopCase) error

func runInteropSuite(t *testing.T, backend interopBackend) {
	t.Helper()
	for _, testCase := range standardInteropCases() {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.support()
			if err == nil {
				err = backend(t, testCase)
			}
			if errors.Is(err, errInteropNotSupported) || errors.Is(err, errInteropNotImplemented) {
				t.Skip(err)
			}
			require.NoError(t, err)
		})
	}
}

func standardInteropCases() []interopCase {
	var cases []interopCase
	for _, version := range []struct {
		name  string
		value protocol.Version
	}{
		{"DTLS12", protocol.Version1_2},
		{"DTLS13", protocol.Version1_3},
	} {
		for _, role := range []interopRole{interopPionClient, interopPionServer} {
			for _, scenario := range standardInteropScenarios() {
				scenario.version = version.value
				scenario.role = role
				scenario.name = version.name + "/" + string(role) + "/" + scenario.name
				cases = append(cases, scenario)
			}
		}
	}

	return cases
}

func standardInteropScenarios() []interopCase {
	cases := []interopCase{
		{name: "Handshake", scenario: interopHandshake},
		{name: "VersionFallback", scenario: interopVersionFallback},
		{name: "CID/Rebinding", scenario: interopCIDRebinding},
		{name: "CID/PolicyDiscard", scenario: interopCIDPolicyDiscard},
		{name: "WebRTC/DefaultMTU", scenario: interopWebRTC},
		{name: "WebRTC/Fragmented", scenario: interopWebRTC, mtu: "256"},
	}
	for _, group := range slices.Sorted(maps.Keys(elliptic.Curves())) {
		cases = append(cases,
			interopCase{
				name:     "KeyExchange/WithFallback/" + group.String(),
				scenario: interopKeyExchange, group: group, groupFallback: true,
			},
			interopCase{
				name:     "KeyExchange/WithoutFallback/" + group.String(),
				scenario: interopKeyExchange, group: group,
			},
			interopCase{
				name:     "KeyUpdate/PionInitiated/" + group.String(),
				scenario: interopKeyUpdatePion, group: group,
			},
			interopCase{
				name:     "KeyUpdate/PeerInitiated/" + group.String(),
				scenario: interopKeyUpdatePeer, group: group,
			},
		)
	}
	for _, cid := range []interopCIDOptions{
		{name: "NoCID"},
		{name: "ZeroLength", pionCIDEnabled: true, peerCIDEnabled: true},
		{
			name: "NonZero", pionCIDEnabled: true, peerCIDEnabled: true,
			pionReceiveCID: []byte("pion-cid"), peerReceiveCID: "peer-id",
		},
		{
			name: "PionZeroLength_PeerNonZero", pionCIDEnabled: true, peerCIDEnabled: true,
			peerReceiveCID: "peer-id",
		},
		{
			name: "PionNonZero_PeerZeroLength", pionCIDEnabled: true, peerCIDEnabled: true,
			pionReceiveCID: []byte("pion-cid"),
		},
	} {
		cases = append(cases, interopCase{name: "CID/" + cid.name, scenario: interopCID, cid: cid})
	}

	return cases
}

func (testCase interopCase) support() error {
	if testCase.version == protocol.Version1_2 {
		if testCase.group == elliptic.X25519MLKEM768 ||
			testCase.scenario == interopKeyUpdatePion || testCase.scenario == interopKeyUpdatePeer {
			return fmt.Errorf("%w: requires DTLS 1.3", errInteropNotSupported)
		}
	}
	if testCase.scenario == interopVersionFallback && testCase.version != protocol.Version1_2 {
		return fmt.Errorf("%w: version fallback targets DTLS 1.2", errInteropNotSupported)
	}

	return nil
}
