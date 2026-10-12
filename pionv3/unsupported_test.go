// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import "testing"

func TestPionV3ListenConnectionIDFragmentedServerHello(t *testing.T) {
	t.Skip("Pion v3 lacks the packet-connection listener API used to inject these CID records")
}

func TestPionV3ListenConnectionIDCollisionPreservesAssociation(t *testing.T) {
	t.Skip("Pion v3 lacks the packet-connection listener API used to inject these CID records")
}

func TestPionV3PathMigration(t *testing.T) {
	t.Skip("Pion v3 does not expose path migration control or RRC")
}

func TestPionV3ListenConnectionIDRebindingRequiresRRC(t *testing.T) {
	t.Skip("Pion v3 does not expose path migration control or RRC")
}

func TestPionV3ConnectionStateRoleAndVersion(t *testing.T) {
	t.Skip("Pion v3 does not expose role, negotiated version, or key usage in State")
}

func TestPionV3SupportedGroups(t *testing.T) { t.Skip("Pion v3 does not support DTLS 1.3") }

func TestPionV3DualStackVersionNegotiationSendsClassifiedAlerts(t *testing.T) {
	t.Skip("Pion v3 does not support DTLS 1.3")
}

func TestPionV3HandshakeDiscardsProtectedRecordWithoutRequiredCID(t *testing.T) {
	t.Skip("Pion v3 does not support DTLS 1.3 protected records")
}

func TestPionV3ReceiveBufferSizeLargeDatagram(t *testing.T) {
	t.Skip("Pion v3 does not expose a configurable receive buffer size")
}
