// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package tooling

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommandOutputMergesEnv(t *testing.T) {
	t.Setenv("TOOLING_ENV_BASE", "base")

	output, err := commandOutput(
		context.Background(),
		"",
		io.Discard,
		[]string{"TOOLING_ENV_OVERRIDE=override"},
		"env",
	)
	require.NoError(t, err)
	require.Contains(t, output, "TOOLING_ENV_BASE=base")
	require.Contains(t, output, "TOOLING_ENV_OVERRIDE=override")
}
