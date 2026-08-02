// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunRejectsUnknownMode(t *testing.T) {
	err := run(
		context.Background(),
		[]string{"-mode", "unknown"},
		io.Discard,
		nil,
	)
	require.ErrorIs(t, err, errUnknownMode)
}
