// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package tooling

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrepareInRepoWorkspaceCopiesSourceCheckout(t *testing.T) {
	repoRoot := t.TempDir()
	sourceDTLS := filepath.Join(t.TempDir(), "dtls-source")
	workDir := filepath.Join(t.TempDir(), "dtls-work")
	inRepoFile := filepath.Join(repoRoot, "openssl", "v3", "inrepo", "openssl_inrepo_smoke_test.go")

	require.NoError(t, os.MkdirAll(filepath.Dir(inRepoFile), 0o750))
	require.NoError(t, os.WriteFile(inRepoFile, []byte("package dtls\n"), 0o600))

	require.NoError(t, os.MkdirAll(sourceDTLS, 0o750))
	require.NoError(
		t,
		os.WriteFile(filepath.Join(sourceDTLS, "go.mod"), []byte("module github.com/pion/dtls/v3\n"), 0o600),
	)
	require.NoError(t, os.WriteFile(filepath.Join(sourceDTLS, "conn.go"), []byte("package dtls\n"), 0o600))

	result, err := PrepareInRepoWorkspace(context.Background(), PrepareWorkspaceOptions{
		RepoRoot:       repoRoot,
		DTLSDir:        sourceDTLS,
		Implementation: "openssl",
		WorkDir:        workDir,
	})
	require.NoError(t, err)
	require.Equal(t, workDir, result.WorkspaceDir)

	_, err = os.Stat(filepath.Join(sourceDTLS, "openssl_inrepo_smoke_test.go"))
	require.ErrorIs(t, err, os.ErrNotExist)

	_, err = os.Stat(filepath.Join(workDir, "conn.go"))
	require.NoError(t, err)

	info, err := os.Lstat(filepath.Join(workDir, "openssl_inrepo_smoke_test.go"))
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
}

func TestPrepareWorkspaceFromDirRejectsSameDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/pion/dtls/v3\n"), 0o600))

	err := prepareWorkspaceFromDir(dir, dir, false)
	require.ErrorContains(t, err, "--work-dir must differ from --dtls-dir")
}
