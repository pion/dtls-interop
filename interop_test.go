// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import "testing"

func TestBoringSSLInterop(t *testing.T) { runInteropSuite(t, runBoringSSLCase) }

func TestOpenSSL3Interop(t *testing.T) { runInteropSuite(t, runOpenSSLCase) }

func TestWolfSSLInterop(t *testing.T) { runInteropSuite(t, runWolfSSLCase) }

func TestPionV3Interop(t *testing.T) { runInteropSuite(t, runPionV3Case) }
