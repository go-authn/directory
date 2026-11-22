//go:build !windows

package hcldir_test

import "testing"

// ownerOnly is the mode 0600 the file was written with, off Windows.
func ownerOnly(*testing.T, string) {}
