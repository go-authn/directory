// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package hcldir

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A file that could not keep its group must not keep its group bits: they
// would now speak for whichever group the process happens to be in.
func TestGroupBitsGoWithTheGroup(t *testing.T) {
	if got := groupSafe(0o640, true); got != 0o640 {
		t.Errorf("kept group: %v", got)
	}
	if got := groupSafe(0o640, false); got != 0o600 {
		t.Errorf("lost group: %v, want 0600", got)
	}
}

// The group a file was given is kept across the rewrite. A new file takes
// the process's group (Linux) or the directory's (BSD, macOS); either way
// not the one an administrator chose, so the test hands the file to another
// group this process belongs to and checks it is still there afterwards.
func TestARewriteKeepsTheGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.hcl")
	if err := os.WriteFile(path, []byte("user \"alice\" { password = \"hunter2\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	groups, _ := os.Getgroups()
	other := -1
	for _, g := range groups {
		if uint32(g) != st.Gid && uint32(g) != uint32(os.Getegid()) {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("this process belongs to no second group to hand the file to")
	}
	if err := os.Chown(path, -1, other); err != nil {
		t.Skipf("cannot hand the file to group %d here: %v", other, err)
	}
	if err := SetPassword([]string{path}, "alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Gid) != other {
		t.Errorf("the file was group %d and is group %d after a password change", other, st.Gid)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("the file is %v, want 0640", fi.Mode().Perm())
	}
}
