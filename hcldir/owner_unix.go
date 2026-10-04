// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package hcldir

import (
	"os"
	"syscall"
)

// keepOwner gives tmp the owner and group the replaced file had, as far as
// this process may, and returns the mode that is still safe to set.
//
// Only root may give a file away, so the owner usually stays this process --
// which could already write the file, so nothing is granted by that. The
// GROUP is different: a file left in this process's group with the old
// group bits would let a group that could not read the old file read the new
// one. So when the group could not be kept, its bits go.
func keepOwner(tmp *os.File, was os.FileInfo, mode os.FileMode) os.FileMode {
	st := was.Sys().(*syscall.Stat_t) // what os.Stat returns on every unix
	if tmp.Chown(int(st.Uid), int(st.Gid)) != nil {
		tmp.Chown(-1, int(st.Gid))
	}
	var now syscall.Stat_t
	if syscall.Fstat(int(tmp.Fd()), &now) != nil {
		return groupSafe(mode, false)
	}
	return groupSafe(mode, now.Gid == st.Gid)
}

// groupSafe is mode, without its group bits unless the file kept its group.
func groupSafe(mode os.FileMode, keptGroup bool) os.FileMode {
	if keptGroup {
		return mode
	}
	return mode &^ 0o070
}
