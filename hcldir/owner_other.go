// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package hcldir

import "os"

// keepOwner does nothing where files have no Unix owner and group: on
// Windows what protects a file is its ACL, which this package does not set.
func keepOwner(_ *os.File, _ os.FileInfo, mode os.FileMode) os.FileMode { return mode }
