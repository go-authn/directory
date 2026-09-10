// SPDX-License-Identifier: BSD-3-Clause

//go:build nosql

package hcldir

import (
	"fmt"

	"github.com/go-authn/directory"
)

// Built without SQL: neither a driver nor the code that would read one is in
// this binary. A configuration naming a database is told THAT, which is a
// different thing from naming a driver that does not exist.
func openSQL(Block) (directory.Source, error) {
	return nil, fmt.Errorf("this binary was built without SQL support (-tags nosql)")
}

// Drivers is empty here, so a message listing what is available lists nothing
// rather than three things this binary cannot do.
var Drivers []string
