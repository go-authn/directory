// SPDX-License-Identifier: BSD-3-Clause

//go:build noldap

package hcldir

import (
	"fmt"

	"github.com/go-authn/directory"
)

// Built without LDAP: no LDAP client is in this binary.
func openLDAP(Block) (directory.Source, error) {
	return nil, fmt.Errorf("this binary was built without LDAP support (-tags noldap)")
}
