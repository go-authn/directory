// SPDX-License-Identifier: BSD-3-Clause

//go:build !noldap

package hcldir

import (
	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
)

// openLDAP connects once, to find out whether the directory is there at all.
func openLDAP(b Block) (directory.Source, error) {
	cfg := ldapdir.Config{
		URL: b.URL, BaseDN: b.BaseDN, BindDN: b.BindDN,
		UserFilter: b.UserFilter, UserAttribute: b.UserAttribute,
		GroupBaseDN: b.GroupBaseDN, GroupFilter: b.GroupFilter,
		GroupAttribute: b.GroupAttribute, MemberAttribute: b.MemberAttribute,
		TOTPAttribute: b.TOTPAttribute,
		StartTLS:      b.StartTLS,
	}
	if b.BindPasswordFile != "" {
		pw, err := secretFile(b.BindPasswordFile, "the bind password")
		if err != nil {
			return nil, err
		}
		cfg.BindPassword = pw
	}
	return ldapdir.New(cfg)
}
