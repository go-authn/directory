// SPDX-License-Identifier: BSD-3-Clause

package hcldir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-authn/directory"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// ErrNotDeclared is somebody these files do not write down.
//
// ⛔ It is NOT "no such person". A name that reaches here may exist perfectly
// well in a sql or ldap directory the same server also reads; what it does not
// have is a sentence in a file we own. Saying "no such person" would be a
// different claim, and a wrong one -- and the server that says it is usually
// serving that person happily.
var ErrNotDeclared = errors.New("not written down in these configuration files")

// SetPassword writes a new password for somebody declared in a user block.
//
// It belongs here, with [UserBlock], for the reason that comment gives: the
// block lived twice and drifted. A write that lived in one server and not the
// other would drift the same way, and worse -- the two would disagree about
// what a password change DOES.
//
// ⛔ The parsed blocks cannot do this. They say alice has a password; they do
// not say which of five files holds the sentence, nor whether that sentence is
// `password` or `password_file`. So the files are re-parsed with hclwrite --
// which keeps comments, ordering and spacing that re-rendering from the struct
// would quietly discard -- and the one block found is edited.
func SetPassword(files []string, name, password string) error {
	if password == "" {
		return errors.New("an empty password would let anybody in as this person")
	}
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		f, diags := hclwrite.ParseConfig(src, path, hcl.InitialPos)
		if diags.HasErrors() {
			return fmt.Errorf("%s: %s", path, diags.Error())
		}
		blk := userBlockIn(f, name)
		if blk == nil {
			continue
		}
		return writePassword(path, f, blk, name, password)
	}
	return fmt.Errorf("user %q: %w", name, ErrNotDeclared)
}

// userBlockIn is the `user "<name>"` block in this file, or nil.
func userBlockIn(f *hclwrite.File, name string) *hclwrite.Block {
	for _, blk := range f.Body().Blocks() {
		if blk.Type() != "user" {
			continue
		}
		if labels := blk.Labels(); len(labels) == 1 && labels[0] == name {
			return blk
		}
	}
	return nil
}

// writePassword puts the password where THAT person's block keeps it.
func writePassword(path string, f *hclwrite.File, blk *hclwrite.Block, name, password string) error {
	body := blk.Body()
	fileAttr := body.GetAttribute("password_file")
	hasInline := body.GetAttribute("password") != nil
	hasHash := body.GetAttribute("nt_hash") != nil

	// ⛔ A person holding only an nt_hash cannot be given a password here
	// without changing WHAT PROVES THEM: the block would start answering S3
	// and WebDAV, which it could not before, because SigV4 computes an HMAC
	// from the password itself and an NT hash cannot produce one. That is a
	// change to the configuration, not to a password.
	if fileAttr == nil && !hasInline && hasHash {
		return fmt.Errorf("user %q holds an nt_hash and no password: "+
			"setting one here would change what can prove them, which is a "+
			"change to the configuration rather than to a password", name)
	}
	if fileAttr == nil && !hasInline {
		return fmt.Errorf("user %q: %w", name, ErrNotDeclared)
	}

	// ⛔ An nt_hash beside a password is DERIVED from it, so writing one
	// without the other leaves a block whose two credentials disagree: the
	// new password would open WebDAV and S3 while SMB went on accepting the
	// OLD one, and nothing would report it.
	//
	// This branch is reachable HERE and is not in go-authn/authnd, which
	// refuses a block carrying both. fileshare allows it, and this package
	// serves both -- which is the whole argument for the code living here
	// rather than in either server.
	if hasHash {
		body.SetAttributeValue("nt_hash", cty.StringVal(
			fmt.Sprintf("%x", directory.NTHashOf(password))))
	}

	if fileAttr != nil {
		// The password lives in a file on purpose -- so that it is not in a
		// configuration somebody prints, pastes or commits. Writing it inline
		// now would undo that silently, so the FILE is what changes.
		target, err := attrString(fileAttr)
		if err != nil {
			return fmt.Errorf("user %q: password_file: %w", name, err)
		}
		if hasHash {
			// The hash changed, so the configuration changed too.
			if err := replaceFile(path, f.Bytes(), 0o644); err != nil {
				return err
			}
		}
		// ⛔ 0600 is asked for, and on Windows it is not honoured: that
		// platform has no Unix permission bits and the file ends up readable
		// by anyone who can reach it. Saying so here rather than letting the
		// mode argument imply a guarantee it cannot keep -- a deployment
		// that needs the secret protected there needs an ACL, which is not
		// something this package sets.
		return replaceFile(target, []byte(password+"\n"), 0o600)
	}
	body.SetAttributeValue("password", cty.StringVal(password))
	return replaceFile(path, f.Bytes(), 0o644)
}

// attrString is the literal string an attribute is set to.
//
// hclwrite does not evaluate: it hands back tokens. A password_file written as
// a plain quoted string is the case that matters, and anything else -- an
// interpolation, a variable -- is refused rather than guessed at, because
// writing through a path we mis-read writes somebody's password to the wrong
// file.
func attrString(a *hclwrite.Attribute) (string, error) {
	toks := a.Expr().BuildTokens(nil)
	if len(toks) != 3 ||
		toks[0].Type != hclsyntax.TokenOQuote ||
		toks[1].Type != hclsyntax.TokenQuotedLit ||
		toks[2].Type != hclsyntax.TokenCQuote {
		return "", errors.New("is not a plain quoted path, so it is not safe to write through")
	}
	return string(toks[1].Bytes), nil
}

// replaceFile writes content where path is, atomically.
//
// ⛔ Through a temporary file in the SAME directory and a rename, because the
// alternative loses somebody's password on a full disk or a crash: a truncate
// that then fails to write leaves a file that exists, parses, and locks the
// person out. A rename either happened or did not.
func replaceFile(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hcldir-*")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return os.Rename(name, path)
}
