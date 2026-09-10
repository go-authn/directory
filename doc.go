// SPDX-License-Identifier: BSD-3-Clause

// Package directory answers three questions about the people a server serves:
// who is here, what proves them, and who is in which group.
//
// The answers come from wherever a site already keeps them — a database, an
// LDAP server, a file, or the program's own configuration — and every source
// answers the same three questions, so the code that USES an identity never
// learns where it came from.
//
// # What proves somebody is not one thing
//
// This is the whole reason the package exists, and it is a fact about
// protocols rather than a design choice:
//
//	NTLMv2 (SMB, Windows file sharing) is a CHALLENGE-RESPONSE. The client
//	never sends the password, so the server must compute MD4(UTF16LE(password))
//	itself. An LDAP bind cannot answer it. Neither can a bcrypt. What answers
//	it is the password, or that MD4 — the "NT hash", which is exactly what
//	Samba's sambaNTPassword attribute holds.
//
//	HTTP Basic, and anything else that hands the server the password, can be
//	answered by ANY verifier: a comparison, a hash, or a bind against a
//	directory that holds the secret and will not give it up.
//
//	SSH authenticates with a public key, or a certificate from an authority.
//	No password is involved at all, and a directory publishes the keys —
//	OpenSSH's convention is the sshPublicKey attribute.
//
// So an [Identity] carries what its source could give, each protocol uses what
// it can, and [Identity.Can] says which is which. A server can then tell a
// person "you can use WebDAV and SFTP, and not SMB, because this directory
// holds a bcrypt" — before they meet a refusal at a mount.
//
// # Reading is done once
//
// A source is read when the server starts, and a change to it is picked up by
// a restart. That is a deliberate limit rather than an oversight: the
// alternative is asking the directory on every connection, which is a
// different design with different failure modes (a server that stops
// authenticating when the database blinks), and this package says which one it
// is rather than implying.
//
// The exception is a PASSWORD CHECK: [Identity.Verify] may reach the source
// every time, because a bind is the only way an LDAP directory will answer
// "is this the right password" and it cannot be cached without holding the
// secret this package went out of its way not to hold.
package directory
