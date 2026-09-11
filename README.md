# directory

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/directory.svg)](https://pkg.go.dev/github.com/go-authn/directory)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/directory/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/directory/actions/workflows/ci.yml)

**Who somebody is and what proves them — one model over a database, an LDAP
server, or a list you hold yourself.** Pure Go, `CGO_ENABLED=0`, no driver
dependencies in the core.

```go
people := directory.NewSet(
    &directory.Static{Name: "the configuration file", People: local},
    sqlSource,   // github.com/go-authn/directory/sqldir
    ldapSource,  // github.com/go-authn/directory/ldapdir
)

for _, id := range must(people.Identities()) {
    fmt.Println(id.Name(), id.Can(directory.NTHash), id.Can(directory.PublicKeys))
}
```

## What proves somebody is not one thing

This is why the package exists, and it is a fact about protocols rather than a
design choice.

| | needs | so it can come from |
|---|---|---|
| **NTLMv2** (SMB, Windows file sharing) | the password, or **MD4(UTF16LE(password))** — the "NT hash" | a password you hold, or `sambaNTPassword` |
| **HTTP Basic**, and anything that hands the server the password | any verifier | a comparison, a hash, or an **LDAP bind** |
| **SSH** | a public key or a certificate | `sshPublicKey`, or a column |
| **a second factor** (RFC 6238) | the shared secret behind the six digits | a column, or an attribute you name |

NTLMv2 is a challenge-response: the client never sends the password, so the
server computes `MD4(UTF16LE(password))` itself. **An LDAP bind cannot
authenticate an SMB session**, and neither can a bcrypt. That is why Samba's
own schema has `sambaNTPassword`, and why `Identity.Can` exists — so a server
can tell somebody "you can use WebDAV and SFTP, not SMB, because this directory
holds a bcrypt" *before* they meet a refusal at a mount.

And plainly in the other direction: the NT hash **is** the credential. Anybody
holding it authenticates as that person exactly as if they held the password.

## The sources

| package | reads | dependencies |
|---|---|---|
| `directory` | a `Static` list you build | **none** |
| `directory/sqldir` | any `*sql.DB`, with **your** queries | none — the driver is yours to pick |
| `directory/ldapdir` | an LDAP server | `go-ldap/ldap/v3` |
| `directory/hcldir` | a `users` block from a configuration file | none — the struct tags are inert |
| `directory/ldaptest` | *(an LDAP directory to test against)* | `glauth/ldap` |

A one-time-code secret is a credential like the others — `Can(TOTPSecret)`,
`Identity.TOTPSecret()` — and like the NT hash it **is** the credential:
whoever holds it produces every future code. `sqldir` reads it from a fifth
column; `ldapdir` reads it from an attribute you name, with **no default**,
because there is no standard one (FreeIPA has `ipatokenOTPkey`, other schemas
have `oathSecret`) and a guess would read nothing while looking like it had
looked. [go-authn/totp](https://github.com/go-authn/totp) is what checks a code
against it.

`sqldir` takes queries rather than a schema, because a site whose people are
already in a database has them in *its* shape; a schema this package invented
would mean copying them into a second one that goes stale. It takes an
`*sql.DB` rather than a DSN, so a program that wants SQLite does not carry
PostgreSQL.

## The `users` block

Two programs had written the same block — a file server deciding who may mount
a share, and an authentication server answering for them both — so it lives
here once:

```hcl
users "sql" {
  driver   = "postgres"               # or sqlite, or mysql
  dsn_file = "/etc/authnd/dsn"        # a DSN holds a password: it lives in a file
  users    = "select login, nt_hash, ssh_keys from staff"
  groups   = "select team, member from team_members"
}

users "ldap" {
  url                = "ldaps://ldap.example.org"
  base_dn            = "ou=people,dc=example,dc=org"
  bind_dn            = "cn=reader,dc=example,dc=org"
  bind_password_file = "/etc/authnd/bind.pw"
}
```

```go
src, err := hcldir.Open(block)      // or hcldir.OpenAll(blocks)
```

`hcldir` imports **no HCL library**: the struct tags are inert strings, so the
caller decodes — with `gohcl`, or by hand — and hands the block over. Nor does
it import a database driver: a program blank-imports the ones it wants, and a
binary that imported none is told exactly that rather than "unknown driver",
because the fix is one line in the program and not in the configuration.

Two build tags leave a kind out entirely: `-tags nosql` and `-tags noldap`. For
the program that uses this, `nosql` is usually the biggest single lever it has
— the three database drivers weigh about 12 MB.

## Testing against a directory

`directory/ldaptest` is an LDAP server to test against, since three packages
had written the same fixture and one of them is a file server in another
organisation:

```go
d, _ := ldaptest.NewServer(&ldaptest.Directory{
    People: map[string]ldaptest.Person{
        "dora": {Password: "hunter2", NTHash: hex.EncodeToString(directory.NTHashOf("hunter2"))},
        "eli":  {Password: "swordfish"},   // a bind, and nothing else
    },
    Groups: map[string][]string{"engineers": {"dora", "eli"}},
})
defer d.Close()
```

It is `glauth/ldap` underneath — an independent implementation — and it is
itself read by **OpenLDAP's own `ldapsearch`** in CI, because a fixture built
from one reading of a protocol can only ever confirm that reading. `d.Binds()`
counts binds, so "this password was checked against the directory" is something
a test can show rather than assume.

## Groups

A group is written `@staff` wherever a person could be — Samba's spelling,
which anybody administering a file server types without being told:

```go
allowed, err := directory.Expand([]string{"@staff", "alice"}, people)
```

Listing the groups is a **different question** from asking about one, and a
source may answer the second and not the first — an LDAP directory can permit
a lookup and refuse an enumeration. So `Set.GroupNames()` reads the sources
that *can* list (the optional `GroupLister`) and skips the rest: a server
publishing a list of groups can honestly publish fewer than `Members` would
answer for, and a server checking membership keeps asking `Members`.

A group with **nobody in it** is refused rather than expanded to nothing: a
configuration that grants nothing to nobody reads exactly like one that works.
A group **no source has** is an error, not an empty list, for the same reason —
and a source that is *broken* is distinguished from one that simply lacks the
group, because that is the difference between a wrong configuration and a
database that is down.

## Several sources, in order

The first source that knows a name owns it. A site with its people in LDAP and
one service account written down locally should not have to put the service
account in LDAP — and adding somebody to LDAP must not break a server that has
them written down. Group membership, by contrast, is the **union**: a group can
have people from both, and returning only the first half would silently exclude
the rest.

## Reading is done once

Sources are read when a server starts; a change is picked up by a restart. That
is a deliberate limit, not an oversight — asking the directory on every
connection is a different design with different failure modes (a server that
stops authenticating when the database blinks). The exception is a **password
check**, which may reach the source every time: a bind is the only way an LDAP
directory answers "is this the right password", and it cannot be cached without
holding the secret this package went out of its way not to hold.

## Verified against real things

- **MD4** against RFC 1320's own test vectors, and the NT hash of `password`
  against the value every article about NTLM quotes.
- **`sqldir`** against a real SQLite database through a real driver: actual SQL,
  actual `NULL`s deciding what each person can be proved with.
- **`ldapdir`** against an **independent LDAP server** (`glauth/ldap`) rather
  than a fake — a fake built from my own reading of the protocol could only
  confirm that reading. The fixture deliberately allows the **unauthenticated
  bind** (an empty password, which a real directory answers with *success*), so
  the test fails if this package ever stops refusing it first.
- **`ldaptest`** — the fixture itself — against **OpenLDAP's `ldapsearch`**,
  which knows nothing about this module: it reads the entries, the
  `sambaNTPassword` of the one person who has it, and the group; it binds as a
  person and is refused with *Invalid credentials (49)* for a wrong password.

## Licence

BSD-3-Clause.
