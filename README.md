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

So an `Identity` answers each protocol with its own method:

- `Verify(password)` for anything that is handed the password. It prefers the
  verifier a source gave (which may be an LDAP bind), and falls back to a held
  password compared in constant time, on SHA-256 digests so that not even the
  length leaks.
- `NTKey()` for NTLMv2: from the hash a source published, or derived from the
  password; `ErrNoCredential` when it has neither.
- `KerberosKey(derive)` for a KDC, which only an identity carrying the password
  can answer: a KDC has to DECRYPT with the key, and a yes from a verifier is
  not one.

A database whose passwords are bcrypt, argon2 or anything else is read with
`sqldir.WithPasswordCheck(func(db, name, password) error)`. Without it, a
password column is compared as it stands.

## Attributes: what describes somebody, and proves nothing

A server publishing `posixAccount` (RFC 2307), `posixGroup` and
`inetOrgPerson` (RFC 2798) entries needs more than credentials: a
`uidNumber`, a `homeDirectory`, a `mail`. These are **attributes**, kept apart
from credentials on purpose — a credential decides who may log in, an
attribute is *published* to everybody allowed to search.

```go
a, err := directory.NewAttributes(
    directory.Attribute{Name: "uidNumber", Values: []string{"1000"}},
    directory.Attribute{Name: "homeDirectory", Values: []string{"/home/alice"}},
    directory.Attribute{Name: "mail", Values: []string{"alice@example.org", "a.liddell@example.org"}},
)
id := directory.NewIdentity("alice", directory.WithPassword("s3cret"), directory.WithAttributes(a))

id.Attributes().Get("UIDNUMBER")   // ["1000"]: case-insensitive, as LDAP is
id.Attributes().Names()            // [uidNumber homeDirectory mail]: in order
```

- Names are **RFC 4512 attribute descriptions** in descriptor form, with
  optional options: `mail`, `description;lang-fr`. The type and options are
  case-insensitive and the order of the options does not matter (§2.5). The
  numeric form (`2.5.4.35`) is refused: refusals are by name, and
  `2.5.4.35` *is* `userPassword`.
- Values are **strings** and are not interpreted: `"0100"` stays `"0100"`. An
  empty value, or none, is refused; an exact repeat is kept once.
- An `Attributes` is immutable, and can only be built by `NewAttributes`, so
  one that exists has been checked. `CheckAttributeName` applies the same rule
  on its own, for a configuration to refuse before anything is read.

### What can never be an attribute

| refused | why |
|---|---|
| `userPassword`, `authPassword`, `userPKCS12`, `sambaNTPassword`, `sambaLMPassword`, `unicodePwd`, `krbPrincipalKey`, `ipaNTHash`, `ipatokenOTPkey`, `oathSecret`, … (56 secrets; `ReservedAttributes()` returns the whole refusal list, 75 names, with reasons) | a secret, read off RFC 4519, RFC 3112, RFC 2798 and the Samba, Active Directory, MIT and Heimdal Kerberos, FreeIPA, 389-ds and OpenLDAP schemas |
| any name containing `password`, `passwd`, `pwd`, `secret`, `credential`, `hash`, `privatekey` | a list only knows the schemas somebody read; the one standard name this would catch, `secretary` (RFC 4524), is allowed |
| `sshPublicKey` | it has its own path, `WithPublicKeys`, so `Can(PublicKeys)` stays true |
| `uid`, `userid`, `cn`, `commonName`, `objectClass` | the server derives them from the name it publishes the entry under |
| `member`, `uniqueMember`, `memberUid`, `memberOf` | membership is what `Members` answers; a second answer would disagree |
| `createTimestamp`, `modifyTimestamp`, `creatorsName`, `modifiersName`, `structuralObjectClass`, `governingStructureRule`, `subschemaSubentry`, `entryDN`, `entryUUID` | the server maintains them; a configuration could only forge them |

### Group attributes

A source may also describe its groups, through the optional
`GroupAttributer` (`GroupAttributes(group) (Attributes, error)`). A source that
does not implement it still compiles and behaves as before.
`Set.GroupAttributes` asks every source: **the first source to give an
attribute owns it**, so a `gidNumber` in a local file overrides the
directory's while a `description` only the directory has comes through. Values
are never merged across sources. A source without `GroupAttributer` is asked
`Members`, to learn whether it has the group at all. Unlike `Members`, a
**broken source is an error** even when another answered: the missing source
may be the one whose `gidNumber` should have won.

A person's attributes come with the person, from the source that owns the
name — a `Set` does not assemble somebody out of two sources.

## The sources

| package | reads | dependencies |
|---|---|---|
| `directory` | a `Static` list you build | **none** |
| `directory/sqldir` | any `*sql.DB`, with **your** queries | none — the driver is yours to pick |
| `directory/ldapdir` | an LDAP server | `go-ldap/ldap/v3` |
| `directory/hcldir` | a `users` block naming a database or an LDAP server, **and** `user`/`group` blocks holding the people themselves | `golang.org/x/crypto/ssh`, to parse an authorized_keys line; `hashicorp/hcl/v2` and `zclconf/go-cty`, to rewrite a file in place (`SetPassword`) |
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
  users    = "select login, null, nt_hash, ssh_keys from staff"   # by position: name, password, nt_hash, ssh_keys, totp_secret
  groups   = "select team, member from team_members"

  # optional, read by column ALIAS: the first column is the name
  users_attributes  = "select login, uid_number as \"uidNumber\", home as \"homeDirectory\", m.address as mail from staff left join mails m using (login)"
  groups_attributes = "select team, gid as \"gidNumber\" from teams"
}

users "ldap" {
  url                = "ldaps://ldap.example.org"
  base_dn            = "ou=people,dc=example,dc=org"
  bind_dn            = "cn=reader,dc=example,dc=org"
  bind_password_file = "/etc/authnd/bind.pw"
  attributes         = ["mail", "uidNumber", "homeDirectory"]   # copied from each person's entry
  group_attributes   = ["gidNumber"]                            # and from each group's
}

user "alice" {
  password_file = "/etc/authnd/alice.pw"
  attributes = {
    uidNumber     = "1000"                  # a string: LDAP values are strings
    homeDirectory = "/home/alice"
    mail          = ["alice@example.org", "a.liddell@example.org"]
    "description;lang-fr" = "une personne"
  }
}

group "staff" {
  members    = ["alice", "bob"]
  attributes = { gidNumber = "100", description = "the people who work here" }   # a posixGroup needs a gidNumber
}
```

**The SQL attributes queries** (`sqldir.Queries.PeopleAttributes` and
`GroupAttributes`) are optional, and the positional `users` and `groups`
queries are unchanged — a sixth positional column is still refused, because
attributes come by *name*, in their own query. Every column after the first is
an attribute named by its alias; a column whose alias is not an attribute
description (an unaliased expression) or names a credential is refused, with
its column number, before a row is read. `NULL` and `''` are absent. A name may
come back on several rows, and the values of all of them are kept — a join to a
table of addresses gives a person several. A group named only in
`groups_attributes` **exists**, with nobody in it: that is how a person's own
primary group is written, and `Members` then answers `[]`.

⛔ **The case of an alias is the database's.** PostgreSQL folds an unquoted
alias to lower case: `as uidNumber` comes back as `uidnumber`. Attribute names
are case-insensitive, so it is the same attribute and `Get("uidNumber")` finds
it — but the spelling a server prints is the database's. Quote the alias
(`as "uidNumber"`) where the spelling matters. SQLite keeps an alias as
written.

**The `attributes` map** in `user` and `group` blocks takes a string or a list
of strings per name; `null` leaves an attribute out. A number is refused with
the fix in the message (`write it as a string, "1000"`): this package does not
choose how a number is spelled. The decoder hands it over as a `cty.Value`.

**ldapdir** copies the names listed in `attributes` / `group_attributes`
(`ldapdir.Config.Attributes`, `GroupAttributes`), matching the directory's
spelling by RFC 4512 equivalence and keeping the configured one. It refuses,
at `New` and in `Block.Check`, anything `CheckAttributeName` refuses, and also
the `totp_attribute` (a secret under a name only this configuration knows), the
group member attribute and the group naming attribute. Subtypes the directory
returns besides (`description;lang-fr` for `description`) are not copied: ask
for them by name.

```go
src, err := hcldir.Open(block)      // or hcldir.OpenAll(blocks)
```

`hcldir` **does not decode**: the struct tags are inert strings, so the caller
decodes — with `gohcl`, or by hand — and hands the block over. It does import
HCL, since v0.10.0, but only to *write*: `SetPassword` edits the file that
declares a person with `hclwrite`, which keeps its comments, ordering and spacing. Nor does
it import a database driver: a program blank-imports the ones it wants, and a
binary that imported none is told exactly that rather than "unknown driver",
because the fix is one line in the program and not in the configuration.

Two build tags leave a kind out entirely: `-tags nosql` and `-tags noldap`. For
the program that uses this, `nosql` is usually the biggest single lever it has
— the three database drivers weigh about 12 MB.

### Who an LDAP directory's people are: the defaults

| setting (`users "ldap"` / `ldapdir.Config`) | default |
|---|---|
| `user_filter` / `UserFilter` | `(\|(objectClass=posixAccount)(objectClass=account)(objectClass=uidObject))` — `ldapdir.DefaultUserFilter` |
| `user_attribute` / `UserAttribute` | `uid` |
| `group_base_dn` / `GroupBaseDN` | `base_dn` |
| `group_filter` / `GroupFilter` | `(objectClass=posixGroup)` |
| `group_attribute` / `GroupAttribute` | `cn` |
| `group_member_attribute` / `MemberAttribute` | `memberUid` |

The three classes are the standard ones that carry a `uid`: `posixAccount`
(RFC 2307, a person with a uidNumber, gidNumber and home directory), `account`
(RFC 4524 §3.1) and `uidObject` (RFC 4519 §3.14).
[go-authn/authnd](https://github.com/go-authn/authnd) publishes a person
without the POSIX attributes as an `account` or an `inetOrgPerson`, and puts
`uidObject` on every person; under the old default such a person was not read
at all.

⛔ **The default user filter is WIDER than it was up to v0.13.0**, which was
`(objectClass=posixAccount)`. A directory holding `account` or `uidObject`
entries that are not posixAccounts — service accounts, hosts named by uid,
people imported from elsewhere — now gives them to every program that kept
the default, and those people can then be checked against the directory by a
bind. A plain `inetOrgPerson` with none of the three classes is still not read
(`TestTheDefaultUserFilter`). To keep exactly the old set, write the old filter:

```hcl
users "ldap" {
  # ...
  user_filter = "(objectClass=posixAccount)"
}
```

### An LDAP directory is reached over TLS

Every password checked against an LDAP directory is a simple bind, and a simple
bind carries the password itself (RFC 4513 §5.1.3, §6.3.3). So a `users "ldap"`
block — and `ldapdir.New` — **refuses `ldap://` to another machine unless
`start_tls = true`**. `ldaps://` is accepted, and so are `ldap://` to a loopback
address (`127.0.0.0/8`, `::1`, `localhost`) and `ldapi://`, where nobody is on
the way. There is no switch to turn this off.

⛔ **This refuses configuration that v0.9.0 accepted.** A block that reached a
remote directory over plain `ldap://` now fails at `Check`, before anything
connects; add `start_tls = true` or move to `ldaps://`.

### A password change keeps the file's mode

`hcldir.SetPassword` rewrites the file that declares the person, through a
temporary file and a rename. The new file keeps the mode the old one had (a
`password_file` is capped at `0600`), and on Unix its owner and group as far
as the process may; when the group cannot be kept, the group bits are
dropped. Up to v0.9.0 the configuration came back `0644` whatever it had been.

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
a test can show rather than assume. `Person.Extra` and `Directory.GroupExtra`
add any other attribute to a person's or a group's entry, and a search gets
back only the attributes it asked for (RFC 4511 §4.5.1.8: none or `*` is all,
`1.1` is none) — so a client that forgets to *ask* for an attribute fails its
test, as it would fail against a real directory.

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

A group with **nobody in it** is refused by `Expand` rather than expanded to
nothing, with `ErrEmptyGroup`: a configuration that grants nothing to nobody
reads exactly like one that works. `Members` itself answers such a group with an
empty list, since the group exists (before v0.12.0 it said `ErrNoSuchGroup`).
A group **no source has** is `ErrNoSuchGroup`, not an empty list —
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
  actual `NULL`s deciding what each person can be proved with. The attributes
  queries were also run once by hand against **PostgreSQL 18.6** through pgx
  (not in CI): an unquoted alias came back lower-cased and was found anyway, a
  quoted one kept its case, and an alias naming `userPassword` was refused.
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
