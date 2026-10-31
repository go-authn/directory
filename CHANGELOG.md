# Changelog

Changes that a deployment has to know about, newest first. Earlier releases
are described in their pull requests and release notes.

## v0.16.0 — 2026-10-31

### Reading every group once

A server that publishes every group asks each one three questions (`Members`,
`GroupAttributes`, `GroupObjectClasses`). For a database, each answer ran the
groups query again and filtered it in Go, so reading n groups of m membership
rows cost 3n scans of m: 2 s of one core for 200 groups of 50, and about 200 s
for 2,000 groups of 50. For a directory, each answer dialled and searched, and
`Members` searched for the people again when a member was a DN.

- `directory.GroupReader`, an optional interface: `ReadGroups()` returns every
  group's members, attributes and classes (`directory.GroupData`) from one pass
  over each query. `sqldir.Source` and `ldapdir.Source` implement it.
- `(*Set).Frozen()` reads every `GroupReader` source once and returns a Set
  that answers `Members`, `GroupAttributes`, `GroupObjectClasses` and
  `GroupNames` from what was read, with the Set's own merging and precedence
  (it is the same code asking sources that answer from memory). A source that
  cannot be read is an error from `Frozen`. Close the original Set, not the
  frozen one.
- Differential tests hold the bulk answers to the per-group answers (values,
  order, and the kind of error) on fixtures and on 80 random SQLite databases,
  and a planted fault (a bulk read that drops the last member) is caught.
- `ldapdir`: a group is matched as the directory matches it (caseIgnoreMatch
  for `cn`); a member DN is mapped to a person once for each distinct value,
  but still by comparing it with every imported person, so a site with very
  many DN members and very many people still pays for that comparison.

## v0.15.0 — 2026-10-25

### Object classes, declared explicitly

A source's configuration can now declare the auxiliary object classes its
people and groups carry, so that a server such as go-authn/authnd can publish
a site schema (SUPANN, eduPerson):

- `directory.ObjectClasses`, `NewObjectClasses`, `CheckObjectClassName`,
  `ErrObjectClassName`; `WithObjectClasses` and `Identity.ObjectClasses()`.
- `GroupObjectClasser` (optional, beside `GroupAttributer`),
  `Set.GroupObjectClasses`, `Static.GroupClasses`.
- hcldir: `object_classes` and `group_object_classes` in `users` blocks of
  both kinds, `object_classes` in `user` and `group` blocks. Errors carry the
  HCL position (`*Range` fields filled by gohcl's `attr_value_range`).
- sqldir: `WithObjectClasses`, `WithGroupObjectClasses`; ldapdir:
  `Config.ObjectClasses`, `Config.GroupObjectClasses`.

**Why explicit.** A class promises the shape of every entry (RFC 4512
§4.1.1). It is never inferred from the attributes present and never read from
the data -- no database column, no upstream `objectClass` value -- so an
attribute appearing in a database cannot change a published class. This
package checks the spelling only (an RFC 4512 `descr`; numeric OIDs, spaces,
quotes and parentheses refused, fuzzed); authnd validates the classes against
the schema it serves (auxiliary only, not one it derives, not unknown).

**Groups across sources.** The first source that has the group and declares
classes decides, whole; a source declaring nothing does not decide; a later
source's different list is ignored, neither merged nor an error.

### sqldir.Source can close its database

`sqldir.ClosesDB()` hands the database to the source, and
`(*sqldir.Source).Close` closes it (and does nothing without the option).
`hcldir.Open` now returns the `*sqldir.Source` itself instead of a wrapper per
combination of optional interfaces, which would have needed eight types once
`GroupObjectClasser` joined `GroupLister` and `GroupAttributer`.

## v0.14.1 — 2026-10-18

- This file only: v0.14.0 shipped with its section still headed
  "Unreleased". The tests for a forged member DN were also strengthened in
  v0.14.0 (a group holding only forgeries), which this file did not say.

## v0.14.0 — 2026-10-18

### ⛔ ldapdir's default user filter is wider

The default `UserFilter` (`user_filter` in a `users "ldap"` block) was

    (objectClass=posixAccount)

and is now `ldapdir.DefaultUserFilter`:

    (|(objectClass=posixAccount)(objectClass=account)(objectClass=uidObject))

**This widens what an upstream directory gives by default.** An institution's
directory may hold `account` (RFC 4524 §3.1) or `uidObject` (RFC 4519 §3.14)
entries that are not posixAccounts -- service accounts, hosts named by uid,
people imported from elsewhere. Every program that kept the default reads them
now, and each of them can be checked against the directory by a bind; before,
they were not read at all.

Why: go-authn/authnd publishes a person without uidNumber, gidNumber and
homeDirectory as an `account` or an `inetOrgPerson`, because RFC 2307 makes
those three MUST in `posixAccount`, and puts `uidObject` on every person. Under
the old default such a person vanished for go-fileshare and every other
consumer of ldapdir.

A plain `inetOrgPerson` with none of the three classes is still not read
(`TestTheDefaultUserFilter`). To keep exactly the old set, configure the old
filter: `user_filter = "(objectClass=posixAccount)"`.

### ⛔ ldapdir's default group filter is wider: groupOfNames groups are read

The default `GroupFilter` (`group_filter`) was `(objectClass=posixGroup)`, with
members in `memberUid`. It is now `ldapdir.DefaultGroupFilter`:

    (|(objectClass=posixGroup)(objectClass=groupOfNames))

and with no `MemberAttribute` (`group_member_attribute`) configured, members
are read from `memberUid` (names) **and** `member` (DNs).

**This widens what an upstream directory gives by default**: an institution's
`groupOfNames` groups become groups here, and an `@group` rule naming one now
grants what it says. It adds **no person**: a `member` DN maps to somebody only
when it is, by distinguishedNameMatch, the DN of an entry the people search
returned. A DN outside those entries, or naming nobody, maps to nobody, and so
does a spoof such as `uid=alice,ou=elsewhere,...` when alice was imported from
`ou=people`.

Why: go-authn/authnd publishes a group without a `gidNumber` as a
`groupOfNames`, since RFC 2307 makes `gidNumber` MUST in `posixGroup`. Under
the old default such a group was "no such group" for go-fileshare.

To keep the old groups exactly: `group_filter = "(objectClass=posixGroup)"`
and `group_member_attribute = "memberUid"`.

### A member DN is no longer read out of the DN

A configured `MemberAttribute` is still the one attribute read. But a DN in it
-- always, for `member` and `uniqueMember` -- now maps only to a person this
source imported, by that person's DN. Up to v0.13.0 it was reduced to the
value of its first RDN, so `uid=alice,ou=elsewhere,...`, `cn=alice,...` and
`uid=zed,...` became members named alice, alice and zed whether or not any of
them had been imported.

### ldaptest applies base and filter to every search

`ldaptest` used to answer every people search with every person, whatever the
filter, and took any filter containing "posixGroup" for a group search. It now
gives each person an `objectClass` (`Person.ObjectClasses`, default `top`,
`account`, `posixAccount`), has `groupOfNames` groups (`GroupsOfNames`, DNs in
`member`), and answers every search with the entries under its base that its
filter matches, so a test of a client's filters can fail. A test that relied on
getting people or groups its filter did not match gets nothing now.
