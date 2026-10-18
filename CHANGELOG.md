# Changelog

Changes that a deployment has to know about, newest first. Earlier releases
are described in their pull requests and release notes.

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
