# Changelog

Changes that a deployment has to know about, newest first. Earlier releases
are described in their pull requests and release notes.

## Unreleased

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

### ldaptest applies the people filter

`ldaptest` used to answer every people search with every person, whatever the
filter. It now gives each person an `objectClass` (`Person.ObjectClasses`,
default `top`, `account`, `posixAccount`) and returns only the people the
filter matches, so a test of a client's filter can fail. A test that searched
with a filter its people did not match, and relied on getting them anyway,
gets nobody now.
