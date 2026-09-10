// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql

package hcldir

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"
)

// openSQL opens the database and hands sqldir the caller's own queries.
//
// The DRIVER is not imported here. A driver is a choice a deployment makes --
// PostgreSQL alone has three -- and a program that wants SQLite should not
// carry the other two, so the PROGRAM imports the ones it wants:
//
//	import _ "modernc.org/sqlite"             // pure Go, no cgo
//	import _ "github.com/jackc/pgx/v5/stdlib"
//	import _ "github.com/go-sql-driver/mysql"
//
// A binary that did not is told exactly that, rather than "unknown driver".
func openSQL(b Block) (directory.Source, error) {
	driver, err := driverFor(b.Driver)
	if err != nil {
		return nil, err
	}
	dsn, err := secretFile(b.DSNFile, "the DSN file")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		// Not wrapped with the DSN: it holds a password. The three drivers
		// were measured and none of them repeats one either -- pgx redacts to
		// `xxxxx` even when reporting a DSN it could not parse.
		return nil, fmt.Errorf("opening the %s database: %w", b.Driver, err)
	}
	// Reached at startup rather than at the first login: a directory that is
	// not answering is a server that cannot authenticate anybody, and it
	// should say so before it listens.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("the %s database is not answering: %w", b.Driver, err)
	}
	src, err := sqldir.New(db, sqldir.Queries{People: b.UsersQuery, Groups: b.GroupsQuery},
		sqldir.Named("a "+b.Driver+" database"))
	if err != nil {
		db.Close()
		return nil, err
	}
	// The database is the CALLER's to close: sqldir takes a *sql.DB precisely
	// so that the driver and the lifetime belong to whoever opened it. Windows
	// found this one -- a test could not remove its own SQLite file, because
	// the handle was still open -- and every Unix hid it, since unlinking a
	// file somebody still holds is allowed there.
	return closing(src, db.Close), nil
}

// driverFor maps the name a person writes -- the database's, not the Go
// package's -- to a driver this binary actually registered.
func driverFor(name string) (string, error) {
	var want string
	switch name {
	case "postgres", "postgresql", "pgx":
		want = "pgx"
	case "sqlite", "sqlite3":
		want = "sqlite"
	case "mysql", "mariadb":
		want = "mysql"
	case "":
		return "", fmt.Errorf("a driver is needed: %s", strings.Join(Drivers, ", "))
	default:
		return "", fmt.Errorf("there is no %q driver here: %s", name, strings.Join(Drivers, ", "))
	}
	if !slices.Contains(sql.Drivers(), want) {
		// The difference that matters: the name is right and this BINARY does
		// not have it. A blank import is the fix, and it is one line.
		return "", fmt.Errorf("this binary registered no %q driver: import one (for example %s)", want, driverPackages[want])
	}
	return want, nil
}

// Drivers are the database names a `users "sql"` block can use.
var Drivers = []string{"sqlite", "postgres", "mysql"}

var driverPackages = map[string]string{
	"sqlite": `_ "modernc.org/sqlite"`,
	"pgx":    `_ "github.com/jackc/pgx/v5/stdlib"`,
	"mysql":  `_ "github.com/go-sql-driver/mysql"`,
}
