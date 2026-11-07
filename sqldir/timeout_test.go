package sqldir_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"testing"
	"time"

	"github.com/go-authn/directory/sqldir"
)

// A driver whose server accepted the connection and stopped answering: the
// query, or the reading of its rows, blocks until the context the driver was
// given ends -- which is all a real driver (pgx, mysql) does on a silent
// socket. Without a context there is nothing that ever ends it.
type silentDriver struct{ inRows bool }

func (d silentDriver) Open(string) (driver.Conn, error) { return silentConn{d.inRows}, nil }

type silentConn struct{ inRows bool }

func (silentConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (silentConn) Close() error                        { return nil }
func (silentConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (c silentConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	if c.inRows {
		return silentRows{ctx}, nil // the first row never arrives
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type silentRows struct{ ctx context.Context }

func (silentRows) Columns() []string { return []string{"name", "password"} }
func (silentRows) Close() error      { return nil }
func (r silentRows) Next([]driver.Value) error {
	<-r.ctx.Done()
	return io.ErrUnexpectedEOF
}

func init() {
	sql.Register("silent-query", silentDriver{})
	sql.Register("silent-rows", silentDriver{inRows: true})
}

func TestAQueryThatNeverAnswersReturnsWithinTheDeadline(t *testing.T) {
	for _, drv := range []string{"silent-query", "silent-rows"} {
		for _, c := range []struct {
			name  string
			q     sqldir.Queries
			start func(*sqldir.Source) error
		}{
			{"people", sqldir.Queries{People: "select name, password from people"}, func(s *sqldir.Source) error { _, err := s.Identities(); return err }},
			{"people attributes", sqldir.Queries{People: "select 1", PeopleAttributes: "select name, sn from people"}, func(s *sqldir.Source) error { _, err := s.Identities(); return err }},
			{"groups", sqldir.Queries{People: "select 1", Groups: "select g, m from teams"}, func(s *sqldir.Source) error { _, err := s.ReadGroups(); return err }},
		} {
			t.Run(drv+"/"+c.name, func(t *testing.T) {
				db, err := sql.Open(drv, "")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				src, err := sqldir.New(db, c.q, sqldir.WithQueryTimeout(150*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				begin := time.Now()
				go func() { done <- c.start(src) }()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("a read that never got an answer succeeded")
					}
					if took := time.Since(begin); took > 3*time.Second {
						t.Errorf("returned after %s with a 150ms deadline", took)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the read is still blocked 10s after a 150ms deadline")
				}
			})
		}
	}
}

func TestTheDefaultQueryTimeoutIsFinite(t *testing.T) {
	if sqldir.DefaultQueryTimeout <= 0 || sqldir.DefaultQueryTimeout > 5*time.Minute {
		t.Fatalf("DefaultQueryTimeout = %s: it must be finite and not absurd", sqldir.DefaultQueryTimeout)
	}
}
