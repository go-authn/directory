package ldapdir_test

// BenchmarkRefreshClientOnly measures what a refresh costs the CLIENT, and
// nothing of the server. BenchmarkRefresh runs an LDAP server in the same
// process (glauth's, behind ldaptest), and in its profile that server was 45 %
// of the allocations: a cost nobody running this package pays, charged to it.
//
// Here the server's answers are recorded once, from ldaptest, as the bytes it
// sent (the 10,000 people and 2,000 groups of 50 members of BenchmarkRefresh),
// and a loopback listener replays them: it reads a request, finds the answer
// recorded for those bytes, and writes it. Nothing is encoded or decoded on
// that side, so what the benchmark allocates is the client's. The file uses
// only what v0.21.0 already had, so the same file measures the baseline.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
)

// frameBytes reads one LDAPMessage as bytes (tag, length and contents).
func frameBytes(r *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 2, 6)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[1])
	if hdr[1] >= 0x80 {
		k := int(hdr[1] & 0x7F)
		ext := make([]byte, k)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		hdr = append(hdr, ext...)
		n = 0
		for _, c := range ext {
			n = n<<8 | int(c)
		}
	}
	out := make([]byte, len(hdr)+n)
	copy(out, hdr)
	_, err := io.ReadFull(r, out[len(hdr):])
	return out, err
}

// opOf is the part of a request after its message id: the operation and its
// controls. The id is where two runs of the same client may differ.
func opOf(frame []byte) (id byte, op []byte) {
	i := 2
	if frame[1] >= 0x80 {
		i += int(frame[1] & 0x7F)
	}
	// INTEGER messageID: 0x02 len id...
	l := int(frame[i+1])
	return frame[i+2], frame[i+2+l:]
}

// finalOp says a response frame ends its request: a bind response or a
// search result done.
func finalOp(frame []byte) bool {
	i := 2
	if frame[1] >= 0x80 {
		i += int(frame[1] & 0x7F)
	}
	_, op := opOf(frame)
	return op[0] == 0x61 || op[0] == 0x65
}

type replayServer struct {
	ln       net.Listener
	upstream string

	mu        sync.Mutex
	recording bool
	frames    map[string][][]byte // request operation -> the response frames
}

func newReplayServer(tb testing.TB, upstream string) *replayServer {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	s := &replayServer{ln: ln, upstream: upstream, recording: true, frames: map[string][][]byte{}}
	tb.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(tb, c)
		}
	}()
	return s
}

func (s *replayServer) serve(tb testing.TB, c net.Conn) {
	defer c.Close()
	s.mu.Lock()
	recording := s.recording
	s.mu.Unlock()
	var up net.Conn
	var upr *bufio.Reader
	if recording {
		var err error
		if up, err = net.Dial("tcp", s.upstream); err != nil {
			return
		}
		defer up.Close()
		upr = bufio.NewReader(up)
	}
	r := bufio.NewReader(c)
	for {
		req, err := frameBytes(r)
		if err != nil {
			return
		}
		_, op := opOf(req)
		if op[0] == 0x42 { // UnbindRequest: no answer
			return
		}
		if recording {
			if _, err := up.Write(req); err != nil {
				return
			}
			var got [][]byte
			for {
				f, err := frameBytes(upr)
				if err != nil {
					return
				}
				got = append(got, f)
				if _, err := c.Write(f); err != nil {
					return
				}
				if finalOp(f) {
					break
				}
			}
			s.mu.Lock()
			s.frames[string(op)] = got
			s.mu.Unlock()
			continue
		}
		s.mu.Lock()
		got, ok := s.frames[string(op)]
		s.mu.Unlock()
		if !ok {
			tb.Errorf("replay: a request that was not recorded: % x", bytes.TrimSpace(op[:min(len(op), 60)]))
			return
		}
		for _, f := range got {
			if _, err := c.Write(f); err != nil {
				return
			}
		}
	}
}

func BenchmarkRefreshClientOnly(b *testing.B) {
	const people, groups, size = 10000, 2000, 50
	srv := bigDirectory(b, people, groups, size)
	rs := newReplayServer(b, srv.URL[len("ldap://"):])
	src, err := ldapdir.New(ldapdir.Config{
		URL: "ldap://" + rs.ln.Addr().String(), BaseDN: srv.PeopleDN, GroupBaseDN: srv.GroupsDN,
		BindDN: srv.ReaderDN, BindPassword: srv.ReaderPassword,
		GroupFilter: "(objectClass=groupOfNames)", GroupAttribute: "cn",
	})
	if err != nil {
		b.Fatal(err)
	}
	set := directory.NewSet(src)
	refresh := func() {
		ids, err := set.Identities()
		if err != nil || len(ids) != people {
			b.Fatal(len(ids), err)
		}
		f, err := set.Frozen()
		if err != nil {
			b.Fatal(err)
		}
		names, _ := f.GroupNames()
		if len(names) != groups {
			b.Fatal(len(names))
		}
		for _, n := range names {
			m, err := f.Members(n)
			if err != nil || len(m) != size {
				b.Fatal(n, len(m), err)
			}
		}
	}
	refresh() // recorded, through the real server
	rs.mu.Lock()
	rs.recording = false
	rs.mu.Unlock()
	if len(rs.frames) < 3 {
		b.Fatal(fmt.Sprint("recorded only ", len(rs.frames), " answers"))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		refresh()
	}
}
