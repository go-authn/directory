// SPDX-License-Identifier: BSD-3-Clause

package ldapdir

import (
	"crypto/tls"
	"testing"
)

// The certificate is verified against the host of the URL, set on the TLS
// configuration here, and the caller's own configuration is not changed.
func TestNewNamesTheURLHostInTheTLSConfig(t *testing.T) {
	for _, c := range []struct {
		name, url, serverName, want string
	}{
		{"ldaps host", "ldaps://ldap.example.org:636", "", "ldap.example.org"},
		{"ldap host with StartTLS", "ldap://dir.example.org", "", "dir.example.org"},
		{"no host", "ldaps://", "", "localhost"},
		{"an explicit name wins", "ldaps://ldap.example.org", "other.example.org", "other.example.org"},
	} {
		t.Run(c.name, func(t *testing.T) {
			own := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.serverName}
			cfg := prepareTLS(c.url, own)
			if cfg.ServerName != c.want {
				t.Errorf("ServerName = %q, want %q", cfg.ServerName, c.want)
			}
			if cfg.MinVersion != tls.VersionTLS13 {
				t.Errorf("the caller's MinVersion was lost: %#x", cfg.MinVersion)
			}
			if own.ServerName != c.serverName {
				t.Errorf("the caller's tls.Config was changed: ServerName %q", own.ServerName)
			}
		})
	}
}
