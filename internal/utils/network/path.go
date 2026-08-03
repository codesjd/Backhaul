package network

import "strings"

// NormalizeBasePath cleans up a user-supplied base path (e.g. from the
// "path" config option) so it can be safely prefixed onto "/channel" and
// "/tunnel". An empty input preserves the historical behavior of serving
// those routes at the root.
func NormalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}
