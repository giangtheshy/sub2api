// Package claudecookie parses claude.ai cookies pasted or exported by an
// operator into a sendable Cookie header plus the sessionKey used by the OAuth
// flow.
//
// Four input shapes are accepted, because that is what browsers and cookie
// extensions actually produce:
//
//   - Netscape cookie file (Cookie-Editor "Export as Netscape", curl -c)
//   - JSON export (Cookie-Editor array, or a flat name -> value object)
//   - a raw Cookie header, "name=value; name=value"
//   - a bare sessionKey, "sk-ant-sid02-..."
package claudecookie

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNoSessionKey is returned when the input carries no usable claude.ai
// session cookie. Callers match on it to render an actionable message.
var ErrNoSessionKey = errors.New("no claude.ai sessionKey found in cookie input")

const (
	cookieNameSessionKey   = "sessionKey"
	cookieNameSessionKeyV3 = "sessionKeyV3"
	sessionKeyPrefix       = "sk-ant-sid"

	// netscapeFieldCount is the number of tab separated fields in a Netscape
	// cookie line: domain, include-subdomains, path, secure, expiry, name, value.
	netscapeFieldCount = 7

	// httpOnlyPrefix marks HttpOnly cookies in Netscape files. The prefix is
	// metadata, not part of the domain.
	httpOnlyPrefix = "#HttpOnly_"
)

// ParsedCookie is one account's worth of cookies.
type ParsedCookie struct {
	// SessionKey is the value of the sessionKey cookie (sessionKeyV3 is used as
	// a fallback when only that one is present).
	SessionKey string
	// Jar is a ready to send Cookie header value, in input order.
	Jar string
	// Names lists the cookie names kept in Jar, in the same order.
	Names []string
}

type cookiePair struct {
	name  string
	value string
}

// ParseOne parses a single account's cookie input, auto-detecting the format.
func ParseOne(raw string) (ParsedCookie, error) {
	return parseOneAt(raw, time.Now())
}

// ParseMany parses operator input that may describe several accounts.
//
// A Netscape or JSON export always describes exactly one account even though it
// spans many lines. Anything else is treated as the historical batch format:
// one sessionKey (or one Cookie header) per line.
func ParseMany(raw string) ([]ParsedCookie, error) {
	return parseManyAt(raw, time.Now())
}

// JarForSessionKey builds the minimal Cookie header for a bare sessionKey.
// It returns an empty string for an empty key so callers can detect the no-op.
func JarForSessionKey(sessionKey string) string {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return ""
	}
	return cookieNameSessionKey + "=" + sessionKey
}

func parseManyAt(raw string, now time.Time) ([]ParsedCookie, error) {
	lines := splitLines(raw)

	if isJSON(raw) || hasNetscapeLine(lines) {
		one, err := parseOneAt(raw, now)
		if err != nil {
			return nil, err
		}
		return []ParsedCookie{one}, nil
	}

	var out []ParsedCookie
	for _, line := range lines {
		if line == "" || isComment(line) {
			continue
		}
		one, err := parseOneAt(line, now)
		if err != nil {
			return nil, err
		}
		out = append(out, one)
	}
	if len(out) == 0 {
		return nil, ErrNoSessionKey
	}
	return out, nil
}

func parseOneAt(raw string, now time.Time) (ParsedCookie, error) {
	pairs, err := extractPairs(raw, now)
	if err != nil {
		return ParsedCookie{}, err
	}
	return build(pairs)
}

// extractPairs dispatches on the input shape. Ordering matters: a Cookie header
// can look like a space separated Netscape line once it has enough pairs, so the
// semicolon check runs first.
func extractPairs(raw string, now time.Time) ([]cookiePair, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, ErrNoSessionKey
	}

	if isJSON(trimmed) {
		return parseJSON(trimmed, now)
	}

	lines := splitLines(raw)

	if strings.Contains(trimmed, ";") {
		return parseCookieHeader(trimmed), nil
	}

	if hasNetscapeLine(lines) {
		return parseNetscape(lines, now), nil
	}

	if strings.Contains(trimmed, "=") {
		return parseCookieHeader(trimmed), nil
	}

	if strings.HasPrefix(trimmed, sessionKeyPrefix) && !strings.ContainsAny(trimmed, " \t") {
		return []cookiePair{{name: cookieNameSessionKey, value: trimmed}}, nil
	}

	return nil, ErrNoSessionKey
}

// build turns ordered pairs into a ParsedCookie, resolving the session key.
func build(pairs []cookiePair) (ParsedCookie, error) {
	out := ParsedCookie{Names: make([]string, 0, len(pairs))}
	parts := make([]string, 0, len(pairs))

	var fallback string
	for _, p := range pairs {
		switch p.name {
		case cookieNameSessionKey:
			// Prefer sessionKey: that is the cookie claude.ai's own OAuth
			// authorize call authenticates with.
			if out.SessionKey == "" {
				out.SessionKey = p.value
			}
		case cookieNameSessionKeyV3:
			if fallback == "" {
				fallback = p.value
			}
		}
		out.Names = append(out.Names, p.name)
		parts = append(parts, p.name+"="+p.value)
	}

	if out.SessionKey == "" {
		out.SessionKey = fallback
	}
	if out.SessionKey == "" {
		return ParsedCookie{}, ErrNoSessionKey
	}

	out.Jar = strings.Join(parts, "; ")
	return out, nil
}

func parseCookieHeader(raw string) []cookiePair {
	var out []cookiePair
	for _, chunk := range strings.Split(raw, ";") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		name, value, ok := strings.Cut(chunk, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		out = append(out, cookiePair{name: name, value: strings.TrimSpace(value)})
	}
	return out
}

func parseNetscape(lines []string, now time.Time) []cookiePair {
	var out []cookiePair
	for _, line := range lines {
		fields, ok := netscapeFields(line)
		if !ok {
			continue
		}
		name := fields[5]
		if name == "" {
			continue
		}
		if isExpired(fields[4], now) {
			continue
		}
		out = append(out, cookiePair{name: name, value: fields[6]})
	}
	return out
}

// netscapeFields splits one Netscape line into its 7 fields, tolerating the
// #HttpOnly_ prefix and editors that turn tabs into runs of spaces.
func netscapeFields(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, false
	}
	if strings.HasPrefix(line, httpOnlyPrefix) {
		line = strings.TrimPrefix(line, httpOnlyPrefix)
	} else if isComment(line) {
		return nil, false
	}

	if fields := strings.Split(line, "\t"); len(fields) >= netscapeFieldCount {
		return fields[:netscapeFieldCount], true
	}

	// Space separated fallback: the value is the remainder, since only the value
	// may legitimately contain spaces.
	fields := strings.Fields(line)
	if len(fields) < netscapeFieldCount {
		return nil, false
	}
	head := fields[:netscapeFieldCount-1]
	value := strings.Join(fields[netscapeFieldCount-1:], " ")
	return append(head, value), true
}

type jsonCookie struct {
	Name           string  `json:"name"`
	Value          string  `json:"value"`
	ExpirationDate float64 `json:"expirationDate"`
	Expires        float64 `json:"expires"`
}

func parseJSON(raw string, now time.Time) ([]cookiePair, error) {
	if strings.HasPrefix(raw, "[") {
		var items []jsonCookie
		if err := json.Unmarshal([]byte(raw), &items); err != nil {
			return nil, fmt.Errorf("%w: invalid JSON cookie export: %v", ErrNoSessionKey, err)
		}
		out := make([]cookiePair, 0, len(items))
		for _, it := range items {
			if it.Name == "" {
				continue
			}
			expiry := it.ExpirationDate
			if expiry == 0 {
				expiry = it.Expires
			}
			if expiry > 0 && int64(expiry) < now.Unix() {
				continue
			}
			out = append(out, cookiePair{name: it.Name, value: it.Value})
		}
		return out, nil
	}

	var flat map[string]string
	if err := json.Unmarshal([]byte(raw), &flat); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON cookie export: %v", ErrNoSessionKey, err)
	}
	names := make([]string, 0, len(flat))
	for name := range flat {
		if name != "" {
			names = append(names, name)
		}
	}
	// A JSON object has no inherent order; sort so the jar is deterministic.
	sort.Strings(names)
	out := make([]cookiePair, 0, len(names))
	for _, name := range names {
		out = append(out, cookiePair{name: name, value: flat[name]})
	}
	return out, nil
}

// isExpired reports whether a Netscape expiry field is in the past. Expiry 0
// marks a session cookie, which browsers do send.
func isExpired(field string, now time.Time) bool {
	expiry, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
	if err != nil || expiry <= 0 {
		return false
	}
	return expiry < now.Unix()
}

func hasNetscapeLine(lines []string) bool {
	for _, line := range lines {
		if _, ok := netscapeFields(line); ok {
			return true
		}
	}
	return false
}

func isJSON(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{")
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

func splitLines(raw string) []string {
	rawLines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		out = append(out, strings.TrimSpace(strings.TrimSuffix(line, "\r")))
	}
	return out
}
