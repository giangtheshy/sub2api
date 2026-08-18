package logredact

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// maxRedactDepth 限制递归深度以防止栈溢出
const maxRedactDepth = 32

var defaultSensitiveKeys = map[string]struct{}{
	"authorization_code": {},
	"code":               {},
	"code_verifier":      {},
	"access_token":       {},
	"refresh_token":      {},
	"id_token":           {},
	"client_secret":      {},
	"password":           {},
	// claude.ai cookie 账号凭证。这份清单与 service.SensitiveCredentialKeys 相互独立，
	// 它守的是幂等记录与日志正文，因此必须单独同步。
	"cookie_jar":  {},
	"session_key": {},
	"cookie":      {},
	// Claude CLI 的 .credentials.json 用 camelCase，那份文件的拼写由外部程序决定、
	// 不归我们选。normalizeKey 只做小写化，因此 "accessToken" 会归一成 "accesstoken"
	// 而与上面的 snake_case 全部错过——必须把同一个密钥的两种拼法都登记。
	"accesstoken":  {},
	"refreshtoken": {},
	"idtoken":      {},
}

var defaultSensitiveKeyList = []string{
	"authorization_code",
	"code",
	"code_verifier",
	"access_token",
	"refresh_token",
	"id_token",
	"client_secret",
	"password",
	// 长键在前：正则交替按先后匹配，"cookie" 排在 "cookie_jar" 之前会先吃掉前缀。
	"cookie_jar",
	"session_key",
	"cookie",
	// camelCase 变体（Claude CLI 凭证文件）；正则带 (?i)，故只需登记小写形式。
	"accesstoken",
	"refreshtoken",
	"idtoken",
}

type textRedactPatterns struct {
	reJSONLike  *regexp.Regexp
	reQueryLike *regexp.Regexp
	rePlain     *regexp.Regexp
}

var (
	reGOCSPX = regexp.MustCompile(`GOCSPX-[0-9A-Za-z_-]{24,}`)
	reAIza   = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)

	defaultTextRedactPatterns = compileTextRedactPatterns(nil)
	extraTextPatternCache     sync.Map // map[string]*textRedactPatterns
)

func RedactMap(input map[string]any, extraKeys ...string) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	keys := buildKeySet(extraKeys)
	redacted, ok := redactValueWithDepth(input, keys, 0).(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return redacted
}

func RedactJSON(raw []byte, extraKeys ...string) string {
	if len(raw) == 0 {
		return ""
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "<non-json payload redacted>"
	}
	keys := buildKeySet(extraKeys)
	redacted := redactValueWithDepth(value, keys, 0)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return "<redacted>"
	}
	return string(encoded)
}

// RedactText 对非结构化文本做轻量脱敏。
//
// 规则：
// - 如果文本本身是 JSON，则按 RedactJSON 处理。
// - 否则尝试对常见 key=value / key:"value" 片段做脱敏。
//
// 注意：该函数用于日志/错误信息兜底，不保证覆盖所有格式。
func RedactText(input string, extraKeys ...string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	raw := []byte(input)
	if json.Valid(raw) {
		return RedactJSON(raw, extraKeys...)
	}

	patterns := getTextRedactPatterns(extraKeys)

	out := input
	out = reGOCSPX.ReplaceAllString(out, "GOCSPX-***")
	out = reAIza.ReplaceAllString(out, "AIza***")
	out = patterns.reJSONLike.ReplaceAllString(out, `$1***$3`)
	out = patterns.reQueryLike.ReplaceAllString(out, `$1=***`)
	out = patterns.rePlain.ReplaceAllString(out, `$1$2***`)
	return out
}

func compileTextRedactPatterns(extraKeys []string) *textRedactPatterns {
	keyAlt := buildKeyAlternation(extraKeys)
	return &textRedactPatterns{
		// JSON-like: "access_token":"..."
		reJSONLike: regexp.MustCompile(`(?i)("(?:` + keyAlt + `)"\s*:\s*")([^"]*)(")`),
		// Query-like: access_token=...
		reQueryLike: regexp.MustCompile(`(?i)\b((?:` + keyAlt + `))=([^&\s]+)`),
		// Plain: access_token: ... / access_token = ...
		rePlain: regexp.MustCompile(`(?i)\b((?:` + keyAlt + `))\b(\s*[:=]\s*)([^,\s]+)`),
	}
}

func getTextRedactPatterns(extraKeys []string) *textRedactPatterns {
	normalizedExtraKeys := normalizeAndSortExtraKeys(extraKeys)
	if len(normalizedExtraKeys) == 0 {
		return defaultTextRedactPatterns
	}

	cacheKey := strings.Join(normalizedExtraKeys, ",")
	if cached, ok := extraTextPatternCache.Load(cacheKey); ok {
		if patterns, ok := cached.(*textRedactPatterns); ok {
			return patterns
		}
	}

	compiled := compileTextRedactPatterns(normalizedExtraKeys)
	actual, _ := extraTextPatternCache.LoadOrStore(cacheKey, compiled)
	if patterns, ok := actual.(*textRedactPatterns); ok {
		return patterns
	}
	return compiled
}

func normalizeAndSortExtraKeys(extraKeys []string) []string {
	if len(extraKeys) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(extraKeys))
	keys := make([]string, 0, len(extraKeys))
	for _, key := range extraKeys {
		normalized := normalizeKey(key)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		keys = append(keys, normalized)
	}
	sort.Strings(keys)
	return keys
}

func buildKeyAlternation(extraKeys []string) string {
	seen := make(map[string]struct{}, len(defaultSensitiveKeyList)+len(extraKeys))
	keys := make([]string, 0, len(defaultSensitiveKeyList)+len(extraKeys))
	for _, k := range defaultSensitiveKeyList {
		seen[k] = struct{}{}
		keys = append(keys, regexp.QuoteMeta(k))
	}
	for _, k := range extraKeys {
		n := normalizeKey(k)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		keys = append(keys, regexp.QuoteMeta(n))
	}
	return strings.Join(keys, "|")
}

func buildKeySet(extraKeys []string) map[string]struct{} {
	keys := make(map[string]struct{}, len(defaultSensitiveKeys)+len(extraKeys))
	for k := range defaultSensitiveKeys {
		keys[k] = struct{}{}
	}
	for _, key := range extraKeys {
		normalized := normalizeKey(key)
		if normalized == "" {
			continue
		}
		keys[normalized] = struct{}{}
	}
	return keys
}

func redactValueWithDepth(value any, keys map[string]struct{}, depth int) any {
	if depth > maxRedactDepth {
		return "<depth limit exceeded>"
	}

	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			if isSensitiveKey(k, keys) {
				out[k] = "***"
				continue
			}
			out[k] = redactValueWithDepth(val, keys, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValueWithDepth(item, keys, depth+1)
		}
		return out
	default:
		return value
	}
}

func isSensitiveKey(key string, keys map[string]struct{}) bool {
	_, ok := keys[normalizeKey(key)]
	return ok
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}
