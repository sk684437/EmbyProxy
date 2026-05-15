package validators

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"embyproxy/internal/storage"
)

var NameRE = regexp.MustCompile(`(?i)^[a-z0-9_-]{1,32}$`)
var SecretRE = regexp.MustCompile(`^[^/?#\s]{0,128}$`)
var profileSet = map[string]bool{"yamby": true, "hills_android": true, "hills_windows": true}

type Result struct {
	Node  storage.Node
	Error string
}

func NormalizeName(value any) string {
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
}

func ValidateName(value any) (string, string) {
	name := NormalizeName(value)
	if !NameRE.MatchString(name) {
		return "", "name 非法：仅允许 a-z / 0-9 / _ / -，长度 1~32"
	}
	return name, ""
}

func ValidateNodeInput(input map[string]any) Result {
	if input == nil {
		return Result{Error: "节点项不是对象"}
	}
	name, errText := ValidateName(input["name"])
	if errText != "" {
		return Result{Error: errText}
	}
	target, errText := ValidateTarget(asString(input["target"]))
	if errText != "" {
		return Result{Error: errText}
	}
	secret, errText := ValidateSecret(input["secret"])
	if errText != "" {
		return Result{Error: errText}
	}
	profile, errText := ValidateImpersonateProfile(input["impersonateProfile"])
	if errText != "" {
		return Result{Error: errText}
	}
	rank := optionalInt(input["rank"])
	hasImpersonate := hasKey(input, "impersonate")
	keepaliveMaxPerDay := 1
	if valuePresent(input["keepaliveMaxPerDay"]) {
		n := intValue(input["keepaliveMaxPerDay"])
		if n < 1 || n > 24 {
			return Result{Error: "保号每日提醒次数不合法（1~24）"}
		}
		keepaliveMaxPerDay = n
	}
	renewDays, errText := dayRange(input["renewDays"], "保号周期不合法（0~3650）")
	if errText != "" {
		return Result{Error: errText}
	}
	remindBeforeDays, errText := dayRange(input["remindBeforeDays"], "提前几天提醒不合法（0~3650）")
	if errText != "" {
		return Result{Error: errText}
	}
	keepaliveAt, errText := normalizeKeepaliveAt(input["keepaliveAt"])
	if errText != "" {
		return Result{Error: errText}
	}
	return Result{Node: storage.Node{
		Name:                name,
		Target:              target,
		StreamTarget:        strings.TrimSpace(asString(input["streamTarget"])),
		Fav:                 ToBool(input["fav"]),
		Rank:                rank,
		Secret:              secret,
		Tag:                 truncate(strings.TrimSpace(asString(input["tag"])), 64),
		Note:                truncate(strings.TrimSpace(asString(input["note"])), 64),
		DisplayName:         truncate(regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(asString(input["displayName"])), " "), 32),
		DirectExternal:      ToBool(input["directExternal"]),
		RenewDays:           renewDays,
		RemindBeforeDays:    remindBeforeDays,
		KeepaliveAt:         keepaliveAt,
		KeepaliveMaxPerDay:  keepaliveMaxPerDay,
		KeepaliveChangeOnly: input["keepaliveChangeOnly"] != false,
		Impersonate:         !hasImpersonate || ToBool(input["impersonate"]),
		ImpersonateProfile:  profile,
	}}
}

func ValidateTarget(value string) (string, string) {
	parts := storage.SplitTargets(value)
	if len(parts) == 0 {
		return "", "target 不能为空"
	}
	if len(parts) > 20 {
		return "", "target 数量过多（最多20）"
	}
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, target := range parts {
		if len(target) > 2048 {
			return "", "target 过长"
		}
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", "target 不是合法 URL: " + target
		}
		if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
			return "", "target 只允许 http/https"
		}
		clean := strings.TrimRight(target, "/")
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return strings.Join(out, "\n"), ""
}

func ValidateSecret(value any) (string, string) {
	secret := strings.TrimSpace(asString(value))
	if !SecretRE.MatchString(secret) {
		return "", "secret 非法：不能包含 / ? # 或空白字符，最长128"
	}
	return secret, ""
}

func ValidateTag(value any) string {
	return truncate(strings.TrimSpace(asString(value)), 64)
}

func ValidateImpersonateProfile(value any) (string, string) {
	profile := strings.ToLower(strings.TrimSpace(asString(value)))
	if profile == "" {
		profile = "yamby"
	}
	if !profileSet[profile] {
		return "", "伪装身份仅支持 yamby/hills_android/hills_windows"
	}
	return profile, ""
}

func ToBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	default:
		return false
	}
}

func dayRange(value any, errText string) (int, string) {
	if !valuePresent(value) {
		return 0, ""
	}
	n := intValue(value)
	if n < 0 || n > 3650 {
		return 0, errText
	}
	return n, ""
}

func normalizeKeepaliveAt(value any) (string, string) {
	raw := strings.TrimSpace(asString(value))
	if raw == "" {
		return "", ""
	}
	replacer := strings.NewReplacer(" ", "", "　", "", "：", ":", "．", ":", "。", ":")
	s := replacer.Replace(raw)
	s = normalizeFullWidthDigits(s)
	m := regexp.MustCompile(`^(\d{1,2}):(\d{1,2})(?::(\d{1,2})(\.\d+)?)?$`).FindStringSubmatch(s)
	if len(m) == 0 {
		m = regexp.MustCompile(`(\d{1,2})\D+(\d{1,2})`).FindStringSubmatch(s)
	}
	if len(m) == 0 {
		return "", "keepaliveAt 格式不合法，示例：03:00"
	}
	hh := clamp(intString(m[1]), 0, 23)
	mm := clamp(intString(m[2]), 0, 59)
	return fmt.Sprintf("%02d:%02d", hh, mm), ""
}

func normalizeFullWidthDigits(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= '０' && r <= '９' {
			return r - '０' + '0'
		}
		return r
	}, value)
}

func optionalInt(value any) *int {
	if !valuePresent(value) {
		return nil
	}
	n := intValue(value)
	return &n
}

func intValue(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func intString(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func truncate(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func valuePresent(value any) bool {
	return value != nil && strings.TrimSpace(asString(value)) != ""
}

func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}
