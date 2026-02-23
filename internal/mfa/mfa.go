package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPeriod = 30
	DefaultDigits = 6
)

func GenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return strings.ToUpper(strings.TrimSpace(enc)), nil
}

func BuildOTPAuthURL(issuer, account, secret string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if issuer == "" {
		issuer = "DomNexDomain"
	}
	if account == "" {
		account = "user"
	}
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(DefaultDigits))
	v.Set("period", strconv.Itoa(DefaultPeriod))
	return "otpauth://totp/" + label + "?" + v.Encode()
}

func ValidateTOTP(secret, code string, now time.Time) bool {
	return ValidateTOTPWithWindow(secret, code, now, 1)
}

func ValidateTOTPWithWindow(secret, code string, now time.Time, window int) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	code = normalizeCode(code)
	if secret == "" || code == "" || len(code) != DefaultDigits {
		return false
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := enc.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return false
	}
	counter := now.UTC().Unix() / DefaultPeriod
	for i := -window; i <= window; i++ {
		if code == hotp(key, uint64(counter+int64(i)), DefaultDigits) {
			return true
		}
	}
	return false
}

func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		n = 10
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 6)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		s := strings.ToUpper(hex.EncodeToString(raw))
		out = append(out, s[0:4]+"-"+s[4:8]+"-"+s[8:12])
	}
	return out, nil
}

func NormalizeRecoveryCode(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "")
	v = strings.ReplaceAll(v, " ", "")
	return v
}

func HashRecoveryCode(v string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(v)))
	return hex.EncodeToString(sum[:])
}

func IsRecoveryCodeFormat(v string) bool {
	n := NormalizeRecoveryCode(v)
	return len(n) >= 8 && len(n) <= 24
}

func normalizeCode(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, " ", "")
	v = strings.ReplaceAll(v, "-", "")
	return v
}

func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := int(sum[offset]&0x7f)<<24 |
		int(sum[offset+1])<<16 |
		int(sum[offset+2])<<8 |
		int(sum[offset+3])
	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := bin % mod
	return fmt.Sprintf("%0*d", digits, code)
}

