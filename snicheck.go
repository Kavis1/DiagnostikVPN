package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

var popularSNIs = []string{
	"www.google.com",
	"www.microsoft.com",
	"www.apple.com",
	"www.amazon.com",
	"www.cloudflare.com",
	"mail.google.com",
	"cdn.jsdelivr.net",
	"www.github.com",
	"chat.openai.com",
	"www.wikipedia.org",
	"www.youtube.com",
	"www.instagram.com",
}

// testSNIBlocking проверяет SNI из конфига и альтернативные SNI при блокировке
func testSNIBlocking(cfg *VPNConfig) []TestResult {
	var results []TestResult

	if cfg.Security == "none" || cfg.Security == "" {
		return results
	}

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	configSNI := cfg.SNI
	if configSNI == "" {
		configSNI = cfg.Address
	}

	// Тестируем SNI из конфига
	configOK := testSNI(addr, configSNI)

	if configOK {
		results = append(results, TestResult{
			Name:    "SNI проверка",
			Status:  StatusOK,
			Message: fmt.Sprintf("SNI \"%s\" — доступен", configSNI),
		})
		return results
	}

	// SNI из конфига не работает — пробуем альтернативные
	var working []string
	var details []string

	details = append(details, fmt.Sprintf("[FAIL] %s (из конфига)", configSNI))

	for _, sni := range popularSNIs {
		if sni == configSNI {
			continue
		}
		ok := testSNI(addr, sni)
		if ok {
			working = append(working, sni)
			details = append(details, fmt.Sprintf("[OK] %s", sni))
		} else {
			details = append(details, fmt.Sprintf("[FAIL] %s", sni))
		}
	}

	if len(working) > 0 {
		limit := len(working)
		if limit > 3 {
			limit = 3
		}
		results = append(results, TestResult{
			Name: "SNI проверка",
			Status:  StatusWarning,
			Message: fmt.Sprintf("SNI \"%s\" ЗАБЛОКИРОВАН! Рабочие альтернативы: %s",
				configSNI, strings.Join(working[:limit], ", ")),
			Details: strings.Join(details, "\n"),
		})
	} else {
		results = append(results, TestResult{
			Name:    "SNI проверка",
			Status:  StatusError,
			Message: fmt.Sprintf("все SNI заблокированы на %s — вероятна DPI/IP блокировка", addr),
			Details: strings.Join(details, "\n"),
		})
	}

	return results
}

func testSNI(addr, sni string) bool {
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
