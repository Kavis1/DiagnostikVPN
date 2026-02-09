package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func runTLSTests(cfg *VPNConfig) []TestResult {
	var results []TestResult

	if cfg.Security == "none" || cfg.Security == "" {
		results = append(results, TestResult{
			Name:    "TLS",
			Status:  StatusInfo,
			Message: "конфигурация без TLS — тест пропущен",
		})
		return results
	}

	results = append(results, testTLSHandshake(cfg))

	if cfg.Security == "reality" {
		results = append(results, testRealityParams(cfg))
	}

	return results
}

func testTLSHandshake(cfg *VPNConfig) TestResult {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Address
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // For diagnostics - connect even with self-signed certs
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.ALPN != "" {
		tlsConfig.NextProtos = strings.Split(cfg.ALPN, ",")
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	elapsed := time.Since(start)

	if err != nil {
		msg := fmt.Sprintf("ошибка TLS handshake: %v", err)
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			msg = "таймаут TLS handshake (возможна DPI блокировка)"
		} else if strings.Contains(err.Error(), "reset") {
			msg = "соединение сброшено при TLS handshake (возможна блокировка)"
		} else if strings.Contains(err.Error(), "certificate") {
			msg = fmt.Sprintf("ошибка сертификата: %v", err)
		} else if strings.Contains(err.Error(), "EOF") {
			msg = "соединение закрыто сервером при TLS handshake"
		}
		return TestResult{
			Name:    "TLS Handshake",
			Status:  StatusError,
			Message: msg,
			Latency: elapsed,
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()

	tlsVersion := "неизвестно"
	switch state.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0"
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1"
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	}

	cipher := tls.CipherSuiteName(state.CipherSuite)

	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = "нет"
	}

	details := fmt.Sprintf("Версия: %s\nCipher: %s\nALPN: %s\nSNI: %s", tlsVersion, cipher, alpn, sni)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		details += fmt.Sprintf("\nСертификат: %s", cert.Subject.CommonName)
		details += fmt.Sprintf("\nИздатель: %s", cert.Issuer.CommonName)
		details += fmt.Sprintf("\nДействителен до: %s", cert.NotAfter.Format("2006-01-02"))
		if time.Now().After(cert.NotAfter) {
			details += " (ИСТЁК!)"
		}
	}

	status := StatusOK
	if state.Version < tls.VersionTLS12 {
		status = StatusWarning
	}

	return TestResult{
		Name:    "TLS Handshake",
		Status:  status,
		Message: fmt.Sprintf("успешно — %s, %s", tlsVersion, cipher),
		Details: details,
		Latency: elapsed,
	}
}

func testRealityParams(cfg *VPNConfig) TestResult {
	var issues []string

	if cfg.PublicKey == "" {
		issues = append(issues, "отсутствует Reality Public Key (pbk)")
	}
	if cfg.ShortID == "" {
		issues = append(issues, "отсутствует Reality Short ID (sid)")
	}
	if cfg.SNI == "" {
		issues = append(issues, "отсутствует SNI (необходим для Reality)")
	}
	if cfg.Fingerprint == "" {
		issues = append(issues, "отсутствует Fingerprint (рекомендуется chrome/firefox)")
	}

	if len(issues) > 0 {
		return TestResult{
			Name:    "Reality параметры",
			Status:  StatusWarning,
			Message: fmt.Sprintf("%d проблем обнаружено", len(issues)),
			Details: strings.Join(issues, "\n"),
		}
	}

	pbkPreview := cfg.PublicKey
	if len(pbkPreview) > 12 {
		pbkPreview = cfg.PublicKey[:8] + "..." + cfg.PublicKey[len(cfg.PublicKey)-4:]
	}

	return TestResult{
		Name:    "Reality параметры",
		Status:  StatusOK,
		Message: fmt.Sprintf("все параметры на месте (pbk: %s, sid: %s)", pbkPreview, cfg.ShortID),
	}
}
