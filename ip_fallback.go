package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// publicResolvers — публичные DNS которые используем для fallback,
// когда системный (провайдерский) DNS не работает / отдаёт другой ответ.
var publicResolvers = []struct {
	addr string
	name string
}{
	{"1.1.1.1:53", "Cloudflare"},
	{"8.8.8.8:53", "Google"},
	{"9.9.9.9:53", "Quad9"},
}

// resolveViaPublicDNS пытается получить IP хоста через публичные DNS,
// игнорируя системный (провайдерский) DNS. Возвращает первый успешный набор IP.
func resolveViaPublicDNS(host string) (ips []string, viaDNS string, err error) {
	for _, dns := range publicResolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "udp", dns.addr)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got, lookupErr := r.LookupHost(ctx, host)
		cancel()
		if lookupErr == nil && len(got) > 0 {
			// Фильтруем IPv4 (TLS dial к IPv6 чаще ломается на Win)
			v4 := make([]string, 0, len(got))
			for _, ip := range got {
				if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
					v4 = append(v4, ip)
				}
			}
			if len(v4) > 0 {
				return v4, dns.name, nil
			}
			return got, dns.name, nil
		}
		err = lookupErr
	}
	if err == nil {
		err = fmt.Errorf("ни один публичный DNS не разрешил %s", host)
	}
	return nil, "", err
}

// testNodeIPFallback пробует достучаться до ноды напрямую по IP с правильным SNI.
// Это даёт ответ на вопрос: блокирует провайдер сам IP или только DNS/SNI домена?
//
// Запускается ТОЛЬКО когда обычное подключение по доменному имени не удалось —
// иначе теста нет смысла.
func testNodeIPFallback(cfg *VPNConfig) TestResult {
	if net.ParseIP(cfg.Address) != nil {
		return TestResult{
			Name:    "IP fallback",
			Status:  StatusInfo,
			Message: "сервер задан IP-адресом — fallback не нужен",
		}
	}

	ips, viaDNS, err := resolveViaPublicDNS(cfg.Address)
	if err != nil {
		return TestResult{
			Name:    "IP fallback",
			Status:  StatusError,
			Message: "публичные DNS тоже не разрешили домен — возможно домен снят с обслуживания",
			Details: err.Error(),
		}
	}

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Address
	}

	var working []string
	var details []string
	details = append(details, fmt.Sprintf("Резолв через %s DNS: %s", viaDNS, strings.Join(ips, ", ")))
	details = append(details, fmt.Sprintf("SNI в TLS: %s", sni))

	port := cfg.Port
	for _, ip := range ips {
		start := time.Now()
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		elapsed := time.Since(start)
		if err != nil {
			details = append(details, fmt.Sprintf("[FAIL] %s:%d → %v (%s)", ip, port, err, elapsed.Round(time.Millisecond)))
			continue
		}
		conn.Close()
		working = append(working, ip)
		details = append(details, fmt.Sprintf("[OK]   %s:%d → TLS handshake успешен (%s)", ip, port, elapsed.Round(time.Millisecond)))
	}

	if len(working) == 0 {
		return TestResult{
			Name:    "IP fallback",
			Status:  StatusError,
			Message: fmt.Sprintf("ни один IP не пускает — IP-блокировка или сервер недоступен (IP проверены: %s)",
				strings.Join(ips, ", ")),
			Details: strings.Join(details, "\n"),
		}
	}

	return TestResult{
		Name:   "IP fallback",
		Status: StatusOK,
		Message: fmt.Sprintf("%d/%d IP доступны напрямую → провайдер блокирует ИМЕННО ДОМЕН (DNS/SNI), а не IP. "+
			"Решение: пропишите %s → %s в hosts-файл, или попросите выдать ключ с IP вместо домена.",
			len(working), len(ips), cfg.Address, working[0]),
		Details: strings.Join(details, "\n"),
	}
}

// fetchSubscriptionViaIP пытается загрузить sub-URL через IP домена (с правильным SNI/Host).
// Используется когда обычный FetchSubscription упал — например провайдер блокирует
// именно домен раздачи подписок.
//
// Возвращает: список TestResult с диагностикой + список спарсенных конфигов (если получилось).
func fetchSubscriptionViaIP(originalURL string) ([]TestResult, []*VPNConfig) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return []TestResult{{
			Name:    "Подписка via IP",
			Status:  StatusError,
			Message: "невалидный URL: " + err.Error(),
		}}, nil
	}
	host := u.Hostname()
	if host == "" {
		return nil, nil
	}
	if net.ParseIP(host) != nil {
		// Уже IP, fallback бессмыслен
		return []TestResult{{
			Name:    "Подписка via IP",
			Status:  StatusInfo,
			Message: "sub-URL уже задан IP — fallback не нужен",
		}}, nil
	}

	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		if p, perr := strconv.Atoi(u.Port()); perr == nil {
			port = p
		}
	}

	var results []TestResult

	ips, viaDNS, err := resolveViaPublicDNS(host)
	if err != nil {
		results = append(results, TestResult{
			Name:    "Подписка via IP",
			Status:  StatusError,
			Message: "публичные DNS не разрешили домен подписки — возможно сервер снят с DNS",
			Details: err.Error(),
		})
		return results, nil
	}

	results = append(results, TestResult{
		Name:    "Подписка via IP — резолв",
		Status:  StatusInfo,
		Message: fmt.Sprintf("через %s DNS получено: %s", viaDNS, strings.Join(ips, ", ")),
	})

	for _, ip := range ips {
		ipFixed := ip // capture для closure

		// 1) Сначала пробуем С НАСТОЯЩЕЙ валидацией сертификата.
		//    IP получен от публичного DNS (Cloudflare/Google) — это authoritative,
		//    подписочный сервер обычно имеет Let's Encrypt cert на верном домене,
		//    отключать проверку не нужно.
		resp, latency, err := doSubURLFetchViaIP(originalURL, host, ipFixed, port, false)

		// 2) Если упало ИМЕННО из-за сертификата — повторим со снятой проверкой
		//    и явной пометкой "cert ошибка". Это нужно чтобы различать:
		//    "сертификат сломан/просрочен/MITM" vs "сервер вообще недоступен".
		insecureUsed := false
		if err != nil && isCertError(err) {
			resp, latency, err = doSubURLFetchViaIP(originalURL, host, ipFixed, port, true)
			insecureUsed = true
		}

		if err != nil {
			results = append(results, TestResult{
				Name:    fmt.Sprintf("Подписка via IP %s", ipFixed),
				Status:  StatusError,
				Message: truncateStr(err.Error(), 120),
				Latency: latency,
			})
			continue
		}

		if insecureUsed {
			results = append(results, TestResult{
				Name:    fmt.Sprintf("Подписка via IP %s", ipFixed),
				Status:  StatusWarning,
				Message: "TLS-сертификат не прошёл валидацию — возможна MITM-инспекция от провайдера/AV или просроченный cert у сервиса. Ответ всё же получен в insecure-режиме.",
			})
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()

		if resp.StatusCode != 200 {
			results = append(results, TestResult{
				Name:    fmt.Sprintf("Подписка via IP %s", ipFixed),
				Status:  StatusWarning,
				Message: fmt.Sprintf("HTTP %d, %d байт", resp.StatusCode, len(body)),
				Latency: latency,
			})
			continue
		}

		// Парсим как подписку
		configs := parseSubBody(body)
		if len(configs) == 0 {
			results = append(results, TestResult{
				Name:    fmt.Sprintf("Подписка via IP %s", ipFixed),
				Status:  StatusWarning,
				Message: fmt.Sprintf("HTTP 200, %d байт — но в ответе не найдено VPN-конфигов", len(body)),
				Latency: latency,
			})
			continue
		}

		results = append(results, TestResult{
			Name:   fmt.Sprintf("Подписка via IP %s", ipFixed),
			Status: StatusOK,
			Message: fmt.Sprintf("ОТВЕТ ПОЛУЧЕН через IP — %d конфигов. "+
				"Провайдер блокирует ИМЕННО ДОМЕН %s, IP открыт.", len(configs), host),
			Details: fmt.Sprintf("Решение: пропишите в hosts-файл строку:\n  %s %s\n"+
				"или попросите поддержку выдать sub-URL с прямым IP.", ipFixed, host),
			Latency: latency,
		})
		return results, configs
	}

	return results, nil
}

// doSubURLFetchViaIP делает один HTTPS-запрос к sub-URL через указанный IP с правильным SNI/Host.
// secure=false (default): валидация цепочки сертификата ВКЛЮЧЕНА.
// secure=true: цепочка не проверяется — fallback для случая когда есть подозрение на MITM/сломанный cert.
func doSubURLFetchViaIP(originalURL, sniHost, ip string, port int, skipVerify bool) (*http.Response, time.Duration, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Любой Dial этого transport уходит на конкретный IP — игнорируем системный DNS.
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp",
				net.JoinHostPort(ip, strconv.Itoa(port)))
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 12 * time.Second,
	}
	client := &http.Client{Timeout: 18 * time.Second, Transport: transport}

	req, err := http.NewRequest("GET", originalURL, nil)
	if err != nil {
		return nil, 0, err
	}
	// http.NewRequest проставляет Host = original host автоматически — именно это нам и нужно.
	req.Header.Set("User-Agent", "v2rayN/6.0")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	return resp, latency, err
}

// isCertError грубо определяет — упал ли запрос именно из-за TLS-сертификата
// (а не connection refused / timeout / DNS).
func isCertError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	keywords := []string{
		"x509", "certificate", "tls: bad", "unknown authority",
		"signed by unknown", "certificate has expired",
		"hostname doesn't match", "doesn't contain any ip sans",
		"is valid for", "certificate is not trusted",
	}
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// parseSubBody — выделена из FetchSubscription чтобы можно было переиспользовать
// (логика: base64 detect → decode → split lines → ParseVPNLink каждую).
func parseSubBody(body []byte) []*VPNConfig {
	content := strings.TrimSpace(string(body))
	if content == "" {
		return nil
	}
	var lines []string
	if looksLikeBase64(content) {
		if dec, err := base64Decode(content); err == nil {
			lines = strings.Split(dec, "\n")
		} else {
			lines = strings.Split(content, "\n")
		}
	} else {
		lines = strings.Split(content, "\n")
	}
	var configs []*VPNConfig
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "://") {
			continue
		}
		if cfg, err := ParseVPNLink(line); err == nil {
			configs = append(configs, cfg)
		}
	}
	return configs
}
