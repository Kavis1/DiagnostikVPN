package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// checkSubscriptionURL детально опрашивает sub-URL подписки разными User-Agent'ами
// чтобы выяснить:
//   - доступен ли сервер раздачи конфигов
//   - отдаёт ли он одинаковый ответ всем UA (плохо: 1 сервер для всех клиентов)
//   - какой Content-Type/размер
//   - не блокирует ли провайдер сам HTTP/HTTPS до подписки
func checkSubscriptionURL(subURL string) []TestResult {
	if !IsSubscriptionURL(subURL) {
		return nil
	}

	var results []TestResult
	uas := []struct{ name, ua string }{
		{"Browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		{"v2rayN", "v2rayN/6.0"},
		{"Hiddify", "Hiddify-Next/2.0"},
		{"Clash", "ClashforWindows/0.20"},
		{"sing-box", "sing-box/1.10"},
	}

	for _, u := range uas {
		results = append(results, probeSubURL(subURL, u.name, u.ua))
	}

	return results
}

func probeSubURL(subURL, label, ua string) TestResult {
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return TestResult{
			Name:    "Подписка " + label,
			Status:  StatusError,
			Message: fmt.Sprintf("ошибка запроса: %v", err),
		}
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		msg := err.Error()
		status := StatusError
		// Если HTTP/2 ошибка — может быть DPI/proxy MITM
		if strings.Contains(msg, "TLS") || strings.Contains(msg, "tls") {
			msg = "TLS ошибка: " + msg + " — возможна MITM-инспекция AV/proxy"
		} else if strings.Contains(msg, "timeout") {
			msg = "таймаут — провайдер может блокировать sub-URL"
		} else if strings.Contains(msg, "connection refused") {
			msg = "соединение отклонено — сервер недоступен"
		}
		return TestResult{
			Name:    "Подписка " + label,
			Status:  status,
			Message: msg,
			Latency: elapsed,
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // макс 1MB
	size := len(body)

	ct := resp.Header.Get("Content-Type")
	server := resp.Header.Get("Server")
	contentDisp := resp.Header.Get("Content-Disposition")
	profileTitle := resp.Header.Get("Profile-Title")

	status := StatusOK
	msgParts := []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
	if size > 0 {
		msgParts = append(msgParts, fmt.Sprintf("%d байт", size))
	}
	if resp.StatusCode >= 400 {
		status = StatusError
	} else if resp.StatusCode >= 300 {
		status = StatusWarning
	}

	details := []string{}
	if ct != "" {
		details = append(details, "Content-Type: "+ct)
	}
	if server != "" {
		details = append(details, "Server: "+server)
	}
	if contentDisp != "" {
		details = append(details, "Content-Disposition: "+contentDisp)
	}
	if profileTitle != "" {
		details = append(details, "Profile-Title: "+profileTitle)
	}
	if subInfo := resp.Header.Get("Subscription-Userinfo"); subInfo != "" {
		details = append(details, "Subscription-Userinfo: "+subInfo)
	}
	// hash для сравнения ответов между UA
	if size > 0 {
		details = append(details, fmt.Sprintf("preview: %q", peekBytes(body, 80)))
	}

	return TestResult{
		Name:    "Подписка " + label,
		Status:  status,
		Message: strings.Join(msgParts, ", "),
		Details: strings.Join(details, "\n"),
		Latency: elapsed,
	}
}

func peekBytes(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	preview := string(b[:n])
	// убираем непечатные
	out := make([]rune, 0, len(preview))
	for _, r := range preview {
		if r == '\n' || r == '\r' || r == '\t' {
			out = append(out, ' ')
			continue
		}
		if r < 32 || r == 127 {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
