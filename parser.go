package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type VPNConfig struct {
	Protocol    string
	UUID        string // for vless/vmess
	Password    string // for trojan/shadowsocks
	Address     string
	Port        int

	// Security
	Security    string // tls, reality, none
	SNI         string
	Fingerprint string
	ALPN        string

	// Reality specific
	PublicKey string
	ShortID   string
	SpiderX   string
	Flow      string

	// Transport
	Transport   string // tcp, ws, grpc, xhttp, etc
	Path        string
	Host        string
	ServiceName string
	Mode        string
	HeaderType  string
	Encryption  string

	// Shadowsocks
	Method string

	// Meta
	Remark string
	RawURI string
}

// IsSubscriptionURL проверяет является ли ввод URL подписки
func IsSubscriptionURL(input string) bool {
	input = strings.TrimSpace(input)
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

// FetchSubscription загружает подписку по URL и возвращает список VPN конфигов
func FetchSubscription(subURL string) ([]*VPNConfig, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Попытка 1: запрос как V2RayN (получим links_base64)
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %w", err)
	}
	req.Header.Set("User-Agent", "v2rayN/6.0")
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки подписки: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("сервер вернул код %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %w", err)
	}

	content := strings.TrimSpace(string(body))
	if content == "" {
		return nil, fmt.Errorf("пустой ответ от сервера")
	}

	// Определяем формат: base64 или plain links
	var lines []string
	if looksLikeBase64(content) {
		decoded, err := base64Decode(content)
		if err != nil {
			// Может быть plain text
			lines = strings.Split(content, "\n")
		} else {
			lines = strings.Split(decoded, "\n")
		}
	} else {
		lines = strings.Split(content, "\n")
	}

	var configs []*VPNConfig
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Пропускаем строки которые не похожи на VPN ссылки
		if !strings.Contains(line, "://") {
			continue
		}
		cfg, err := ParseVPNLink(line)
		if err != nil {
			// Пропускаем неизвестные протоколы
			continue
		}
		configs = append(configs, cfg)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("в подписке не найдено ни одного VPN конфига")
	}

	return configs, nil
}

// looksLikeBase64 проверяет похожа ли строка на base64 (нет ://, одна строка)
func looksLikeBase64(s string) bool {
	// Если содержит ://, это plain links
	if strings.Contains(s, "://") {
		return false
	}
	// Если нет переносов строки и состоит из base64 символов
	if strings.ContainsAny(s, "\n\r") {
		// Многострочный — скорее всего plain
		firstLine := strings.SplitN(s, "\n", 2)[0]
		if strings.Contains(firstLine, "://") {
			return false
		}
	}
	return true
}

func ParseVPNLink(uri string) (*VPNConfig, error) {
	uri = strings.TrimSpace(uri)

	if strings.HasPrefix(uri, "vless://") {
		return parseVLESS(uri)
	}
	if strings.HasPrefix(uri, "trojan://") {
		return parseTrojan(uri)
	}
	if strings.HasPrefix(uri, "ss://") {
		return parseShadowsocks(uri)
	}
	if strings.HasPrefix(uri, "vmess://") {
		return parseVMess(uri)
	}

	maxLen := len(uri)
	if maxLen > 20 {
		maxLen = 20
	}
	return nil, fmt.Errorf("неподдерживаемый протокол: %s", uri[:maxLen])
}

func parseVLESS(uri string) (*VPNConfig, error) {
	// vless://UUID@host:port?params#remark
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга VLESS URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}

	params := u.Query()
	remark, _ := url.QueryUnescape(u.Fragment)

	cfg := &VPNConfig{
		Protocol:    "vless",
		UUID:        u.User.Username(),
		Address:     u.Hostname(),
		Port:        port,
		Security:    params.Get("security"),
		SNI:         params.Get("sni"),
		Fingerprint: params.Get("fp"),
		ALPN:        params.Get("alpn"),
		PublicKey:   params.Get("pbk"),
		ShortID:     params.Get("sid"),
		SpiderX:     params.Get("spx"),
		Flow:        params.Get("flow"),
		Transport:   params.Get("type"),
		Path:        params.Get("path"),
		Host:        params.Get("host"),
		ServiceName: params.Get("serviceName"),
		Mode:        params.Get("mode"),
		HeaderType:  params.Get("headerType"),
		Encryption:  params.Get("encryption"),
		Remark:      remark,
		RawURI:      uri,
	}

	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	if cfg.Security == "" {
		cfg.Security = "none"
	}

	return cfg, nil
}

func parseTrojan(uri string) (*VPNConfig, error) {
	// trojan://password@host:port?params#remark
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга Trojan URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}

	params := u.Query()
	remark, _ := url.QueryUnescape(u.Fragment)

	password := u.User.Username()
	if p, ok := u.User.Password(); ok && p != "" {
		password = password + ":" + p
	}

	cfg := &VPNConfig{
		Protocol:    "trojan",
		Password:    password,
		Address:     u.Hostname(),
		Port:        port,
		Security:    params.Get("security"),
		SNI:         params.Get("sni"),
		Fingerprint: params.Get("fp"),
		ALPN:        params.Get("alpn"),
		PublicKey:   params.Get("pbk"),
		ShortID:     params.Get("sid"),
		Transport:   params.Get("type"),
		Path:        params.Get("path"),
		Host:        params.Get("host"),
		ServiceName: params.Get("serviceName"),
		Mode:        params.Get("mode"),
		HeaderType:  params.Get("headerType"),
		Remark:      remark,
		RawURI:      uri,
	}

	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	if cfg.Security == "" {
		cfg.Security = "tls"
	}

	return cfg, nil
}

func parseShadowsocks(uri string) (*VPNConfig, error) {
	// ss://base64(method:password)@host:port#remark
	// or ss://base64(method:password@host:port)#remark (legacy)
	raw := strings.TrimPrefix(uri, "ss://")

	remark := ""
	if idx := strings.LastIndex(raw, "#"); idx != -1 {
		remark, _ = url.QueryUnescape(raw[idx+1:])
		raw = raw[:idx]
	}

	var method, password, host string
	var port int

	if atIdx := strings.LastIndex(raw, "@"); atIdx != -1 {
		encoded := raw[:atIdx]
		hostPort := raw[atIdx+1:]

		decoded, err := base64Decode(encoded)
		if err != nil {
			return nil, fmt.Errorf("ошибка декодирования SS URI: %w", err)
		}

		parts := strings.SplitN(decoded, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("неверный формат SS: ожидается method:password")
		}
		method = parts[0]
		password = parts[1]

		h, p, err := parseHostPort(hostPort)
		if err != nil {
			return nil, err
		}
		host = h
		port = p
	} else {
		decoded, err := base64Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("ошибка декодирования SS URI: %w", err)
		}
		atIdx2 := strings.LastIndex(decoded, "@")
		if atIdx2 == -1 {
			return nil, fmt.Errorf("неверный формат SS URI")
		}
		parts := strings.SplitN(decoded[:atIdx2], ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("неверный формат SS: ожидается method:password")
		}
		method = parts[0]
		password = parts[1]

		h, p, err := parseHostPort(decoded[atIdx2+1:])
		if err != nil {
			return nil, err
		}
		host = h
		port = p
	}

	return &VPNConfig{
		Protocol:  "shadowsocks",
		Method:    method,
		Password:  password,
		Address:   host,
		Port:      port,
		Security:  "none",
		Transport: "tcp",
		Remark:    remark,
		RawURI:    uri,
	}, nil
}

func parseVMess(uri string) (*VPNConfig, error) {
	// vmess://base64(json)
	encoded := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования VMess URI: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &data); err != nil {
		return nil, fmt.Errorf("ошибка парсинга VMess JSON: %w", err)
	}

	port := 443
	if p, ok := data["port"]; ok {
		switch v := p.(type) {
		case float64:
			port = int(v)
		case string:
			port, _ = strconv.Atoi(v)
		}
	}

	cfg := &VPNConfig{
		Protocol:    "vmess",
		UUID:        getString(data, "id"),
		Address:     getString(data, "add"),
		Port:        port,
		Security:    getString(data, "tls"),
		SNI:         getString(data, "sni"),
		Fingerprint: getString(data, "fp"),
		ALPN:        getString(data, "alpn"),
		Transport:   getString(data, "net"),
		Path:        getString(data, "path"),
		Host:        getString(data, "host"),
		HeaderType:  getString(data, "type"),
		Remark:      getString(data, "ps"),
		RawURI:      uri,
	}

	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}

	return cfg, nil
}

// === Helpers ===

func base64Decode(s string) (string, error) {
	// Try standard base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	// Try URL-safe base64
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	// Try without padding
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	return "", fmt.Errorf("не удалось декодировать base64")
}

func parseHostPort(s string) (string, int, error) {
	// Handle [IPv6]:port
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 {
			return "", 0, fmt.Errorf("неверный IPv6 адрес")
		}
		host := s[1:end]
		port := 443
		if len(s) > end+2 && s[end+1] == ':' {
			port, _ = strconv.Atoi(s[end+2:])
		}
		return host, port, nil
	}

	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s, 443, nil
	}
	port, _ := strconv.Atoi(parts[1])
	if port == 0 {
		port = 443
	}
	return parts[0], port, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
