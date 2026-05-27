package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SmartFetchResult — расширенный результат загрузки подписки.
// Содержит детекты "лимит устройств" / "нужен Happ UA" / "успех".
type SmartFetchResult struct {
	OK               bool
	Configs          []*VPNConfig
	LimitExceeded    bool   // сервер сказал что превышен лимит устройств
	HappOnly         bool   // сервер требует именно Happ UA / Happ-формат
	UsedUA           string // какой UA сработал
	UsedHWID         bool   // отправляли ли HWID
	TLSInsecureUsed  bool   // пришлось отключать TLS-валидацию (cert сломан/MITM/просрочен)
	ResponsePreview  string
	Error            error
}

// uaRotation — порядок попыток. Стандартные клиенты сначала, потом Happ
// (потому что Happ-сервера часто возвращают JSON-формат, который сложнее парсить).
var uaRotation = []string{
	"v2rayN/6.0",
	"Hiddify-Next/2.0",
	"sing-box/1.13",
	"Clash/1.18",
	"Happ/2.0",
}

// SmartFetchSubscription пытается загрузить подписку используя несколько стратегий:
//   1) Каждый из uaRotation БЕЗ HWID
//   2) Каждый из uaRotation С HWID-заголовком
//   3) Если в ответе обнаружен признак "лимит устройств" — сразу возвращаем LimitExceeded=true
//   4) Если в ответе VLESS-конфиги — успех
//   5) Если только JSON Happ-формата — парсим его (отдельный путь)
//
// TLS-валидация: сначала строгая, при certificate-error — fallback с insecure
// и пометкой TLSInsecureUsed (этот сигнал отдельно идёт в отчёт).
func SmartFetchSubscription(subURL string) *SmartFetchResult {
	res := &SmartFetchResult{}

	// Строгий клиент — проверка цепочки настоящая
	strictClient := newSubFetchClient(false)
	// Insecure клиент — для fallback при сломанном cert
	insecureClient := newSubFetchClient(true)

	hwid := getStableHWID()

	// Этап 1: без HWID
	for _, ua := range uaRotation {
		body, status, insecure, err := fetchOnceWithFallback(strictClient, insecureClient, subURL, ua, "")
		if err != nil {
			res.Error = err
			continue
		}
		if insecure {
			res.TLSInsecureUsed = true
		}
		if status != 200 {
			continue
		}
		if hit, configs, isHapp := analyzeSubBody(body); hit {
			res.OK = true
			res.Configs = configs
			res.HappOnly = isHapp
			res.UsedUA = ua
			res.UsedHWID = false
			res.ResponsePreview = peekResponse(body, 200)
			return res
		}
		if isLimitExceededResponse(body, status) {
			res.LimitExceeded = true
			res.UsedUA = ua
			res.ResponsePreview = peekResponse(body, 400)
			return res
		}
	}

	// Этап 2: добавляем HWID
	for _, ua := range uaRotation {
		body, status, insecure, err := fetchOnceWithFallback(strictClient, insecureClient, subURL, ua, hwid)
		if err != nil {
			res.Error = err
			continue
		}
		if insecure {
			res.TLSInsecureUsed = true
		}
		if status != 200 {
			if status == 403 || status == 429 {
				if isLimitExceededResponse(body, status) {
					res.LimitExceeded = true
					res.UsedUA = ua
					res.UsedHWID = true
					res.ResponsePreview = peekResponse(body, 400)
					return res
				}
			}
			continue
		}
		if hit, configs, isHapp := analyzeSubBody(body); hit {
			res.OK = true
			res.Configs = configs
			res.HappOnly = isHapp
			res.UsedUA = ua
			res.UsedHWID = true
			res.ResponsePreview = peekResponse(body, 200)
			return res
		}
		if isLimitExceededResponse(body, status) {
			res.LimitExceeded = true
			res.UsedUA = ua
			res.UsedHWID = true
			res.ResponsePreview = peekResponse(body, 400)
			return res
		}
	}

	// Ничего не сработало
	return res
}

// newSubFetchClient — http.Client с настраиваемой TLS-валидацией.
// secure=true → проверяем цепочку (продакшен подписки имеют Let's Encrypt cert).
// secure=false → fallback при сломанном/MITM/expired cert; вызывает TLSInsecureUsed
//   флаг в отчёте, чтобы пользователь видел что что-то с cert не так.
func newSubFetchClient(skipVerify bool) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
				MinVersion:         tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		},
	}
}

// fetchOnceWithFallback: сначала строгий запрос, при cert-error — повторение с insecure.
// Возвращает (body, status, insecureUsed, err).
func fetchOnceWithFallback(strict, insecure *http.Client, subURL, ua, hwid string) ([]byte, int, bool, error) {
	body, status, err := fetchOnce(strict, subURL, ua, hwid)
	if err == nil {
		return body, status, false, nil
	}
	if !isCertError(err) {
		return body, status, false, err
	}
	body, status, err = fetchOnce(insecure, subURL, ua, hwid)
	return body, status, true, err
}

func fetchOnce(client *http.Client, subURL, ua, hwid string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	if hwid != "" {
		// Шлём HWID в нескольких вариантах header'ов — разные панели ждут разное:
		//   X-Hwid — Remnawave / Marzban-fork
		//   Hwid — старые сервисы
		//   X-Device-Id — обобщённый
		req.Header.Set("X-Hwid", hwid)
		req.Header.Set("Hwid", hwid)
		req.Header.Set("X-Device-Id", hwid)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	return body, resp.StatusCode, nil
}

// analyzeSubBody определяет — что нам прислал сервер.
// Возвращает (ok, configs, isHappFormat).
//   - ok=true — что-то полезное, configs могут содержать ноды
//   - isHapp=true — это Happ JSON-формат, configs извлечены из outbounds
func analyzeSubBody(body []byte) (bool, []*VPNConfig, bool) {
	if len(body) == 0 {
		return false, nil, false
	}

	// Сначала пытаемся обычным base64/plain путём
	cfgs := parseSubBody(body)
	if len(cfgs) > 0 {
		// Эвристика: если все ноды имеют адрес 0.0.0.0 или 127.0.0.1 — это заглушка
		realCount := 0
		for _, c := range cfgs {
			if c.Address != "0.0.0.0" && c.Address != "127.0.0.1" && c.Address != "" {
				realCount++
			}
		}
		if realCount > 0 {
			return true, cfgs, false
		}
	}

	// Может быть Happ JSON массив
	if happCfgs := parseHappJSON(body); len(happCfgs) > 0 {
		return true, happCfgs, true
	}

	return false, nil, false
}

// parseHappJSON извлекает VPN-серверы из ответа Happ-формата
// (массив объектов с .outbounds[] и .remarks).
func parseHappJSON(body []byte) []*VPNConfig {
	trimmed := strings.TrimSpace(string(body))
	if !strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "{") {
		return nil
	}

	// Парсим как массив "профилей" — это Happ-формат.
	var profiles []happProfile
	if err := json.Unmarshal(body, &profiles); err != nil {
		// Иногда это один объект, не массив
		var single happProfile
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			return nil
		}
		profiles = []happProfile{single}
	}

	var out []*VPNConfig
	for _, p := range profiles {
		for i, ob := range p.Outbounds {
			cfg := happOutboundToConfig(ob, p.Remarks, i)
			if cfg != nil {
				out = append(out, cfg)
			}
		}
	}
	return out
}

type happProfile struct {
	Remarks   string         `json:"remarks"`
	Outbounds []happOutbound `json:"outbounds"`
}

type happOutbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
	Stream   json.RawMessage `json:"streamSettings"`
}

// happOutboundToConfig конвертирует Happ-объект в наш VPNConfig.
// Поддерживает: shadowsocks, trojan, vless. Возвращает nil для других.
func happOutboundToConfig(ob happOutbound, profileRemark string, idx int) *VPNConfig {
	switch ob.Protocol {
	case "shadowsocks":
		var s struct {
			Servers []struct {
				Address  string `json:"address"`
				Port     int    `json:"port"`
				Method   string `json:"method"`
				Password string `json:"password"`
			} `json:"servers"`
		}
		if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Servers) == 0 {
			return nil
		}
		srv := s.Servers[0]
		return &VPNConfig{
			Protocol:  "shadowsocks",
			Address:   srv.Address,
			Port:      srv.Port,
			Method:    srv.Method,
			Password:  srv.Password,
			Transport: "tcp",
			Security:  "none",
			Remark:    fmt.Sprintf("%s · proxy-%d (SS)", profileRemark, idx+1),
		}
	case "trojan":
		var s struct {
			Servers []struct {
				Address  string `json:"address"`
				Port     int    `json:"port"`
				Password string `json:"password"`
			} `json:"servers"`
		}
		if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Servers) == 0 {
			return nil
		}
		cfg := &VPNConfig{
			Protocol:  "trojan",
			Address:   s.Servers[0].Address,
			Port:      s.Servers[0].Port,
			Password:  s.Servers[0].Password,
			Transport: "tcp",
			Security:  "tls",
			Remark:    fmt.Sprintf("%s · proxy-%d (Trojan)", profileRemark, idx+1),
		}
		applyHappStreamSettings(cfg, ob.Stream)
		return cfg
	case "vless":
		var s struct {
			Vnext []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
				Users   []struct {
					ID         string `json:"id"`
					Encryption string `json:"encryption"`
					Flow       string `json:"flow"`
				} `json:"users"`
			} `json:"vnext"`
		}
		if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Vnext) == 0 || len(s.Vnext[0].Users) == 0 {
			return nil
		}
		cfg := &VPNConfig{
			Protocol:   "vless",
			Address:    s.Vnext[0].Address,
			Port:       s.Vnext[0].Port,
			UUID:       s.Vnext[0].Users[0].ID,
			Flow:       s.Vnext[0].Users[0].Flow,
			Encryption: s.Vnext[0].Users[0].Encryption,
			Transport:  "tcp",
			Security:   "none",
			Remark:     fmt.Sprintf("%s · proxy-%d (VLESS)", profileRemark, idx+1),
		}
		applyHappStreamSettings(cfg, ob.Stream)
		return cfg
	}
	return nil
}

// applyHappStreamSettings вынимает поля transport/security/SNI из streamSettings.
func applyHappStreamSettings(cfg *VPNConfig, stream json.RawMessage) {
	if len(stream) == 0 {
		return
	}
	var s struct {
		Network         string `json:"network"`
		Security        string `json:"security"`
		TLSSettings     struct {
			ServerName    string   `json:"serverName"`
			AllowInsecure bool     `json:"allowInsecure"`
			ALPN          []string `json:"alpn"`
			Fingerprint   string   `json:"fingerprint"`
		} `json:"tlsSettings"`
		RealitySettings struct {
			ServerName  string `json:"serverName"`
			PublicKey   string `json:"publicKey"`
			ShortID     string `json:"shortId"`
			Fingerprint string `json:"fingerprint"`
		} `json:"realitySettings"`
		WSSettings struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"wsSettings"`
		GRPCSettings struct {
			ServiceName string `json:"serviceName"`
		} `json:"grpcSettings"`
		TCPSettings struct {
			Header map[string]interface{} `json:"header"`
		} `json:"tcpSettings"`
	}
	if err := json.Unmarshal(stream, &s); err != nil {
		return
	}
	if s.Network != "" {
		cfg.Transport = s.Network
	}
	if s.Security != "" {
		cfg.Security = s.Security
	}
	switch s.Security {
	case "tls":
		cfg.SNI = s.TLSSettings.ServerName
		cfg.Fingerprint = s.TLSSettings.Fingerprint
		if len(s.TLSSettings.ALPN) > 0 {
			cfg.ALPN = strings.Join(s.TLSSettings.ALPN, ",")
		}
	case "reality":
		cfg.SNI = s.RealitySettings.ServerName
		cfg.PublicKey = s.RealitySettings.PublicKey
		cfg.ShortID = s.RealitySettings.ShortID
		cfg.Fingerprint = s.RealitySettings.Fingerprint
		if cfg.Fingerprint == "" {
			cfg.Fingerprint = "chrome"
		}
	}
	if s.Network == "ws" {
		cfg.Path = s.WSSettings.Path
		if h, ok := s.WSSettings.Headers["Host"]; ok {
			cfg.Host = h
		}
	}
	if s.Network == "grpc" {
		cfg.ServiceName = s.GRPCSettings.ServiceName
	}
}

// isLimitExceededResponse — эвристика на ответ "превышен лимит устройств".
func isLimitExceededResponse(body []byte, status int) bool {
	if status == 403 || status == 429 || status == 451 {
		// Эти коды часто означают device limit
		return true
	}
	low := strings.ToLower(string(body))
	keywords := []string{
		"limit exceeded",
		"device limit",
		"limit of devices",
		"too many devices",
		"превышен лимит",
		"лимит устройств",
		"максимальное количество устройств",
		"hwid limit",
		"device_limit_reached",
	}
	for _, k := range keywords {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func peekResponse(body []byte, n int) string {
	s := string(body)
	if len(s) > n {
		s = s[:n] + "..."
	}
	// Чистим непечатные
	out := make([]rune, 0, len(s))
	for _, r := range s {
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
