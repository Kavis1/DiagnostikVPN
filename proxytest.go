package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SiteCheck описывает один сайт, который мы пытаемся открыть через VPN-туннель.
type SiteCheck struct {
	Site      string
	Host      string
	Port      int
	HTTPPath  string
	UA        string
	OkCodes   []int  // допустимые HTTP-коды (200, 301, 302, 403 — некоторые сайты не любят HEAD)
	IPCountry string // ожидаемая страна — для проверки exit-IP
}

// CommonSites — список самых частых сайтов которые пользователи проверяют
// после подключения VPN. Все на HTTPS, поэтому достаточно :443.
var CommonSites = []SiteCheck{
	{Site: "YouTube", Host: "www.youtube.com", Port: 443, HTTPPath: "/", OkCodes: []int{200, 204, 301, 302, 303}},
	{Site: "Gemini (Google AI)", Host: "gemini.google.com", Port: 443, HTTPPath: "/", OkCodes: []int{200, 301, 302, 303}},
	{Site: "TikTok", Host: "www.tiktok.com", Port: 443, HTTPPath: "/", OkCodes: []int{200, 301, 302, 403}},
	{Site: "Discord", Host: "discord.com", Port: 443, HTTPPath: "/", OkCodes: []int{200, 301, 302}},
	{Site: "Telegram Web", Host: "web.telegram.org", Port: 443, HTTPPath: "/", OkCodes: []int{200, 301, 302}},
	{Site: "Roblox", Host: "www.roblox.com", Port: 443, HTTPPath: "/", OkCodes: []int{200, 301, 302, 403}},
	{Site: "Cloudflare 1.1.1.1 (контроль)", Host: "1.1.1.1", Port: 443, HTTPPath: "/", OkCodes: []int{200, 301, 302}},
}

// SiteResult — результат проверки одного сайта через ключ.
type SiteResult struct {
	Site       string
	Reachable  bool
	StatusCode int
	BodySize   int
	Latency    time.Duration
	Error      string
}

// KeyVerdict — итоговая оценка одного ключа.
type KeyVerdict struct {
	ConfigName    string
	ServerAddr    string
	SitesPassed   int
	SitesTotal    int
	AvgLatency    time.Duration
	PacketLoss    float64 // 0..100 %
	AvgPing       time.Duration
	BandwidthKBps float64
	ExitIP        string
	ExitCountry   string
	Verdict       string // OK / PARTIAL / FAIL / VISION_UNSUPPORTED / PROXY_UNSUPPORTED
	Recommendation string
	SiteResults   []SiteResult
}

// testKeyAgainstSites гоняет один ключ против списка сайтов.
// Параллелит запросы по сайтам через goroutines для скорости.
// Если передан sb (sing-box proxy) — используем его для всех сайтов.
// Если sb==nil — fallback на Go-native VLESS/Trojan dialer.
func testKeyAgainstSites(cfg *VPNConfig, sites []SiteCheck, sb ProxyBackend) []SiteResult {
	results := make([]SiteResult, len(sites))
	var wg sync.WaitGroup
	for i, s := range sites {
		wg.Add(1)
		go func(idx int, site SiteCheck) {
			defer wg.Done()
			results[idx] = checkSiteThroughVPN(cfg, site, sb)
		}(i, s)
	}
	wg.Wait()
	return results
}

// dialAnyProxy выбирает между sing-box (SOCKS5) и Go-native dialer.
func dialAnyProxy(cfg *VPNConfig, host string, port int, sb ProxyBackend) (net.Conn, error) {
	if sb != nil {
		return sb.Dial(host, port)
	}
	return dialThroughVPN(cfg, host, port)
}

// checkSiteThroughVPN: подключается через VPN → TLS до target → HEAD → ответ.
func checkSiteThroughVPN(cfg *VPNConfig, site SiteCheck, sb ProxyBackend) SiteResult {
	start := time.Now()

	conn, err := dialAnyProxy(cfg, site.Host, site.Port, sb)
	if err != nil {
		return SiteResult{
			Site:    site.Site,
			Error:   "tunnel: " + err.Error(),
			Latency: time.Since(start),
		}
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		// non-fatal
	}

	// Оборачиваем в TLS — целевой сайт всё равно HTTPS.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         site.Host,
		InsecureSkipVerify: false, // для целевых сайтов проверяем настоящую цепочку
		MinVersion:         tls.VersionTLS12,
	})

	if err := tlsConn.Handshake(); err != nil {
		return SiteResult{Site: site.Site, Error: "TLS: " + err.Error(), Latency: time.Since(start)}
	}
	defer tlsConn.Close()

	req, _ := http.NewRequest("HEAD", "https://"+site.Host+site.HTTPPath, nil)
	ua := site.UA
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	if err := req.Write(tlsConn); err != nil {
		return SiteResult{Site: site.Site, Error: "request write: " + err.Error(), Latency: time.Since(start)}
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		// Некоторые сервера падают на HEAD — пробуем GET
		// (на этом же соединении уже не получится — оно дохлое)
		return SiteResult{Site: site.Site, Error: "response: " + err.Error(), Latency: time.Since(start)}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	okStatus := false
	for _, c := range site.OkCodes {
		if resp.StatusCode == c {
			okStatus = true
			break
		}
	}
	// 200..399 — практически всегда успех
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		okStatus = true
	}

	return SiteResult{
		Site:       site.Site,
		Reachable:  okStatus,
		StatusCode: resp.StatusCode,
		BodySize:   len(bodyBytes),
		Latency:    time.Since(start),
	}
}

// dialThroughVPN устанавливает TCP-туннель через VPN до целевого host:port.
// Поддерживает VLESS-TCP и Trojan-TCP. Для других протоколов/транспортов возвращает
// ошибку с пояснением — это не баг, а ограничение Go-only тестов без xray-клиента.
func dialThroughVPN(cfg *VPNConfig, host string, port int) (net.Conn, error) {
	// WS/gRPC/xhttp — не поддерживаем (нужен HTTP-фронтенд)
	if cfg.Transport != "" && cfg.Transport != "tcp" && cfg.Transport != "raw" {
		return nil, fmt.Errorf("транспорт %s требует полноценный xray-клиент", cfg.Transport)
	}
	switch cfg.Protocol {
	case "vless":
		return dialVLESS(cfg, host, port)
	case "trojan":
		return dialTrojan(cfg, host, port)
	default:
		return nil, fmt.Errorf("протокол %s в этом тесте не поддерживается (только VLESS/Trojan TCP)", cfg.Protocol)
	}
}

func dialVLESS(cfg *VPNConfig, host string, port int) (net.Conn, error) {
	tlsConn, err := getTLSConn(cfg)
	if err != nil {
		return nil, err
	}

	uuid, err := parseUUID(cfg.UUID)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("invalid UUID: %w", err)
	}

	var header []byte
	header = append(header, 0) // VLESS version 0
	header = append(header, uuid[:]...)

	// Addons (flow)
	if cfg.Flow != "" {
		flowBytes := []byte(cfg.Flow)
		addonBuf := []byte{0x0a, byte(len(flowBytes))}
		addonBuf = append(addonBuf, flowBytes...)
		header = append(header, byte(len(addonBuf)))
		header = append(header, addonBuf...)
	} else {
		header = append(header, 0)
	}

	header = append(header, 0x01) // CMD: TCP CONNECT
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	header = append(header, portBuf...)
	header = append(header, 0x02) // ATYP: domain
	header = append(header, byte(len(host)))
	header = append(header, []byte(host)...)

	if err := tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		// non-fatal
	}
	if _, err := tlsConn.Write(header); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("vless header write: %w", err)
	}
	if err := tlsConn.SetWriteDeadline(time.Time{}); err != nil {
		// non-fatal
	}

	return &vlessConn{Conn: tlsConn, needSkipHeader: true}, nil
}

// vlessConn — обёртка над net.Conn, которая при первом Read'е пропускает
// VLESS response header (version + addon-len + addon), чтобы потребитель
// видел чистый payload-стрим (полезно для http.ReadResponse).
type vlessConn struct {
	net.Conn
	mu             sync.Mutex
	needSkipHeader bool
	leftover       []byte
}

func (v *vlessConn) Read(p []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.needSkipHeader {
		head := make([]byte, 2)
		if _, err := io.ReadFull(v.Conn, head); err != nil {
			return 0, fmt.Errorf("vless response header: %w", err)
		}
		// version байт не обязательно 0 — Vision может вернуть payload сразу
		if head[0] != 0 && head[0] != 1 {
			// Если в первом байте уже видим HTTP/TLS data — кладём это в leftover
			v.leftover = append(v.leftover, head...)
			v.needSkipHeader = false
		} else {
			addonLen := int(head[1])
			if addonLen > 0 {
				skip := make([]byte, addonLen)
				if _, err := io.ReadFull(v.Conn, skip); err != nil {
					return 0, fmt.Errorf("vless addon: %w", err)
				}
			}
			v.needSkipHeader = false
		}
	}

	if len(v.leftover) > 0 {
		n := copy(p, v.leftover)
		v.leftover = v.leftover[n:]
		return n, nil
	}
	return v.Conn.Read(p)
}

func dialTrojan(cfg *VPNConfig, host string, port int) (net.Conn, error) {
	tlsConn, err := getTLSConn(cfg)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum224([]byte(cfg.Password))
	hexHash := hex.EncodeToString(hash[:])

	var header []byte
	header = append(header, []byte(hexHash)...)
	header = append(header, 0x0d, 0x0a)
	header = append(header, 0x01) // CONNECT
	header = append(header, 0x03) // ATYP: domain
	header = append(header, byte(len(host)))
	header = append(header, []byte(host)...)

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	header = append(header, portBuf...)
	header = append(header, 0x0d, 0x0a)

	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := tlsConn.Write(header); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("trojan header write: %w", err)
	}
	tlsConn.SetWriteDeadline(time.Time{})

	return tlsConn, nil
}

// supportsProxyTest возвращает true только для конфигов, которые мы умеем
// проксировать в Go-only режиме. Vision с TCP пробуем но предупреждаем.
func supportsProxyTest(cfg *VPNConfig) (bool, string) {
	if cfg.Protocol != "vless" && cfg.Protocol != "trojan" {
		return false, fmt.Sprintf("протокол %s не поддерживается без xray-клиента", strings.ToUpper(cfg.Protocol))
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" && cfg.Transport != "raw" {
		return false, fmt.Sprintf("транспорт %s требует HTTP-фронтенд (sing-box/xray)", cfg.Transport)
	}
	if cfg.Flow == "xtls-rprx-vision" {
		return true, "Vision flow — результаты ориентировочные (нужен xray-клиент для точного теста)"
	}
	return true, ""
}
