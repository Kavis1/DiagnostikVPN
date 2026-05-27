package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// runInteractiveOnly — режим БЕЗ автотестов. Парсим подписку, показываем меню,
// пользователь выбирает ноду, поднимаем её как реальный системный прокси,
// затем цикл custom URL'ов.
func runInteractiveOnly(configs []*VPNConfig) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println(colorBold + "============================================================" + colorReset)
	fmt.Println(colorBold + "  ТОЛЬКО ИНТЕРАКТИВНЫЙ РЕЖИМ (без автотестов)" + colorReset)
	fmt.Println(colorBold + "============================================================" + colorReset)
	fmt.Println()
	fmt.Printf("Загружено %d ключей из подписки. Выберите ноду для туннеля:\n", len(configs))
	fmt.Println()

	// Распечатываем нумерованный список
	for i, cfg := range configs {
		name := cfg.Remark
		if name == "" {
			name = fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
		}
		proto := strings.ToUpper(cfg.Protocol)
		if cfg.Transport != "" && cfg.Transport != "tcp" {
			proto += "+" + strings.ToUpper(cfg.Transport)
		}
		if cfg.Security == "reality" {
			proto += "+Reality"
		}
		if cfg.Flow == "xtls-rprx-vision" {
			proto += "+Vision"
		}
		fmt.Printf("  %s%2d.%s %-44s  %s%s%s\n",
			colorCyan, i+1, colorReset,
			truncateStr(name, 44),
			colorDim, proto, colorReset)
	}
	fmt.Println()

	idx, ok := promptChoice(reader, len(configs))
	if !ok {
		return
	}
	chosen := configs[idx]

	v := KeyVerdict{
		ConfigName: chosen.Remark,
		ServerAddr: fmt.Sprintf("%s:%d", chosen.Address, chosen.Port),
	}
	if v.ConfigName == "" {
		v.ConfigName = v.ServerAddr
	}

	runManualTunnelCheck(chosen, v, reader)

	// Custom URL цикл
	view := []rankedView{{name: v.ConfigName, cfg: chosen}}
	for {
		fmt.Println()
		fmt.Println("Проверить конкретный URL через выбранный ключ?")
		fmt.Println("Введите URL или Enter чтобы пропустить:")
		fmt.Print("> ")
		urlInput, _ := reader.ReadString('\n')
		urlInput = strings.TrimSpace(urlInput)
		if urlInput == "" {
			break
		}
		runCustomURLCheck(urlInput, view)
	}

	// Финальный шаг — TUN-troubleshooter (here мы знаем только выбранный ключ, на нём и тестируем TUN)
	fmt.Println()
	if askYesNo(reader, "Запустить мастер «приложения не ходят через VPN»?") {
		report := runTunTroubleshooter(chosen)
		appendTunReport(report)
	}

	fmt.Println()
	fmt.Println(colorGreen + "Интерактивный режим завершён." + colorReset)
}

// appendTunReport дописывает финальную секцию мастера в diagnostik_report.txt
// (в самый конец, чтобы поддержка увидела весь контекст вместе с остальным отчётом).
func appendTunReport(r *TunReport) {
	if r == nil || !r.Used {
		return
	}
	text := formatTunReportForFile(r)
	if text == "" {
		return
	}
	const reportFile = "diagnostik_report.txt"
	f, err := os.OpenFile(reportFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// Если файла нет — создаём заново (например при -only-interactive)
		f, err = os.OpenFile(reportFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Printf("%sНе удалось записать отчёт TUN-мастера: %v%s\n", colorYellow, err, colorReset)
			return
		}
		// UTF-8 BOM
		f.Write([]byte{0xEF, 0xBB, 0xBF})
		fmt.Fprintf(f, "DiagnostikVPN v%s — отчёт TUN-мастера (запущен отдельно от основной диагностики)\n",
			version)
		fmt.Fprintf(f, "Дата: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	defer f.Close()
	f.WriteString(text)
	fmt.Printf("%s✓ Результаты мастера дописаны в %s%s\n", colorGreen, reportFile, colorReset)
}

// promptChoice — спрашивает номер ноды (1-based), валидирует.
// Возвращает 0-based индекс и флаг ok=false если пользователь отказался.
func promptChoice(reader *bufio.Reader, total int) (int, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Printf("Номер ноды (1-%d) или 'q' для выхода: ", total)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || strings.ToLower(line) == "q" || strings.ToLower(line) == "quit" {
			return 0, false
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 1 || idx > total {
			fmt.Printf("%sНеверный номер. Попробуйте ещё раз.%s\n", colorRed, colorReset)
			continue
		}
		return idx - 1, true
	}
	return 0, false
}

// askYesNo показывает вопрос и возвращает true/false.
func askYesNo(reader *bufio.Reader, prompt string) bool {
	fmt.Print(prompt + " [y/n]> ")
	line, _ := reader.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes" || line == "д" || line == "да"
}

// runInteractiveStage запускается ПОСЛЕ всех автоматических тестов.
// Этап 1: предлагает поднять лучший рабочий ключ как реальный системный
// прокси и открыть браузер для ручной проверки сайтов.
// Этап 2: даёт ввести любой URL и проверить открывается ли он через все рабочие ключи.
// Этап 3: для .ru/.рф доменов сразу сообщает "VPN намеренно отключён".
func runInteractiveStage(verdicts []KeyVerdict, configs []*VPNConfig) {
	if len(verdicts) == 0 {
		return
	}

	type rankedKey struct {
		idx     int
		verdict KeyVerdict
		cfg     *VPNConfig
		score   int
	}
	var ranked []rankedKey
	for i, v := range verdicts {
		s := verdictScore(v.Verdict)
		if s <= 0 {
			continue
		}
		var cfg *VPNConfig
		if i < len(configs) {
			cfg = configs[i]
		}
		ranked = append(ranked, rankedKey{i, v, cfg, s})
	}

	if len(ranked) == 0 {
		fmt.Printf("\n%sИнтерактивный режим пропущен — нет ни одного рабочего ключа.%s\n",
			colorYellow, colorReset)
		return
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		// При равном score предпочитаем меньшие потери и больший BW
		return ranked[i].verdict.BandwidthKBps > ranked[j].verdict.BandwidthKBps
	})

	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println(colorBold + "============================================================" + colorReset)
	fmt.Println(colorBold + "  ИНТЕРАКТИВНАЯ ПРОВЕРКА (ручная)" + colorReset)
	fmt.Println(colorBold + "============================================================" + colorReset)
	fmt.Println()
	fmt.Println("Автотесты показали HTTP 200/301 — но это не гарантия что сайт реально")
	fmt.Println("работает (видео грузится, страница рендерится). Можно проверить руками.")
	fmt.Println()
	fmt.Printf("Запустить лучший ключ %s%s%s [%s, BW %.0f KB/s] как системный прокси?\n",
		colorCyan, ranked[0].verdict.ConfigName, colorReset,
		ranked[0].verdict.Verdict, ranked[0].verdict.BandwidthKBps)
	fmt.Print("[y/n]> ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "y" || ans == "yes" || ans == "д" || ans == "да" {
		runManualTunnelCheck(ranked[0].cfg, ranked[0].verdict, reader)
	}

	// Цикл проверки custom URL
	for {
		fmt.Println()
		fmt.Println("Проверить конкретный URL через все рабочие ключи?")
		fmt.Println("Введите URL (например https://www.netflix.com) или Enter чтобы выйти:")
		fmt.Print("> ")
		urlInput, _ := reader.ReadString('\n')
		urlInput = strings.TrimSpace(urlInput)
		if urlInput == "" {
			break
		}

		view := make([]rankedView, 0, len(ranked))
		for _, r := range ranked {
			if r.cfg == nil {
				continue
			}
			view = append(view, rankedView{r.verdict.ConfigName, r.cfg})
		}
		runCustomURLCheck(urlInput, view)
	}

	// Финальный шаг — TUN-troubleshooter (свой TUN запускается на лучшем sing-box-совместимом ключе)
	fmt.Println()
	if askYesNo(reader, "У вас не работают приложения (Discord, игры) через VPN, хотя сайты в браузере открываются?") {
		best := pickBestCfgForTUN(verdicts, configs)
		report := runTunTroubleshooter(best)
		appendTunReport(report)
	}
}

func verdictScore(v string) int {
	switch v {
	case "EXCELLENT":
		return 5
	case "OK":
		return 4
	case "PARTIAL":
		return 3
	case "POOR":
		return 2
	}
	return 0
}

// runManualTunnelCheck поднимает sing-box/xray в mixed (HTTP+SOCKS) inbound,
// настраивает Windows system proxy на этот endpoint, ждёт Enter, восстанавливает.
func runManualTunnelCheck(cfg *VPNConfig, v KeyVerdict, reader *bufio.Reader) {
	if cfg == nil {
		fmt.Printf("%sОшибка: нет конфигурации для лучшего ключа%s\n", colorRed, colorReset)
		return
	}

	// Берём свободный порт из ОС вместо фиксированного 18080 — иначе при
	// конфликте (Jupyter, Webpack, другая instance тулзы) программа упадёт.
	mixedPort, err := getFreeTCPPort()
	if err != nil {
		fmt.Printf("%sНе удалось выбрать свободный порт: %v%s\n", colorRed, err, colorReset)
		return
	}

	fmt.Println()
	fmt.Printf("Поднимаю backend (HTTP+SOCKS) на %s127.0.0.1:%d%s...\n",
		colorCyan, mixedPort, colorReset)

	sb, err := startMixedBackend(cfg, mixedPort)
	if err != nil {
		fmt.Printf("%sНе удалось запустить backend: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer sb.Stop()

	fmt.Printf("%s✓ %s запущен%s — ключ %s%s%s\n",
		colorGreen, sb.BackendName(), colorReset, colorCyan, v.ConfigName, colorReset)

	prevState, err := setWindowsProxy(fmt.Sprintf("127.0.0.1:%d", mixedPort))
	if err != nil {
		fmt.Printf("%sНе удалось включить системный прокси: %v%s\n", colorYellow, err, colorReset)
		fmt.Printf("Настройте вручную: HTTP/SOCKS прокси на %s127.0.0.1:%d%s\n",
			colorCyan, mixedPort, colorReset)
	} else {
		fmt.Printf("%s✓ Системный прокси Windows установлен на 127.0.0.1:%d%s\n",
			colorGreen, mixedPort, colorReset)
		defer restoreWindowsProxy(prevState)
	}

	// Quick health check
	if ip := quickProxyIPCheck(sb.SocksAddr()); ip != "" {
		fmt.Printf("  Exit IP через туннель: %s%s%s\n", colorGreen, ip, colorReset)
	}

	fmt.Println()
	fmt.Println(colorBold + "Теперь:" + colorReset)
	fmt.Println("  1. Откройте Chrome / Edge / Firefox")
	fmt.Println("  2. Зайдите на сайт который хотите проверить (YouTube, Discord и т.д.)")
	fmt.Println("  3. Убедитесь что страницы РЕАЛЬНО грузятся, видео воспроизводится")
	fmt.Println()
	fmt.Println("Когда закончите — нажмите Enter здесь, и я выключу прокси.")
	fmt.Print("> ")
	reader.ReadString('\n')

	fmt.Println("Останавливаю backend и восстанавливаю настройки прокси...")
}

type rankedView struct {
	name string
	cfg  *VPNConfig
}

// runCustomURLCheck — для одного URL гонит через все рабочие ключи.
func runCustomURLCheck(rawURL string, ranked []rankedView) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		fmt.Printf("%sНевалидный URL: %v%s\n", colorRed, err, colorReset)
		return
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		fmt.Printf("%sНе удалось извлечь домен из URL%s\n", colorRed, colorReset)
		return
	}

	if isRussianDomain(host) {
		fmt.Println()
		fmt.Printf("%s%s>> Домен %s — российский (.ru/.рф/.su/.москва)%s\n",
			colorBold, colorYellow, host, colorReset)
		fmt.Println()
		fmt.Println("  Многие VPN-сервисы НАМЕРЕННО ИСКЛЮЧАЮТ маршрутизацию российских")
		fmt.Println("  доменов через свои выходные узлы — чтобы не попасть в реестр")
		fmt.Println("  Роскомнадзора (proxy для .ru трафика быстро блокируется).")
		fmt.Println()
		fmt.Println("  Если ваш сервис делает так же — на эти домены VPN работать не будет")
		fmt.Println("  by design. Используйте split-tunneling в VPN-клиенте или отключайте")
		fmt.Println("  VPN для российских ресурсов.")
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Printf("Проверяю %s%s%s через %d рабочих ключей...\n",
		colorCyan, rawURL, colorReset, len(ranked))
	fmt.Println()

	for _, r := range ranked {
		if r.cfg == nil {
			continue
		}
		fmt.Printf("  %s%-32s%s → ", colorCyan, truncateStr(r.name, 32), colorReset)
		ok, code, lat, errMsg := probeURLThroughBackend(r.cfg, rawURL)
		if ok {
			fmt.Printf("%s[OK]%s HTTP %d, %s\n",
				colorGreen, colorReset, code, lat.Round(time.Millisecond))
		} else {
			fmt.Printf("%s[FAIL]%s %s (%s)\n",
				colorRed, colorReset, errMsg, lat.Round(time.Millisecond))
		}
	}
}

// probeURLThroughBackend поднимает backend для cfg, делает HEAD запрос через SOCKS5.
func probeURLThroughBackend(cfg *VPNConfig, rawURL string) (bool, int, time.Duration, string) {
	start := time.Now()

	sb, err := newProxyBackend(cfg)
	if err != nil {
		return false, 0, time.Since(start), "backend: " + truncateStr(err.Error(), 60)
	}
	defer sb.Stop()

	dialer, err := proxy.SOCKS5("tcp", sb.SocksAddr(), nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return false, 0, time.Since(start), "socks: " + err.Error()
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		TLSClientConfig:       &tls.Config{}, // проверяем настоящую цепочку сайта
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 12 * time.Second,
	}
	client := &http.Client{
		Timeout:   18 * time.Second,
		Transport: transport,
	}

	req, _ := http.NewRequest("HEAD", rawURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		// HEAD может быть отвергнут — попробуем GET
		req2, _ := http.NewRequest("GET", rawURL, nil)
		req2.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err = client.Do(req2)
		if err != nil {
			return false, 0, time.Since(start), truncateStr(err.Error(), 60)
		}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))

	ok := resp.StatusCode < 500
	return ok, resp.StatusCode, time.Since(start), ""
}

// startMixedBackend — sing-box/xray с mixed inbound (HTTP+SOCKS) на конкретном порту.
func startMixedBackend(cfg *VPNConfig, port int) (ProxyBackend, error) {
	if strings.EqualFold(cfg.Transport, "xhttp") {
		return startMixedXray(cfg, port)
	}
	return startMixedSingBox(cfg, port)
}

func startMixedSingBox(cfg *VPNConfig, port int) (*SingBoxProxy, error) {
	binPath := locateSingBox()
	if binPath == "" {
		return nil, fmt.Errorf("sing-box.exe не найден")
	}

	outbound, err := buildOutbound(cfg)
	if err != nil {
		return nil, err
	}

	full := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "warn",
			"timestamp": true,
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": port,
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{"type": "direct", "tag": "direct"},
		},
		"route": map[string]interface{}{"final": "proxy"},
	}

	return launchProxyProcess(binPath, full, port, "sing-box")
}

func startMixedXray(cfg *VPNConfig, port int) (*XrayProxy, error) {
	binPath := locateXrayCore()
	if binPath == "" {
		return nil, fmt.Errorf("xray.exe не найден")
	}

	outbound, err := buildXrayOutbound(cfg)
	if err != nil {
		return nil, err
	}

	full := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "mixed-in",
				"port":     port,
				"listen":   "127.0.0.1",
				"protocol": "http", // xray HTTP-прокси для браузера
			},
			map[string]interface{}{
				"tag":      "socks-in",
				"port":     port + 1,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{"auth": "noauth", "udp": false},
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{"tag": "direct", "protocol": "freedom"},
		},
	}

	configJSON, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return nil, err
	}
	tmpfile, err := os.CreateTemp("", "diag-xray-manual-*.json")
	if err != nil {
		return nil, err
	}
	tmpfile.Write(configJSON)
	tmpfile.Close()

	var stderr bytes.Buffer
	cmd := exec.Command(binPath, "run", "-c", tmpfile.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		os.Remove(tmpfile.Name())
		return nil, err
	}

	p := &XrayProxy{
		cmd:        cmd,
		socksAddr:  fmt.Sprintf("127.0.0.1:%d", port+1), // SOCKS вход (port+1), HTTP — port
		configPath: tmpfile.Name(),
		stderr:     &stderr,
		binPath:    binPath,
	}
	if err := p.waitReady(12 * time.Second); err != nil {
		short := strings.TrimSpace(stderr.String())
		if len(short) > 400 {
			short = short[:400] + "..."
		}
		p.Stop()
		return nil, fmt.Errorf("xray не поднялся: %v | stderr: %s", err, short)
	}
	return p, nil
}

// launchProxyProcess — общий помощник для запуска sing-box с готовой config-map.
func launchProxyProcess(binPath string, config map[string]interface{}, port int, kind string) (*SingBoxProxy, error) {
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	tmpfile, err := os.CreateTemp("", "diag-"+kind+"-manual-*.json")
	if err != nil {
		return nil, err
	}
	tmpfile.Write(configJSON)
	tmpfile.Close()

	var stderr bytes.Buffer
	cmd := exec.Command(binPath, "run", "-c", tmpfile.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		os.Remove(tmpfile.Name())
		return nil, err
	}

	p := &SingBoxProxy{
		cmd:        cmd,
		socksAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		configPath: tmpfile.Name(),
		stderr:     &stderr,
		binPath:    binPath,
	}
	if err := p.waitReady(12 * time.Second); err != nil {
		short := strings.TrimSpace(stderr.String())
		if len(short) > 400 {
			short = short[:400] + "..."
		}
		p.Stop()
		return nil, fmt.Errorf("%s не поднялся: %v | stderr: %s", kind, err, short)
	}
	return p, nil
}

// quickProxyIPCheck — через SOCKS5 делаем GET ipinfo.io/ip для подтверждения exit IP.
func quickProxyIPCheck(socksAddr string) string {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 8 * time.Second})
	if err != nil {
		return ""
	}
	transport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{Timeout: 12 * time.Second, Transport: transport}
	resp, err := client.Get("https://ipinfo.io/ip")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return strings.TrimSpace(string(body))
}

// === System proxy management ===
//
// SystemProxyState и функции setSystemProxy/restoreSystemProxy реализованы
// per-OS: sysproxy_windows.go использует реестр + WinInet refresh,
// sysproxy_darwin.go — networksetup для каждого активного сервиса.

// setWindowsProxy / restoreWindowsProxy — старые имена, оставлены для
// обратной совместимости с уже написанными вызовами в interactive.go.
// Внутри делегируют в platform-aware setSystemProxy / restoreSystemProxy.
func setWindowsProxy(proxyServer string) (SystemProxyState, error) {
	return setSystemProxy(proxyServer)
}

func restoreWindowsProxy(prev SystemProxyState) {
	restoreSystemProxy(prev)
}

// WindowsProxyState — алиас для обратной совместимости с местами где
// тип явно использовался. На macOS поля просто остаются пустыми.
type WindowsProxyState = SystemProxyState

// isRussianDomain — детект российских TLD (включая punycode-формы).
func isRussianDomain(host string) bool {
	host = strings.ToLower(host)
	ruTLDs := []string{".ru", ".рф", ".su", ".moscow", ".москва", ".tatar", ".ru.com"}
	for _, tld := range ruTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	// IDN — рф закодирована в Punycode
	punyRU := []string{".xn--p1ai", ".xn--80adxhks", ".xn--80aswg"}
	for _, p := range punyRU {
		if strings.HasSuffix(host, p) {
			return true
		}
	}
	return false
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
