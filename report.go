package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

type TestStatus int

const (
	StatusOK TestStatus = iota
	StatusWarning
	StatusError
	StatusInfo
)

type TestResult struct {
	Name    string
	Status  TestStatus
	Message string
	Details string
	Latency time.Duration
}

func enableWindowsColors() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	handle, _ := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	var mode uint32
	getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	setConsoleMode.Call(uintptr(handle), uintptr(mode|0x0004))
}

func statusIcon(s TestStatus) string {
	switch s {
	case StatusOK:
		return colorGreen + "[OK]" + colorReset
	case StatusWarning:
		return colorYellow + "[!!]" + colorReset
	case StatusError:
		return colorRed + "[XX]" + colorReset
	case StatusInfo:
		return colorCyan + "[ii]" + colorReset
	default:
		return "    "
	}
}

func printBanner() {
	fmt.Println(colorCyan + "+==================================================================+")
	fmt.Println("|       DiagnostikVPN v" + version + " -- полная диагностика VPN              |")
	fmt.Println("|  VLESS/Reality/Vision, Trojan-gRPC/WS, Shadowsocks-2022, VMess  |")
	fmt.Println("|  + sing-box (точный туннель), zapret (DPI bypass), WARP detect  |")
	fmt.Println("+==================================================================+" + colorReset)
	fmt.Println()
}

func printSection(num int, name string) {
	fmt.Println()
	line := fmt.Sprintf("=== %d. %s ===", num, name)
	fmt.Println(colorBold + colorBlue + line + colorReset)
	fmt.Println()
}

func printConfig(cfg *VPNConfig) {
	fmt.Println(colorBold + "  КОНФИГУРАЦИЯ" + colorReset)
	fmt.Printf("  Протокол:     %s%s%s\n", colorCyan, strings.ToUpper(cfg.Protocol), colorReset)
	fmt.Printf("  Сервер:       %s%s:%d%s\n", colorCyan, cfg.Address, cfg.Port, colorReset)
	if cfg.Remark != "" {
		fmt.Printf("  Название:     %s\n", cfg.Remark)
	}
	if cfg.Security != "none" && cfg.Security != "" {
		fmt.Printf("  Безопасность: %s\n", cfg.Security)
	}
	fmt.Printf("  Transport:    %s\n", cfg.Transport)
	if cfg.SNI != "" {
		fmt.Printf("  SNI:          %s\n", cfg.SNI)
	}
	if cfg.Fingerprint != "" {
		fmt.Printf("  Fingerprint:  %s\n", cfg.Fingerprint)
	}
	if cfg.Flow != "" {
		fmt.Printf("  Flow:         %s\n", cfg.Flow)
	}
	if cfg.PublicKey != "" {
		end := len(cfg.PublicKey)
		if end > 4 {
			end = 4
		}
		start := 8
		if start > len(cfg.PublicKey) {
			start = len(cfg.PublicKey)
		}
		fmt.Printf("  Reality PBK:  %s...%s\n", cfg.PublicKey[:start], cfg.PublicKey[len(cfg.PublicKey)-end:])
	}
	if cfg.Method != "" {
		fmt.Printf("  Шифрование:  %s\n", cfg.Method)
	}
	fmt.Println()
}


func printResult(r TestResult) {
	icon := statusIcon(r.Status)
	fmt.Printf("  %s %s: %s\n", icon, r.Name, r.Message)
}

func printSummary(results []TestResult) {
	fmt.Println()
	fmt.Println(colorBold + "======================= ИТОГО =======================" + colorReset)
	fmt.Println()

	ok, warn, fail := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarning:
			warn++
		case StatusError:
			fail++
		}
	}

	total := ok + warn + fail
	fmt.Printf("  Всего тестов:     %d\n", total)
	fmt.Printf("  %sУспешно:          %d%s\n", colorGreen, ok, colorReset)
	if warn > 0 {
		fmt.Printf("  %sПредупреждения:   %d%s\n", colorYellow, warn, colorReset)
	}
	if fail > 0 {
		fmt.Printf("  %sОшибки:           %d%s\n", colorRed, fail, colorReset)
	}
	fmt.Println()

	if fail == 0 && warn == 0 {
		fmt.Printf("  Общая оценка: %s%sОТЛИЧНО [OK]%s\n", colorBold, colorGreen, colorReset)
	} else if fail == 0 {
		fmt.Printf("  Общая оценка: %s%sХОРОШО [!!]%s\n", colorBold, colorYellow, colorReset)
	} else if fail <= 2 {
		fmt.Printf("  Общая оценка: %s%sЕСТЬ ПРОБЛЕМЫ [XX]%s\n", colorBold, colorRed, colorReset)
	} else {
		fmt.Printf("  Общая оценка: %s%sКРИТИЧЕСКИЕ ПРОБЛЕМЫ [XX]%s\n", colorBold, colorRed, colorReset)
	}
	fmt.Println()
}

func writeConfigToBuilder(b *strings.Builder, cfg *VPNConfig) {
	fmt.Fprintf(b, "  Протокол:     %s\n", strings.ToUpper(cfg.Protocol))
	fmt.Fprintf(b, "  Сервер:       %s:%d\n", cfg.Address, cfg.Port)
	if cfg.Remark != "" {
		fmt.Fprintf(b, "  Название:     %s\n", cfg.Remark)
	}
	if cfg.Security != "none" && cfg.Security != "" {
		fmt.Fprintf(b, "  Безопасность: %s\n", cfg.Security)
	}
	fmt.Fprintf(b, "  Transport:    %s\n", cfg.Transport)
	if cfg.SNI != "" {
		fmt.Fprintf(b, "  SNI:          %s\n", cfg.SNI)
	}
	if cfg.Fingerprint != "" {
		fmt.Fprintf(b, "  Fingerprint:  %s\n", cfg.Fingerprint)
	}
	if cfg.Flow != "" {
		fmt.Fprintf(b, "  Flow:         %s\n", cfg.Flow)
	}
	if cfg.Method != "" {
		fmt.Fprintf(b, "  Шифрование:   %s\n", cfg.Method)
	}
}

func writeResultsToBuilder(b *strings.Builder, results []TestResult) {
	for _, r := range results {
		status := "OK"
		switch r.Status {
		case StatusWarning:
			status = "WARN"
		case StatusError:
			status = "FAIL"
		case StatusInfo:
			status = "INFO"
		}
		lat := ""
		if r.Latency > 0 {
			lat = fmt.Sprintf(" (%s)", r.Latency.Round(time.Millisecond))
		}
		fmt.Fprintf(b, "  [%s] %s: %s%s\n", status, r.Name, r.Message, lat)
		if r.Details != "" {
			for _, line := range strings.Split(r.Details, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(b, "         %s\n", line)
				}
			}
		}
	}
}

// analyzeProblems анализирует результаты и генерирует список возможных проблем и рекомендаций
func analyzeProblems(results []TestResult) string {
	var problems []string

	flags := map[string]bool{}

	for _, r := range results {
		switch {
		case r.Name == "DNS разрешение" && r.Status == StatusError:
			flags["dnsFail"] = true
		case r.Name == "TCP подключение" && r.Status == StatusError:
			flags["tcpFail"] = true
		case r.Name == "TLS Handshake" && r.Status == StatusError:
			flags["tlsFail"] = true
		case strings.Contains(r.Name, "подключение") && r.Status == StatusError &&
			!strings.Contains(r.Name, "TCP"):
			flags["vpnFail"] = true
		case r.Name == "Стабильность соединения" && r.Status == StatusWarning:
			flags["stabilityWarn"] = true
		case r.Name == "Сторонние VPN" && r.Status == StatusWarning:
			flags["otherVPN"] = true
		case r.Name == "VPN-клиент" && r.Status == StatusWarning:
			flags["noClient"] = true
		case r.Name == "SNI проверка" && (r.Status == StatusWarning || r.Status == StatusError):
			flags["sniBlock"] = true
		case r.Name == "Системный прокси" && r.Status == StatusWarning:
			flags["proxy"] = true
		case r.Name == "MTU" && r.Status == StatusWarning:
			flags["lowMTU"] = true
		case r.Name == "Антивирусы (установленные)" && r.Status == StatusWarning:
			flags["avInstalled"] = true
		case r.Name == "Антивирусы (процессы)" && r.Status == StatusWarning:
			flags["avRunning"] = true
		case r.Name == "Outbound-блокировки Firewall" && r.Status == StatusWarning:
			flags["fwBlock"] = true
		case r.Name == "Hosts-файл" && r.Status == StatusError:
			flags["hostsHijack"] = true
		case r.Name == "IPv6" && r.Status == StatusWarning:
			flags["ipv6Leak"] = true
		case r.Name == "DNS leak (потенциал)" && r.Status == StatusWarning:
			flags["dnsLeak"] = true
		case r.Name == "DPI обход (Go-native)" && r.Status == StatusWarning:
			flags["dpiBlock"] = true
		case strings.HasPrefix(r.Name, "Zapret [") && r.Status == StatusOK:
			flags["zapretHelped"] = true
		case strings.HasPrefix(r.Name, "Подписка") && r.Status == StatusError:
			flags["subFail"] = true
		}
	}

	if flags["hostsHijack"] {
		problems = append(problems, "* В hosts-файле есть запись для домена VPN-сервера (hijack!). Откройте C:\\Windows\\System32\\drivers\\etc\\hosts и удалите подозрительные строки.")
	}
	if flags["noClient"] {
		problems = append(problems, "* VPN-клиент не обнаружен. Установите Hiddify (https://hiddify.com) или v2rayN для подключения.")
	}
	if flags["otherVPN"] {
		problems = append(problems, "* Обнаружены сторонние VPN-программы. Отключите их перед подключением — они могут мешать.")
	}
	if flags["avInstalled"] || flags["avRunning"] {
		problems = append(problems, "* Активен антивирус с возможной HTTPS-инспекцией (Kaspersky, ESET, Avast и т.п.). Отключите модуль 'Защищённое соединение' / 'HTTPS-сканирование' / 'Web Shield' и попробуйте снова.")
	}
	if flags["fwBlock"] {
		problems = append(problems, "* В Windows Firewall есть outbound-правила, явно блокирующие VPN-приложения. Откройте wf.msc → Outbound Rules → найдите и отключите правила с упоминанием VPN/proxy.")
	}
	if flags["proxy"] {
		problems = append(problems, "* Обнаружен системный прокси. Отключите его в настройках Windows (Настройки > Сеть > Прокси).")
	}
	if flags["dnsFail"] {
		problems = append(problems, "* DNS не может разрешить адрес сервера. Смените DNS на 8.8.8.8 (Google) или 1.1.1.1 (Cloudflare) в настройках сети.")
	}
	if flags["tcpFail"] {
		problems = append(problems, "* Порт VPN-сервера недоступен. Возможна блокировка провайдером, брандмауэром или сервер временно недоступен.")
	}
	if flags["sniBlock"] {
		problems = append(problems, "* SNI заблокирован провайдером. Попросите поддержку сменить SNI на рабочий (см. отчёт выше).")
	}
	if flags["dpiBlock"] {
		problems = append(problems, "* Подтверждена DPI-блокировка по SNI: фрагментированный TLS-handshake проходит, обычный — нет. Установите zapret/winws или используйте Hiddify с TLS-fragmentation.")
	}
	if flags["zapretHelped"] {
		problems = append(problems, "* Запуск через zapret помог восстановить соединение — ОБЯЗАТЕЛЬНО используйте winws с указанной в отчёте стратегией.")
	}
	if flags["tlsFail"] && !flags["sniBlock"] && !flags["dpiBlock"] {
		problems = append(problems, "* TLS соединение не удалось. Возможна DPI-блокировка провайдером или MITM от антивируса.")
	}
	if flags["vpnFail"] {
		problems = append(problems, "* VPN-протокол не подключился. Проверьте правильность ключа или обратитесь в поддержку.")
	}
	if flags["stabilityWarn"] {
		problems = append(problems, "* Нестабильное соединение. Возможны потери пакетов или перегрузка сервера. Попробуйте другой сервер.")
	}
	if flags["lowMTU"] {
		problems = append(problems, "* Низкий MTU может вызывать проблемы с большими пакетами. Проверьте настройки роутера.")
	}
	if flags["ipv6Leak"] {
		problems = append(problems, "* IPv6 активен и доступен напрямую — возможен IPv6-leak в обход VPN. Отключите IPv6 в свойствах подключения или используйте VPN с поддержкой IPv6.")
	}
	if flags["dnsLeak"] {
		problems = append(problems, "* Система использует только провайдерский DNS — потенциальная утечка DNS. Установите 1.1.1.1 / 8.8.8.8 как основной DNS.")
	}
	if flags["subFail"] {
		problems = append(problems, "* Сервер подписки недоступен с этой машины. Проверьте URL, наличие интернета, или блокировку провайдером.")
	}

	if len(problems) == 0 {
		return "Проблем не обнаружено. Все тесты пройдены успешно."
	}

	return "Возможные проблемы и рекомендации:\n" + strings.Join(problems, "\n")
}

// maskPrivacyData маскирует приватные данные пользователя в отчёте
func maskPrivacyData(text string, serverAddresses []string) string {
	// Собираем IP серверов (их НЕ маскируем)
	allowedIPs := make(map[string]bool)
	for _, addr := range serverAddresses {
		allowedIPs[addr] = true
		ips, err := net.LookupHost(addr)
		if err == nil {
			for _, ip := range ips {
				allowedIPs[ip] = true
			}
		}
	}

	// Маскируем hostname
	hostname, _ := os.Hostname()
	if hostname != "" {
		text = strings.ReplaceAll(text, hostname, "[HIDDEN]")
	}

	// Маскируем IPv4 адреса (кроме серверных)
	ipv4Re := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	text = ipv4Re.ReplaceAllStringFunc(text, func(match string) string {
		if allowedIPs[match] {
			return match
		}
		parts := strings.SplitN(match, ".", 2)
		return parts[0] + ".*.*.*"
	})

	// Маскируем IPv6 — но только настоящие, не путая с временем/датой.
	// Триггер: либо "::", либо хотя бы один шестнадцатеричный символ a-f
	// в группах, либо хотя бы одна группа из 3+ цифр.
	ipv6Re := regexp.MustCompile(`(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d+)?(?:%[0-9a-zA-Z]+)?`)
	text = ipv6Re.ReplaceAllStringFunc(text, func(m string) string {
		// Отсеиваем не-IPv6: время "15:04:05", дата "2026-05-27" не сюда попадает
		// (последняя из них не имеет двоеточий).
		// Требуем либо a-f символ, либо "::", либо группу из 3+ символов.
		hasLetter := false
		hasCompress := strings.Contains(m, "::")
		groups := strings.Split(m, ":")
		hasLong := false
		for _, g := range groups {
			if len(g) >= 3 {
				hasLong = true
			}
			for _, c := range g {
				if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
					hasLetter = true
				}
			}
		}
		if !hasLetter && !hasCompress && !hasLong {
			return m // это, скорее всего, время — оставляем
		}
		// Дополнительная проверка: должно быть как минимум 3 группы (для нормального IPv6)
		// и не должно начинаться с '%' (interface id отдельно)
		if len(groups) < 3 {
			return m
		}
		return "[IPv6 скрыт]"
	})

	return text
}

// saveReportV31 — расширенная версия отчёта с per-key verdict и WARP-рекомендацией.
func saveReportV31(filename string, configs []*VPNConfig, results []TestResult, dump []DebugSection,
	verdicts []KeyVerdict, subURL, warpRecommendation string, privacy bool) error {
	var b strings.Builder

	fmt.Fprintf(&b, "DiagnostikVPN v%s -- Полный отчёт диагностики\n", version)
	fmt.Fprintf(&b, "Дата: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Проверено конфигов: %d\n", len(configs))
	if subURL != "" {
		fmt.Fprintf(&b, "Sub-URL: %s\n", subURL)
	}
	fmt.Fprintf(&b, "==================================================\n\n")

	// === [0] КОРОТКАЯ СВОДКА ПО КЛЮЧАМ — сразу в начало для быстрого скана поддержкой ===
	if len(verdicts) > 0 {
		fmt.Fprintf(&b, "==================================================\n")
		fmt.Fprintf(&b, "[0] СВОДНАЯ ТАБЛИЦА ПО КЛЮЧАМ\n")
		fmt.Fprintf(&b, "==================================================\n")
		fmt.Fprintf(&b, "%s\n", formatAllVerdictsTable(verdicts))

		fmt.Fprintf(&b, "\nДетали по каждому ключу:\n")
		for _, v := range verdicts {
			fmt.Fprintf(&b, "\n----- %s -----\n", v.ConfigName)
			fmt.Fprintf(&b, "Verdict: %s\n", v.Verdict)
			fmt.Fprintf(&b, "Рекомендация: %s\n", v.Recommendation)
			fmt.Fprintf(&b, "%s\n", formatVerdictDetails(v))
		}

		if warpRecommendation != "" {
			fmt.Fprintf(&b, "\nWARP-комбинация: %s\n", warpRecommendation)
		}
	}

	for i, cfg := range configs {
		fmt.Fprintf(&b, "\nКонфигурация %d/%d:\n", i+1, len(configs))
		writeConfigToBuilder(&b, cfg)
	}

	// === Сгруппированные результаты ===
	system, interference, nodes, zapret, perKey, other := groupResultsV31(results)

	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "[1] СИСТЕМА И СЕТЬ\n")
	fmt.Fprintf(&b, "==================================================\n")
	writeResultsToBuilder(&b, system)

	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "[2] ПОМЕХИ (AV / firewall / proxy / DNS)\n")
	fmt.Fprintf(&b, "==================================================\n")
	writeResultsToBuilder(&b, interference)

	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "[3] ПРОВЕРКА VPN-СЕРВЕРОВ И ПОДПИСКИ\n")
	fmt.Fprintf(&b, "==================================================\n")
	writeResultsToBuilder(&b, nodes)

	if len(perKey) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "[4] РЕАЛЬНЫЕ ТЕСТЫ ЧЕРЕЗ КЛЮЧИ (сайты, bandwidth, exit-IP)\n")
		fmt.Fprintf(&b, "==================================================\n")
		writeResultsToBuilder(&b, perKey)
	}

	if len(zapret) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "[5] ZAPRET / DPI-BYPASS RETEST\n")
		fmt.Fprintf(&b, "==================================================\n")
		writeResultsToBuilder(&b, zapret)
	}

	if len(other) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "[6] ПРОЧЕЕ\n")
		fmt.Fprintf(&b, "==================================================\n")
		writeResultsToBuilder(&b, other)
	}

	ok, warn, fail := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarning:
			warn++
		case StatusError:
			fail++
		}
	}
	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "ИТОГО ТЕСТОВ: %d   успешно: %d   предупр.: %d   ошибки: %d\n",
		ok+warn+fail, ok, warn, fail)

	fmt.Fprintf(&b, "==================================================\n")
	fmt.Fprintf(&b, "АНАЛИЗ И РЕКОМЕНДАЦИИ\n")
	fmt.Fprintf(&b, "==================================================\n")
	fmt.Fprintf(&b, "%s\n", analyzeProblems(results))

	if len(dump) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "DEBUG DUMP (сырые выводы системных команд)\n")
		fmt.Fprintf(&b, "==================================================\n")
		fmt.Fprintf(&b, "%s\n", debugDumpToString(dump))
	}

	reportText := b.String()

	if privacy {
		serverAddrs := make([]string, 0, len(configs))
		for _, cfg := range configs {
			serverAddrs = append(serverAddrs, cfg.Address)
		}
		reportText = maskPrivacyData(reportText, serverAddrs)
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	f.Write([]byte{0xEF, 0xBB, 0xBF})
	f.WriteString(reportText)

	return nil
}

// groupResultsV31 — расширенная группировка с per-key секцией.
func groupResultsV31(results []TestResult) (system, interference, nodes, zapret, perKey, other []TestResult) {
	sysNames := map[string]bool{
		"ОС и платформа":     true,
		"Сетевые интерфейсы": true,
		"DNS серверы":        true,
		"Шлюз по умолчанию":  true,
		"Системное время":    true,
	}
	interferenceNames := map[string]bool{
		"VPN-клиент":                     true,
		"Сторонние VPN":                  true,
		"Брандмауэр":                     true,
		"Outbound-блокировки Firewall":   true,
		"Ограничения запуска приложений": true,
		"Системный прокси":               true,
		"VPN-адаптеры":                   true,
		"Антивирусы (установленные)":     true,
		"Антивирусы (процессы)":          true,
		"Windows Defender":               true,
		"DNS leak (потенциал)":           true,
		"IPv6":                           true,
		"Hosts-файл":                     true,
		"Cloudflare WARP":                true,
	}

	for _, r := range results {
		switch {
		case strings.HasPrefix(r.Name, "Сайт ") ||
			strings.HasPrefix(r.Name, "Качество канала ") ||
			strings.HasPrefix(r.Name, "Egress IP ") ||
			strings.HasPrefix(r.Name, "Bandwidth ") ||
			strings.HasPrefix(r.Name, "ИТОГ [") ||
			strings.HasPrefix(r.Name, "Прокси-тест "):
			perKey = append(perKey, r)
		case strings.HasPrefix(r.Name, "Zapret"):
			zapret = append(zapret, r)
		case sysNames[r.Name]:
			system = append(system, r)
		case interferenceNames[r.Name]:
			interference = append(interference, r)
		case r.Name == "DNS разрешение" || r.Name == "Альтернативные DNS" ||
			r.Name == "Ping" || r.Name == "TCP подключение" || r.Name == "MTU" ||
			r.Name == "Маршрут (traceroute)" || r.Name == "TLS Handshake" ||
			r.Name == "TLS" || r.Name == "Reality параметры" ||
			r.Name == "SNI проверка" || r.Name == "DNS проверка" ||
			r.Name == "Стабильность соединения" || r.Name == "IP fallback" ||
			strings.HasPrefix(r.Name, "UDP ") ||
			strings.HasPrefix(r.Name, "VLESS") || strings.HasPrefix(r.Name, "VMess") ||
			strings.HasPrefix(r.Name, "Trojan") || strings.HasPrefix(r.Name, "Shadowsocks") ||
			strings.HasPrefix(r.Name, "Подписка") ||
			strings.HasPrefix(r.Name, "DPI обход"):
			nodes = append(nodes, r)
		default:
			other = append(other, r)
		}
	}
	return
}

// === Старая функция оставлена для обратной совместимости ===
func saveReportMulti(filename string, configs []*VPNConfig, results []TestResult, dump []DebugSection, subURL string, privacy bool) error {
	var b strings.Builder

	fmt.Fprintf(&b, "DiagnostikVPN v%s -- Полный отчёт диагностики\n", version)
	fmt.Fprintf(&b, "Дата: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Проверено конфигов: %d\n", len(configs))
	if subURL != "" {
		fmt.Fprintf(&b, "Sub-URL: %s\n", subURL)
	}
	fmt.Fprintf(&b, "==================================================\n\n")

	for i, cfg := range configs {
		fmt.Fprintf(&b, "Конфигурация %d/%d:\n", i+1, len(configs))
		writeConfigToBuilder(&b, cfg)
		fmt.Fprintf(&b, "\n")
	}

	// === Сгруппированные результаты по разделам ===
	system, interference, nodes, zapret, other := groupResults(results)

	fmt.Fprintf(&b, "==================================================\n")
	fmt.Fprintf(&b, "[1] СИСТЕМА И СЕТЬ\n")
	fmt.Fprintf(&b, "==================================================\n")
	writeResultsToBuilder(&b, system)

	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "[2] ПОМЕХИ (AV / firewall / proxy / DNS)\n")
	fmt.Fprintf(&b, "==================================================\n")
	writeResultsToBuilder(&b, interference)

	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "[3] ПРОВЕРКА VPN-СЕРВЕРОВ И ПОДПИСКИ\n")
	fmt.Fprintf(&b, "==================================================\n")
	writeResultsToBuilder(&b, nodes)

	if len(zapret) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "[4] ZAPRET / DPI-BYPASS RETEST\n")
		fmt.Fprintf(&b, "==================================================\n")
		writeResultsToBuilder(&b, zapret)
	}

	if len(other) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "[5] ПРОЧЕЕ\n")
		fmt.Fprintf(&b, "==================================================\n")
		writeResultsToBuilder(&b, other)
	}

	ok, warn, fail := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarning:
			warn++
		case StatusError:
			fail++
		}
	}
	fmt.Fprintf(&b, "\n==================================================\n")
	fmt.Fprintf(&b, "ИТОГО ТЕСТОВ: %d   успешно: %d   предупр.: %d   ошибки: %d\n",
		ok+warn+fail, ok, warn, fail)

	// Анализ проблем и рекомендации
	fmt.Fprintf(&b, "==================================================\n")
	fmt.Fprintf(&b, "АНАЛИЗ И РЕКОМЕНДАЦИИ\n")
	fmt.Fprintf(&b, "==================================================\n")
	fmt.Fprintf(&b, "%s\n", analyzeProblems(results))

	// === Debug dump (сырые выводы) ===
	if len(dump) > 0 {
		fmt.Fprintf(&b, "\n==================================================\n")
		fmt.Fprintf(&b, "DEBUG DUMP (сырые выводы системных команд)\n")
		fmt.Fprintf(&b, "==================================================\n")
		fmt.Fprintf(&b, "%s\n", debugDumpToString(dump))
	}

	reportText := b.String()

	// Применяем маскировку приватных данных
	if privacy {
		serverAddrs := make([]string, 0, len(configs))
		for _, cfg := range configs {
			serverAddrs = append(serverAddrs, cfg.Address)
		}
		reportText = maskPrivacyData(reportText, serverAddrs)
	}

	// Записываем в файл
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// UTF-8 BOM
	f.Write([]byte{0xEF, 0xBB, 0xBF})
	f.WriteString(reportText)

	return nil
}

// groupResults распределяет TestResult'ы по логическим секциям отчёта.
func groupResults(results []TestResult) (system, interference, nodes, zapret, other []TestResult) {
	sysNames := map[string]bool{
		"ОС и платформа":     true,
		"Сетевые интерфейсы": true,
		"DNS серверы":        true,
		"Шлюз по умолчанию":  true,
		"Системное время":    true,
	}
	interferenceNames := map[string]bool{
		"VPN-клиент":                    true,
		"Сторонние VPN":                 true,
		"Брандмауэр":                    true,
		"Outbound-блокировки Firewall":  true,
		"Ограничения запуска приложений": true,
		"Системный прокси":              true,
		"VPN-адаптеры":                  true,
		"Антивирусы (установленные)":    true,
		"Антивирусы (процессы)":         true,
		"Windows Defender":              true,
		"DNS leak (потенциал)":          true,
		"IPv6":                          true,
		"Hosts-файл":                    true,
	}

	for _, r := range results {
		switch {
		case strings.HasPrefix(r.Name, "Zapret"):
			zapret = append(zapret, r)
		case sysNames[r.Name]:
			system = append(system, r)
		case interferenceNames[r.Name]:
			interference = append(interference, r)
		case r.Name == "DNS разрешение" || r.Name == "Альтернативные DNS" ||
			r.Name == "Ping" || r.Name == "TCP подключение" || r.Name == "MTU" ||
			r.Name == "Маршрут (traceroute)" || r.Name == "TLS Handshake" ||
			r.Name == "TLS" || r.Name == "Reality параметры" ||
			r.Name == "SNI проверка" || r.Name == "DNS проверка" ||
			r.Name == "Стабильность соединения" || r.Name == "IP fallback" ||
			strings.HasPrefix(r.Name, "UDP ") ||
			strings.HasPrefix(r.Name, "VLESS") || strings.HasPrefix(r.Name, "VMess") ||
			strings.HasPrefix(r.Name, "Trojan") || strings.HasPrefix(r.Name, "Shadowsocks") ||
			strings.HasPrefix(r.Name, "Подписка") ||
			strings.HasPrefix(r.Name, "DPI обход"):
			nodes = append(nodes, r)
		default:
			other = append(other, r)
		}
	}
	return
}
