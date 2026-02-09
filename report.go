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
	fmt.Println("|        DiagnostikVPN -- Диагностика VPN соединений              |")
	fmt.Println("|        Поддержка: VLESS, Trojan, Shadowsocks (Xray)            |")
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

	hasDNSFail := false
	hasTCPFail := false
	hasTLSFail := false
	hasVPNFail := false
	hasStabilityWarn := false
	hasOtherVPN := false
	hasNoClient := false
	hasSNIBlock := false
	hasProxy := false
	hasLowMTU := false

	for _, r := range results {
		switch {
		case r.Name == "DNS разрешение" && r.Status == StatusError:
			hasDNSFail = true
		case r.Name == "TCP подключение" && r.Status == StatusError:
			hasTCPFail = true
		case r.Name == "TLS Handshake" && r.Status == StatusError:
			hasTLSFail = true
		case strings.Contains(r.Name, "подключение") && r.Status == StatusError &&
			!strings.Contains(r.Name, "TCP"):
			hasVPNFail = true
		case r.Name == "Стабильность соединения" && r.Status == StatusWarning:
			hasStabilityWarn = true
		case r.Name == "Сторонние VPN" && r.Status == StatusWarning:
			hasOtherVPN = true
		case r.Name == "VPN-клиент" && r.Status == StatusWarning:
			hasNoClient = true
		case r.Name == "SNI проверка" && (r.Status == StatusWarning || r.Status == StatusError):
			hasSNIBlock = true
		case r.Name == "Системный прокси" && r.Status == StatusWarning:
			hasProxy = true
		case r.Name == "MTU" && r.Status == StatusWarning:
			hasLowMTU = true
		}
	}

	if hasNoClient {
		problems = append(problems, "* VPN-клиент не обнаружен. Установите Hiddify (https://hiddify.com) или v2rayN для подключения.")
	}
	if hasOtherVPN {
		problems = append(problems, "* Обнаружены сторонние VPN-программы. Отключите их перед подключением — они могут мешать.")
	}
	if hasProxy {
		problems = append(problems, "* Обнаружен системный прокси. Отключите его в настройках Windows (Настройки > Сеть > Прокси).")
	}
	if hasDNSFail {
		problems = append(problems, "* DNS не может разрешить адрес сервера. Смените DNS на 8.8.8.8 (Google) или 1.1.1.1 (Cloudflare) в настройках сети.")
	}
	if hasTCPFail {
		problems = append(problems, "* Порт VPN-сервера недоступен. Возможна блокировка провайдером, брандмауэром или сервер временно недоступен.")
	}
	if hasSNIBlock {
		problems = append(problems, "* SNI заблокирован провайдером. Попросите поддержку сменить SNI на рабочий (см. отчёт выше).")
	}
	if hasTLSFail && !hasSNIBlock {
		problems = append(problems, "* TLS соединение не удалось. Возможна DPI-блокировка провайдером.")
	}
	if hasVPNFail {
		problems = append(problems, "* VPN-протокол не подключился. Проверьте правильность ключа или обратитесь в поддержку.")
	}
	if hasStabilityWarn {
		problems = append(problems, "* Нестабильное соединение. Возможны потери пакетов или перегрузка сервера. Попробуйте другой сервер.")
	}
	if hasLowMTU {
		problems = append(problems, "* Низкий MTU может вызывать проблемы с большими пакетами. Проверьте настройки роутера.")
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

	// Маскируем IPv6 адреса
	ipv6Re := regexp.MustCompile(`[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,7}(/\d+)?`)
	text = ipv6Re.ReplaceAllString(text, "[IPv6 скрыт]")

	return text
}

func saveReportMulti(filename string, configs []*VPNConfig, results []TestResult, privacy bool) error {
	var b strings.Builder

	fmt.Fprintf(&b, "DiagnostikVPN v%s -- Отчёт диагностики\n", version)
	fmt.Fprintf(&b, "Дата: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Проверено конфигов: %d\n", len(configs))
	fmt.Fprintf(&b, "===================================\n\n")

	for i, cfg := range configs {
		fmt.Fprintf(&b, "Конфигурация %d/%d:\n", i+1, len(configs))
		writeConfigToBuilder(&b, cfg)
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "Результаты:\n")
	writeResultsToBuilder(&b, results)

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
	fmt.Fprintf(&b, "\nИтого: %d тестов, %d успешно, %d предупреждений, %d ошибок\n",
		ok+warn+fail, ok, warn, fail)

	// Анализ проблем и рекомендации
	fmt.Fprintf(&b, "\n===================================\n")
	fmt.Fprintf(&b, "%s\n", analyzeProblems(results))

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
