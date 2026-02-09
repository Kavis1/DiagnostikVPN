package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "2.3.0"

var privacyMode bool

func main() {
	enableWindowsColors()
	printBanner()

	reader := bufio.NewReader(os.Stdin)

	// Запрос ссылки
	fmt.Println("Вставьте ссылку подписки или VPN-ключ:")
	fmt.Print("> ")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%sОшибка чтения ввода: %v%s\n", colorRed, err, colorReset)
		waitExit()
		return
	}
	uri := strings.TrimSpace(input)

	if uri == "" {
		fmt.Printf("%sОшибка: вы не вставили ссылку%s\n", colorRed, colorReset)
		waitExit()
		return
	}

	// Запрос режима конфиденциальности
	fmt.Println("Скрыть ваши IP-адреса в отчёте? (y/n):")
	fmt.Print("> ")
	privInput, _ := reader.ReadString('\n')
	privAnswer := strings.TrimSpace(strings.ToLower(privInput))
	if privAnswer == "y" || privAnswer == "yes" || privAnswer == "д" || privAnswer == "да" {
		privacyMode = true
	}
	fmt.Println()

	// Определяем тип ввода
	var configs []*VPNConfig

	if IsSubscriptionURL(uri) {
		fmt.Printf("  Загрузка подписки...")
		var err error
		configs, err = FetchSubscription(uri)
		if err != nil {
			fmt.Printf(" %sошибка: %v%s\n", colorRed, err, colorReset)
			waitExit()
			return
		}
		fmt.Printf(" %sнайдено %d конфигов%s\n", colorGreen, len(configs), colorReset)
	} else {
		cfg, err := ParseVPNLink(uri)
		if err != nil {
			fmt.Printf("%sОшибка парсинга: %v%s\n", colorRed, err, colorReset)
			waitExit()
			return
		}
		configs = []*VPNConfig{cfg}
		fmt.Printf("  Конфиг: %s%s%s\n", colorCyan, strings.ToUpper(cfg.Protocol), colorReset)
	}

	var allResults []TestResult
	startTime := time.Now()

	// 1. Система + помехи
	fmt.Printf("  Проверка системы...")
	sysResults := runSystemInfoTests()
	allResults = append(allResults, sysResults...)
	intResults := runInterferenceTests()
	allResults = append(allResults, intResults...)
	testedDNS := make(map[string]bool)
	for _, cfg := range configs {
		if !testedDNS[cfg.Address] {
			testedDNS[cfg.Address] = true
		}
	}
	for _, cfg := range configs {
		if testedDNS[cfg.Address] {
			dnsHijack := checkDNSHijacking(cfg.Address)
			allResults = append(allResults, dnsHijack)
			testedDNS[cfg.Address] = false
		}
	}
	fmt.Printf(" %sготово%s\n", colorGreen, colorReset)

	// 2. Проходим по конфигам
	testedServers := make(map[string]bool)

	for i, cfg := range configs {
		name := cfg.Remark
		if name == "" {
			name = fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
		}
		fmt.Printf("  Проверка %d/%d: %s...", i+1, len(configs), name)

		serverKey := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

		// Сетевые тесты
		if !testedServers[serverKey] {
			testedServers[serverKey] = true
			netResults := runNetworkTests(cfg)
			allResults = append(allResults, netResults...)
		}

		// TLS
		tlsResults := runTLSTests(cfg)
		allResults = append(allResults, tlsResults...)

		// SNI проверка — только если TLS не прошёл
		tlsFailed := false
		for _, r := range tlsResults {
			if r.Name == "TLS Handshake" && r.Status == StatusError {
				tlsFailed = true
			}
		}
		if tlsFailed && cfg.Security != "none" && cfg.Security != "" {
			sniResults := testSNIBlocking(cfg)
			allResults = append(allResults, sniResults...)
		}

		// VPN
		vpnResults := runVPNTests(cfg)
		allResults = append(allResults, vpnResults...)

		// Показываем краткий статус конфига
		cfgFail := false
		for _, r := range vpnResults {
			if r.Status == StatusError {
				cfgFail = true
			}
		}
		if cfgFail {
			fmt.Printf(" %sпроблемы%s\n", colorRed, colorReset)
		} else {
			fmt.Printf(" %sOK%s\n", colorGreen, colorReset)
		}
	}

	// Итого
	ok, warn, fail := 0, 0, 0
	for _, r := range allResults {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarning:
			warn++
		case StatusError:
			fail++
		}
	}

	fmt.Println()
	totalTime := time.Since(startTime)
	if fail == 0 && warn == 0 {
		fmt.Printf("  Результат: %s%sОТЛИЧНО%s (%d тестов, %s)\n", colorBold, colorGreen, colorReset, ok+warn+fail, totalTime.Round(time.Millisecond))
	} else if fail == 0 {
		fmt.Printf("  Результат: %s%sХОРОШО%s (%d тестов, %d предупреждений, %s)\n", colorBold, colorYellow, colorReset, ok+warn+fail, warn, totalTime.Round(time.Millisecond))
	} else {
		fmt.Printf("  Результат: %s%sЕСТЬ ПРОБЛЕМЫ%s (%d тестов, %d ошибок, %s)\n", colorBold, colorRed, colorReset, ok+warn+fail, fail, totalTime.Round(time.Millisecond))
	}

	// Сохранить отчёт
	reportFile := "diagnostik_report.txt"
	if len(configs) > 0 {
		if err := saveReportMulti(reportFile, configs, allResults, privacyMode); err == nil {
			fmt.Printf("  Отчёт сохранён: %s%s%s\n", colorGreen, reportFile, colorReset)
		}
	}

	fmt.Println()
	fmt.Printf("  %s>> Отправьте файл \"%s\" в поддержку сервиса,%s\n", colorCyan, reportFile, colorReset)
	fmt.Printf("  %s   который выдал вам ключ.%s\n", colorCyan, colorReset)
	fmt.Println()

	waitExit()
}

func waitExit() {
	fmt.Println("Нажмите Enter для выхода...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

