package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "3.3.0"

var (
	privacyMode      bool
	autoDownload     bool
	withZapret       bool
	debugDumpEnabled bool
	cliInput         string
	skipSiteTests    bool
	downloadSingbox  bool
	downloadXrayBin  bool
	skipInteractive  bool
	onlyInteractive  bool
	onlyTun          bool
	supportBot       string
)

func main() {
	flag.BoolVar(&autoDownload, "download-zapret", false, "автоматически скачать zapret-win-bundle при отсутствии")
	flag.BoolVar(&withZapret, "with-zapret", true, "включить retest через zapret/winws если есть проблемы")
	flag.BoolVar(&debugDumpEnabled, "debug-dump", true, "добавлять в отчёт сырые дампы ipconfig/route/netstat и т.д.")
	flag.StringVar(&cliInput, "uri", "", "VPN-ссылка или URL подписки (если не указан — спрашиваем в консоли)")
	flag.BoolVar(&privacyMode, "privacy", false, "маскировать локальные IP-адреса в отчёте")
	flag.BoolVar(&skipSiteTests, "no-sites", false, "не проверять открываемость популярных сайтов через ключи")
	flag.BoolVar(&downloadSingbox, "download-singbox", true, "авто-скачать sing-box.exe если нет (нужен для VLESS+Reality+Vision/gRPC/WS/SS)")
	flag.BoolVar(&downloadXrayBin, "download-xray", true, "авто-скачать xray.exe если нет (нужен для xhttp transport — sing-box его не знает)")
	flag.BoolVar(&skipInteractive, "no-interactive", false, "не запускать после тестов интерактивный режим ручной проверки")
	flag.BoolVar(&onlyInteractive, "only-interactive", false, "пропустить автотесты, сразу меню выбора ноды + туннель + URL-тестер")
	flag.BoolVar(&onlyTun, "only-tun", false, "запустить только мастер «приложения не ходят через VPN» (без подписки и автотестов)")
	flag.StringVar(&supportBot, "support-bot", "@XNeoVPNbot", "Telegram-бот поддержки для инструкции о превышении лимита устройств")
	flag.Parse()

	// only-tun — ранний exit, не требует подписки (но если URI задан — поднимем
	// свой TUN на лучшем ключе из неё; иначе только диагностика без замены).
	if onlyTun {
		enableWindowsColors()
		printBanner()
		var bestCfg *VPNConfig
		if strings.TrimSpace(cliInput) != "" && IsSubscriptionURL(cliInput) {
			if cfgs, err := FetchSubscription(cliInput); err == nil && len(cfgs) > 0 {
				// без verdicts — используем первый sing-box-совместимый
				for _, c := range cfgs {
					if !strings.EqualFold(c.Transport, "xhttp") {
						bestCfg = c
						break
					}
				}
			}
		}
		report := runTunTroubleshooter(bestCfg)
		appendTunReport(report)
		waitExit()
		return
	}

	enableWindowsColors()
	printBanner()

	reader := bufio.NewReader(os.Stdin)
	uri := strings.TrimSpace(cliInput)

	if uri == "" {
		fmt.Println("Вставьте ссылку подписки или VPN-ключ:")
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("%sОшибка чтения ввода: %v%s\n", colorRed, err, colorReset)
			waitExit()
			return
		}
		uri = strings.TrimSpace(input)
	}

	if uri == "" {
		fmt.Printf("%sОшибка: вы не вставили ссылку%s\n", colorRed, colorReset)
		waitExit()
		return
	}

	if !privacyMode {
		fmt.Println("Скрыть ваши IP-адреса в отчёте? (y/n):")
		fmt.Print("> ")
		privInput, _ := reader.ReadString('\n')
		privAnswer := strings.TrimSpace(strings.ToLower(privInput))
		if privAnswer == "y" || privAnswer == "yes" || privAnswer == "д" || privAnswer == "да" {
			privacyMode = true
		}
	}
	fmt.Println()

	var configs []*VPNConfig
	var subURLForReport string
	var subURLProbes []TestResult

	if IsSubscriptionURL(uri) {
		subURLForReport = uri
		fmt.Printf("  Загрузка подписки (ротация UA + HWID)...")

		smart := SmartFetchSubscription(uri)

		// Сразу обрабатываем лимит устройств — это блокер
		if smart.LimitExceeded {
			fmt.Printf(" %sЛИМИТ УСТРОЙСТВ%s\n", colorRed, colorReset)
			printDeviceLimitInstructions()
			subURLProbes = append(subURLProbes, TestResult{
				Name:    "Подписка — лимит устройств",
				Status:  StatusError,
				Message: "сервер вернул признак превышения лимита устройств (UA=" + smart.UsedUA + ")",
				Details: "Response preview: " + smart.ResponsePreview,
			})
			waitExit()
			return
		}

		if smart.OK {
			configs = smart.Configs
			tag := smart.UsedUA
			if smart.UsedHWID {
				tag += " + HWID"
			}
			if smart.HappOnly {
				tag += " (Happ JSON формат)"
			}
			fmt.Printf(" %sнайдено %d конфигов [%s]%s\n", colorGreen, len(configs), tag, colorReset)
			subURLProbes = append(subURLProbes, TestResult{
				Name:    "Подписка — успех",
				Status:  StatusOK,
				Message: fmt.Sprintf("UA=%s, HWID=%v, Happ-формат=%v", smart.UsedUA, smart.UsedHWID, smart.HappOnly),
			})
			if smart.TLSInsecureUsed {
				subURLProbes = append(subURLProbes, TestResult{
					Name:    "Подписка — TLS warning",
					Status:  StatusWarning,
					Message: "сертификат не прошёл строгую валидацию (возможна MITM-инспекция от AV/провайдера, или просроченный сертификат на сервере). Ответ получен в insecure-режиме.",
				})
			}
		} else {
			fmt.Printf(" %sне удалось ни одним UA%s\n", colorRed, colorReset)
			if smart.Error != nil {
				fmt.Printf("    последняя ошибка: %v\n", smart.Error)
			}

			// IP-fallback: если домен подписки заблокирован, пробуем через IP с правильным SNI/Host
			fmt.Printf("  Подписка через IP (резолв через 1.1.1.1/8.8.8.8)...")
			fallbackResults, fallbackConfigs := fetchSubscriptionViaIP(uri)
			subURLProbes = append(subURLProbes, fallbackResults...)
			if len(fallbackConfigs) > 0 {
				configs = fallbackConfigs
				fmt.Printf(" %sПРОШЛО — %d конфигов (домен блокируется, IP открыт!)%s\n",
					colorYellow, len(configs), colorReset)
			} else {
				fmt.Printf(" %sтоже упало%s\n", colorRed, colorReset)
			}
		}

		fmt.Printf("  Зондирование sub-URL (5 User-Agent'ов)...")
		subURLProbes = append(subURLProbes, checkSubscriptionURL(uri)...)
		fmt.Printf(" %s%d проб%s\n", colorGreen, len(subURLProbes), colorReset)
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

	if len(configs) == 0 && len(subURLProbes) == 0 {
		fmt.Printf("%sНет ни одного конфига и ни одного успешного зонда sub-URL — нечего тестировать%s\n",
			colorRed, colorReset)
		waitExit()
		return
	}

	// === -only-interactive === : пропускаем все автотесты, сразу к ручному режиму
	if onlyInteractive {
		if len(configs) == 0 {
			fmt.Printf("%sНет ключей для интерактивного режима%s\n", colorRed, colorReset)
			waitExit()
			return
		}
		// Подгрузить backend'ы (тихо, без шума автотестов)
		if locateSingBox() == "" && downloadSingbox {
			fmt.Printf("  Скачивание sing-box.exe (~12MB)...")
			if _, err := downloadSingBox(); err != nil {
				fmt.Printf(" %sошибка: %v%s\n", colorYellow, err, colorReset)
			} else {
				fmt.Printf(" %sок%s\n", colorGreen, colorReset)
			}
		}
		needsXray := false
		for _, c := range configs {
			if strings.EqualFold(c.Transport, "xhttp") {
				needsXray = true
				break
			}
		}
		if needsXray && locateXrayCore() == "" && downloadXrayBin {
			fmt.Printf("  Скачивание xray-core (~30MB)...")
			if _, err := downloadXrayCore(); err != nil {
				fmt.Printf(" %sошибка: %v%s\n", colorYellow, err, colorReset)
			} else {
				fmt.Printf(" %sок%s\n", colorGreen, colorReset)
			}
		}

		runInteractiveOnly(configs)
		waitExit()
		return
	}

	var allResults []TestResult
	startTime := time.Now()

	// 1. Система + помехи
	fmt.Printf("  Проверка системы...")
	sysResults := runSystemInfoTests()
	allResults = append(allResults, sysResults...)
	intResults := runInterferenceTests()
	allResults = append(allResults, intResults...)

	// WARP отдельно — важно для рекомендаций
	allResults = append(allResults, runWARPCheck())

	// Hosts-файл
	serverAddrs := make([]string, 0, len(configs))
	for _, cfg := range configs {
		serverAddrs = append(serverAddrs, cfg.Address)
	}
	allResults = append(allResults, checkHostsFile(serverAddrs))

	// DNS-hijack
	testedDNS := make(map[string]bool)
	for _, cfg := range configs {
		if !testedDNS[cfg.Address] {
			testedDNS[cfg.Address] = true
			allResults = append(allResults, checkDNSHijacking(cfg.Address))
		}
	}
	fmt.Printf(" %sготово%s\n", colorGreen, colorReset)

	if len(subURLProbes) > 0 {
		allResults = append(allResults, subURLProbes...)
	}

	// Определяем локальный IP/страну ОДИН раз — для сравнения с exit-IP
	var localIP, localCountry string
	if !skipSiteTests && len(configs) > 0 {
		fmt.Printf("  Определение локального exit-IP...")
		localIP, localCountry, _ = detectLocalExitIP()
		if localIP != "" {
			fmt.Printf(" %s%s (%s)%s\n", colorGreen, localIP, localCountry, colorReset)
		} else {
			fmt.Printf(" %sне удалось определить%s\n", colorYellow, colorReset)
		}

		// sing-box — для VLESS/Trojan/SS/VMess со всеми обычными транспортами
		if locateSingBox() == "" && downloadSingbox {
			fmt.Printf("  Скачивание sing-box.exe (~12MB)...")
			if path, err := downloadSingBox(); err != nil {
				fmt.Printf(" %sошибка: %v%s\n", colorYellow, err, colorReset)
			} else {
				fmt.Printf(" %sок: %s%s\n", colorGreen, path, colorReset)
			}
		} else if p := locateSingBox(); p != "" {
			fmt.Printf("  sing-box.exe: %s%s%s\n", colorGreen, p, colorReset)
		}

		// xray-core — нужен только для xhttp transport (sing-box его не знает)
		needsXray := false
		for _, c := range configs {
			if strings.EqualFold(c.Transport, "xhttp") {
				needsXray = true
				break
			}
		}
		if needsXray {
			if locateXrayCore() == "" && downloadXrayBin {
				fmt.Printf("  Скачивание xray-core (~30MB, нужен для xhttp transport)...")
				if path, err := downloadXrayCore(); err != nil {
					fmt.Printf(" %sошибка: %v%s\n", colorYellow, err, colorReset)
				} else {
					fmt.Printf(" %sок: %s%s\n", colorGreen, path, colorReset)
				}
			} else if p := locateXrayCore(); p != "" {
				fmt.Printf("  xray.exe: %s%s%s\n", colorGreen, p, colorReset)
			}
		}
	}

	// 2. Проходим по конфигам — базовая сеть + TLS + DPI
	testedServers := make(map[string]bool)
	var failedConfigs []*VPNConfig
	var verdicts []KeyVerdict

	for i, cfg := range configs {
		name := cfg.Remark
		if name == "" {
			name = fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
		}
		fmt.Printf("  Проверка %d/%d: %s\n", i+1, len(configs), name)

		serverKey := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
		var perServer []TestResult

		if !testedServers[serverKey] {
			testedServers[serverKey] = true
			fmt.Printf("    └─ сетевые тесты...")
			netResults := runNetworkTests(cfg)
			perServer = append(perServer, netResults...)
			perServer = append(perServer, probeUDPPort(cfg.Address, cfg.Port))
			fmt.Printf(" %sok%s\n", colorGreen, colorReset)
		}

		fmt.Printf("    └─ TLS...")
		tlsResults := runTLSTests(cfg)
		perServer = append(perServer, tlsResults...)
		fmt.Printf(" %sok%s\n", colorGreen, colorReset)

		tlsFailed := false
		for _, r := range tlsResults {
			if r.Name == "TLS Handshake" && r.Status == StatusError {
				tlsFailed = true
			}
		}

		// Если сеть/TLS упали — пробуем IP-fallback: резолв через 1.1.1.1, dial к IP с правильным SNI.
		// Это отличает "DNS/SNI блокирует домен" от "IP блокирован".
		netFailed := false
		for _, r := range perServer {
			if (r.Name == "DNS разрешение" || r.Name == "TCP подключение") && r.Status == StatusError {
				netFailed = true
				break
			}
		}
		if netFailed || tlsFailed {
			perServer = append(perServer, testNodeIPFallback(cfg))
		}

		if tlsFailed && cfg.Security != "none" && cfg.Security != "" {
			sniResults := testSNIBlocking(cfg)
			perServer = append(perServer, sniResults...)
		}

		if cfg.Security == "tls" || cfg.Security == "reality" {
			fmt.Printf("    └─ DPI обход (fragmented ClientHello)...")
			dpiResults := runDPIBypassTests(cfg)
			perServer = append(perServer, dpiResults...)
			fmt.Printf(" %sok%s\n", colorGreen, colorReset)
		}

		fmt.Printf("    └─ VPN handshake...")
		vpnResults := runVPNTests(cfg)
		perServer = append(perServer, vpnResults...)
		fmt.Printf(" %sok%s\n", colorGreen, colorReset)

		// 3. РЕАЛЬНЫЙ ТЕСТ САЙТОВ через ключ + bandwidth + exit IP + packet loss
		if !skipSiteTests {
			fmt.Printf("    └─ сайты через ключ (%d сайтов)...", len(CommonSites))
			v, keyResults := runKeyTests(cfg, localIP, localCountry)
			perServer = append(perServer, keyResults...)
			verdicts = append(verdicts, v)
			fmt.Printf(" %s%d/%d, verdict=%s%s\n",
				colorGreen, v.SitesPassed, v.SitesTotal, v.Verdict, colorReset)
		}

		allResults = append(allResults, perServer...)

		// Записываем ноду в failed если хоть один TLS/VPN-тест упал
		cfgFail := false
		for _, r := range vpnResults {
			if r.Status == StatusError {
				cfgFail = true
			}
		}
		if cfgFail || tlsFailed {
			failedConfigs = append(failedConfigs, cfg)
		}
	}

	// 4. Zapret retest для упавших конфигов (с реальной проверкой сайтов внутри!)
	if withZapret && len(failedConfigs) > 0 {
		fmt.Printf("  Zapret retest для %d упавших нод...", len(failedConfigs))
		zapretResults := runZapretRetests(failedConfigs, autoDownload)
		allResults = append(allResults, zapretResults...)
		fmt.Printf(" %sготово%s\n", colorGreen, colorReset)
	}

	// 5. Debug dump
	var dump []DebugSection
	if debugDumpEnabled {
		fmt.Printf("  Сбор debug-дампа...")
		dump = collectDebugDump()
		fmt.Printf(" %s%d секций%s\n", colorGreen, len(dump), colorReset)
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

	// Краткая сводка по ключам в консоль
	if len(verdicts) > 0 {
		fmt.Println()
		fmt.Printf("%sСводка по ключам:%s\n", colorBold, colorReset)
		fmt.Println(formatAllVerdictsTable(verdicts))
	}

	// Сохранить отчёт
	reportFile := "diagnostik_report.txt"
	if len(configs) > 0 || len(subURLProbes) > 0 {
		warpRec := recommendWARPForFailedKeys(failedConfigs)
		if err := saveReportV31(reportFile, configs, allResults, dump, verdicts, subURLForReport, warpRec, privacyMode); err == nil {
			fmt.Printf("  Отчёт сохранён: %s%s%s\n", colorGreen, reportFile, colorReset)
		} else {
			fmt.Printf("  %sОшибка сохранения отчёта: %v%s\n", colorRed, err, colorReset)
		}
	}

	fmt.Println()
	fmt.Printf("  %s>> Отправьте файл \"%s\" в поддержку сервиса,%s\n", colorCyan, reportFile, colorReset)
	fmt.Printf("  %s   который выдал вам ключ.%s\n", colorCyan, colorReset)
	fmt.Println()

	// Интерактивный этап — реальная проверка лучшего ключа в браузере + custom URL
	if !skipInteractive {
		runInteractiveStage(verdicts, configs)
	}

	waitExit()
}

// printDeviceLimitInstructions — точный текст для случая когда сервер вернул
// "превышен лимит устройств". Шаги для пользователя чтобы временно отключить
// устройство и продолжить диагностику.
func printDeviceLimitInstructions() {
	fmt.Println()
	fmt.Println(colorBold + colorRed + "===============================================================" + colorReset)
	fmt.Println(colorBold + colorRed + "  НЕ МОГУ ЗАПУСТИТЬ ТЕСТ: У ВАС ЛИМИТ УСТРОЙСТВ" + colorReset)
	fmt.Println(colorBold + colorRed + "===============================================================" + colorReset)
	fmt.Println()
	fmt.Println("Сервер подписки сообщил что вы превысили лимит устройств для этого ключа.")
	fmt.Println("Чтобы продолжить диагностику, временно освободите одно устройство:")
	fmt.Println()
	fmt.Printf("  1. Откройте в Telegram бота %s%s%s\n", colorCyan, supportBot, colorReset)
	fmt.Printf("  2. Нажмите %s«📋 Мои подписки»%s\n", colorCyan, colorReset)
	fmt.Println("  3. Выберите тот ключ который вы сейчас тестируете (если у вас их несколько)")
	fmt.Printf("  4. Нажмите %s«Устройства»%s\n", colorCyan, colorReset)
	fmt.Printf("  5. Затем %s«🔄 Управление устройствами»%s\n", colorCyan, colorReset)
	fmt.Println("  6. Из списка устройств нажмите на любое — оно будет временно отключено")
	fmt.Println()
	fmt.Printf("  %sПосле завершения работы программы не забудьте сбросить%s\n", colorYellow, colorReset)
	fmt.Printf("  %sтестовое устройство в боте%s\n", colorYellow, colorReset)
	fmt.Println()
	fmt.Printf("  HWID этой машины: %s%s%s\n", colorDim, shortHWID(), colorReset)
	fmt.Println()
}

func waitExit() {
	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		return
	}
	fmt.Println("Нажмите Enter для выхода...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
