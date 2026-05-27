package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// runTunTroubleshooter — отдельный интерактивный мастер для проблем вида
// "сайты работают, а приложения (Discord, игры, мессенджеры) нет".
//
// Корневая причина почти всегда одна: пользовательский VPN-клиент работает
// в режиме system-proxy / SOCKS5, который ловит только HTTP/HTTPS-трафик
// браузера. Приложения с собственным сетевым стеком игнорируют системный
// прокси и идут напрямую через провайдера.
//
// Решение — TUN-режим (виртуальный сетевой адаптер, через него идёт ВЕСЬ
// трафик). Мастер ведёт пользователя через диагностику и помогает понять
// что именно не работает.
//
// Возвращает структуру для логирования в отчёт.
type TunReport struct {
	Used               bool
	UserWantsApps      bool
	TunReportedAsOn    bool
	BaselineIP         string
	BaselineCountry    string
	WithVPNIP          string
	WithVPNCountry     string
	IPChanged          bool
	ResidualProcesses  []string
	UserClientName     string
	UserAppFailing     string
	OwnTUN             *TestTUNResult // результат запуска нашего тестового TUN
	Notes              []string
}

// vpnClientProcesses — процессы которые мы просим закрыть перед измерением baseline.
// Это всё что НЕ TUN-режим (просто SOCKS-frontend) — оно создаёт ложное ощущение
// "VPN работает", путая baseline.
var vpnClientProcesses = []struct {
	exe  string
	name string
}{
	{"happ.exe", "Happ"},
	{"happ-cli.exe", "Happ CLI"},
	{"hiddify.exe", "Hiddify"},
	{"hiddifynext.exe", "Hiddify Next"},
	{"hiddifycli.exe", "Hiddify CLI"},
	{"v2rayn.exe", "v2rayN"},
	{"v2rayng.exe", "v2rayNG"},
	{"v2ray.exe", "V2Ray Core"},
	{"xray.exe", "Xray Core"},
	{"sing-box.exe", "sing-box"},
	{"nekobox.exe", "NekoBox"},
	{"nekoray.exe", "NekoRay"},
	{"clash.exe", "Clash"},
	{"clash-verge.exe", "Clash Verge"},
	{"clash-meta.exe", "Clash Meta"},
	{"mihomo.exe", "Mihomo"},
	{"invy.exe", "Invy"},
	{"invy-cli.exe", "Invy CLI"},
	{"v2box.exe", "V2Box"},
	{"streisand.exe", "Streisand"},
	{"karing.exe", "Karing"},
	{"foxray.exe", "FoXray"},
}

// tunModeHelp — короткие подсказки где в каждом популярном клиенте включается TUN.
var tunModeHelp = []struct {
	client string
	hint   string
}{
	{"Hiddify Next", "Настройки → Системные → включить «TUN Mode» (нужны права администратора)"},
	{"v2rayN", "Меню «Settings» → «Параметры системного прокси» → выбрать «TUN Mode»"},
	{"NekoBox/NekoRay", "Preferences → Core → включить «TUN Mode» + запуск от админа"},
	{"Clash Verge / Clash for Windows", "Settings → System Setup → включить «TUN Mode» (Service mode)"},
	{"sing-box (вручную)", "В конфиге inbound type=tun, нужен wintun.dll и admin"},
	{"Happ", "Настройки → «Режим VPN» → включить «TUN»"},
}

// runTunTroubleshooter запускает мастер. Возвращает TunReport который потом
// можно дописать в diagnostik_report.txt чтобы поддержка видела весь контекст.
//
// Если передан bestCfg — используется для запуска нашего собственного тестового TUN
// (когда пользовательский клиент не справился).
func runTunTroubleshooter(bestCfg *VPNConfig) *TunReport {
	reader := bufio.NewReader(os.Stdin)
	r := &TunReport{Used: true}

	fmt.Println()
	fmt.Println(colorBold + "============================================================" + colorReset)
	fmt.Println(colorBold + "  МАСТЕР: ПРИЛОЖЕНИЯ НЕ ХОДЯТ ЧЕРЕЗ VPN" + colorReset)
	fmt.Println(colorBold + "============================================================" + colorReset)
	fmt.Println()

	// ----- 1. Сайты работают вообще? -----
	fmt.Println("1) Сейчас сайты в браузере открываются через VPN?")
	fmt.Println("   (зайдите на youtube.com / discord.com и проверьте)")
	fmt.Print("   [y/n]> ")
	sites := yesNo(reader)
	if !sites {
		fmt.Println()
		fmt.Printf("%sСайты не открываются — это базовая проблема, не TUN.%s\n", colorRed, colorReset)
		fmt.Println("Завершите этот мастер и используйте основной режим программы:")
		fmt.Println("он проверит ключи, DPI, антивирус и т.д.")
		r.Notes = append(r.Notes, "Сайты не открываются — основная диагностика не сделана/нашла блокировки")
		return r
	}

	// ----- 2. Что должно работать -----
	fmt.Println()
	fmt.Println("2) Что должно работать?")
	fmt.Println("   1 — только сайты в браузере")
	fmt.Println("   2 — сайты И приложения (Discord, игры, мессенджеры)")
	fmt.Print("   [1/2]> ")
	choice := readLine(reader)
	if choice == "1" {
		fmt.Println()
		fmt.Printf("%sОК — system-proxy/SOCKS5 режима достаточно. Мастер завершён.%s\n", colorGreen, colorReset)
		r.Notes = append(r.Notes, "Пользователю нужны только сайты — TUN не нужен")
		return r
	}
	if choice != "2" {
		fmt.Printf("%sНеверный выбор. Выход.%s\n", colorYellow, colorReset)
		return r
	}
	r.UserWantsApps = true

	// ----- 3. TUN включён? -----
	fmt.Println()
	fmt.Println("3) В вашем VPN-клиенте включён режим TUN (Tunnel) / Virtual NIC?")
	fmt.Println("   Это режим когда клиент создаёт виртуальный сетевой адаптер")
	fmt.Println("   и через него идёт ВЕСЬ трафик системы (не только браузер).")
	fmt.Println("   Опции:")
	fmt.Println("     y — да, включён")
	fmt.Println("     n — нет такого режима / не знаю где искать")
	fmt.Print("   [y/n]> ")
	tunOn := yesNo(reader)
	r.TunReportedAsOn = tunOn

	if !tunOn {
		fmt.Println()
		fmt.Printf("%sГде включить TUN в популярных клиентах:%s\n", colorCyan, colorReset)
		for _, h := range tunModeHelp {
			fmt.Printf("  • %s%s%s — %s\n", colorBold, h.client, colorReset, h.hint)
		}
		fmt.Println()
		fmt.Println("ВАЖНО: запускайте VPN-клиент ОТ АДМИНИСТРАТОРА — TUN без админ-прав не поднимется.")
		fmt.Println("Включите TUN и вернитесь в этот мастер.")
		fmt.Println()
		fmt.Print("Включили TUN? [y/n]> ")
		if !yesNo(reader) {
			r.Notes = append(r.Notes, "Пользователь не смог включить TUN-режим")
			fmt.Println()
			fmt.Println("Без TUN-режима приложения через VPN работать не будут (это by design системного прокси).")
			fmt.Println("Решение — установить VPN-клиент с TUN-поддержкой (Hiddify Next / Clash Verge / NekoBox).")
			return r
		}
		r.TunReportedAsOn = true
	}

	// ----- 4. Просим выключить VPN для замера baseline -----
	fmt.Println()
	fmt.Println(colorBold + "4) Замер исходного IP (без VPN)" + colorReset)
	fmt.Println()
	fmt.Println("Чтобы проверить что TUN РЕАЛЬНО заворачивает трафик,")
	fmt.Println("нужно сначала запомнить ваш IP БЕЗ VPN.")
	fmt.Println()
	fmt.Println("ОТКЛЮЧИТЕ VPN-клиент (Disconnect в его UI) и ЗАКРОЙТЕ его окно.")
	fmt.Println("Затем нажмите Enter:")
	fmt.Print("> ")
	reader.ReadString('\n')

	// Проверяем что VPN-процессы закрыты
	residual := findRunningVPNProcesses()
	if len(residual) > 0 {
		fmt.Println()
		fmt.Printf("%sВНИМАНИЕ: ещё запущены VPN-процессы:%s\n", colorYellow, colorReset)
		for _, p := range residual {
			fmt.Printf("  • %s\n", p)
		}
		fmt.Println()
		fmt.Println("Закройте их полностью (Task Manager → End task если не закрываются через X).")
		fmt.Println("Нажмите Enter когда закроете:")
		fmt.Print("> ")
		reader.ReadString('\n')

		residual = findRunningVPNProcesses()
		if len(residual) > 0 {
			fmt.Printf("%sВсё ещё активны: %s%s\n", colorRed, strings.Join(residual, ", "), colorReset)
			fmt.Println("Замер baseline IP будет неточным.")
			r.ResidualProcesses = residual
		}
	}

	// Запоминаем baseline IP
	fmt.Printf("Определяю ваш IP... ")
	ip, country, err := detectLocalExitIP()
	if err != nil || ip == "" {
		fmt.Printf("%sне удалось (%v)%s\n", colorRed, err, colorReset)
		fmt.Println("Без baseline IP проверить смену не получится. Завершаю мастер.")
		r.Notes = append(r.Notes, "Не удалось определить baseline IP")
		return r
	}
	fmt.Printf("%s%s (%s)%s\n", colorGreen, ip, country, colorReset)
	r.BaselineIP = ip
	r.BaselineCountry = country

	// ----- 5. Включить VPN в TUN-режиме -----
	fmt.Println()
	fmt.Println(colorBold + "5) Включите VPN в TUN-режиме" + colorReset)
	fmt.Println()
	fmt.Println("Запустите ваш VPN-клиент ОТ ИМЕНИ АДМИНИСТРАТОРА, убедитесь что в нём")
	fmt.Println("включён TUN-режим, и подключитесь к серверу.")
	fmt.Println()
	fmt.Print("Подключились? [y/n]> ")
	if !yesNo(reader) {
		fmt.Println("Без активного VPN продолжить тест нельзя. Завершаю мастер.")
		return r
	}

	// Даём 2-3 секунды чтобы туннель устаканился (DHCP-like negotiation, route setup)
	fmt.Printf("Жду пока TUN устаканится...")
	time.Sleep(3 * time.Second)
	fmt.Println(" ок")

	fmt.Printf("Определяю IP через текущее соединение... ")
	ip2, country2, err := detectLocalExitIP()
	if err != nil || ip2 == "" {
		fmt.Printf("%sне удалось (%v)%s\n", colorRed, err, colorReset)
		fmt.Println("Странно — VPN включён, но интернет не отвечает. Возможные причины:")
		fmt.Println("  • TUN не поднялся (нет прав админа / wintun.dll отсутствует)")
		fmt.Println("  • DNS leak — отравлен системный DNS")
		fmt.Println("  • Firewall блокирует приложения")
		r.Notes = append(r.Notes, "VPN включён, но интернет не работает (TUN не поднялся / DNS / Firewall)")
		return r
	}
	fmt.Printf("%s%s (%s)%s\n", colorGreen, ip2, country2, colorReset)
	r.WithVPNIP = ip2
	r.WithVPNCountry = country2
	r.IPChanged = (ip2 != ip)

	// ----- 6. Анализ -----
	fmt.Println()
	if !r.IPChanged {
		fmt.Printf("%s%s>> IP НЕ СМЕНИЛСЯ: %s == %s%s\n", colorBold, colorRed, ip, ip2, colorReset)
		fmt.Println()
		fmt.Println("Это означает что TUN-режим НЕ работает (или вы забыли подключиться).")
		fmt.Println("Возможные причины:")
		fmt.Println("  1. VPN-клиент не от админа — TUN не поднялся, fallback на system-proxy")
		fmt.Println("  2. В клиенте включён 'split tunneling' и наша программа в исключениях")
		fmt.Println("  3. Конфликт с другим VPN-адаптером (несколько wintun одновременно)")
		fmt.Println("  4. Firewall режет TUN-интерфейс")
		fmt.Println()
		fmt.Println("Параллельная диагностика — посмотрим какие VPN-адаптеры сейчас активны:")
		printActiveTUNAdapters()

		r.Notes = append(r.Notes, fmt.Sprintf("TUN не сработал: baseline IP %s == VPN IP %s", ip, ip2))
	} else {
		fmt.Printf("%s%s>> IP СМЕНИЛСЯ: %s (%s) → %s (%s)%s\n",
			colorBold, colorGreen, ip, country, ip2, country2, colorReset)
		fmt.Println()
		fmt.Println("TUN-режим работает корректно — программы Go увидели новый IP.")
		fmt.Println("Это значит что Discord / игры / мессенджеры тоже должны пойти через VPN.")
		fmt.Println()
		fmt.Print("Откройте ваше проблемное приложение. Работает теперь? [y/n]> ")
		if yesNo(reader) {
			fmt.Printf("%s>> Отлично, проблема решена.%s\n", colorGreen, colorReset)
			r.Notes = append(r.Notes, "TUN заработал, приложение тоже")
			return r
		}
	}

	// ----- 7. Своя верификация: поднимаем СВОЙ тестовый TUN -----
	fmt.Println()
	fmt.Println(colorBold + "7) Поднимаю свой тестовый TUN — независимая проверка" + colorReset)
	fmt.Println()
	fmt.Println("Чтобы исключить «дело в моём клиенте», запустим свой sing-box")
	fmt.Println("с TUN-режимом на лучшем рабочем ключе из подписки. Если у нас IP")
	fmt.Println("сменится — значит TUN в этой системе работает в принципе.")
	fmt.Println()
	fmt.Println("ВАЖНО: 1) перед этим закройте ваш VPN-клиент (Disconnect + закрыть окно).")
	fmt.Println("       2) программа должна быть запущена ОТ АДМИНИСТРАТОРА.")
	fmt.Println()
	fmt.Print("Закрыли клиент и готовы? [y/n]> ")
	if yesNo(reader) {
		// Проверяем что VPN-процессы реально закрыты
		residual2 := findRunningVPNProcesses()
		if len(residual2) > 0 {
			fmt.Printf("%sВсё ещё запущены: %s. Свой TUN не запускаю — будет конфликт.%s\n",
				colorRed, strings.Join(residual2, ", "), colorReset)
			r.Notes = append(r.Notes, "Свой TUN не тестировали — пользователь не закрыл свой клиент: "+strings.Join(residual2, ", "))
		} else if bestCfg == nil {
			fmt.Printf("%sНет конфигов для теста (вы запустили мастер без подписки).%s\n", colorYellow, colorReset)
			r.Notes = append(r.Notes, "Свой TUN не тестировали — отсутствует подписка для лучшего ключа")
		} else {
			fmt.Printf("Использую ключ %s%s%s\n", colorCyan, nodeDisplayName(bestCfg), colorReset)
			ownTun := runTestTUN(bestCfg, r.BaselineIP)
			r.OwnTUN = ownTun

			fmt.Println()
			if ownTun.IPChanged {
				fmt.Printf("%s%s>> НАШ TUN РАБОТАЕТ: %s → %s%s\n",
					colorBold, colorGreen, r.BaselineIP, ownTun.IPAfter, colorReset)
				fmt.Println()
				fmt.Println("Это значит:")
				fmt.Println("  • Wintun/драйвер в порядке")
				fmt.Println("  • Admin-права хватает")
				fmt.Println("  • Сетевой стек системы готов к TUN")
				fmt.Println("  • Проблема в вашем VPN-клиенте (конфиг / split-tunneling / mode)")
				fmt.Println()
				fmt.Println("Сейчас весь трафик системы идёт через наш TUN. Откройте проблемное")
				fmt.Println("приложение и проверьте — работает ли через наш туннель.")
				fmt.Print("Работает? [y/n]> ")
				if yesNo(reader) {
					fmt.Printf("%s>> Подтверждено: приложения через TUN работают.%s\n", colorGreen, colorReset)
					fmt.Println("Используйте свой клиент в TUN-режиме (или sing-box / Hiddify Next вместо текущего).")
					r.Notes = append(r.Notes, "Приложение работает через наш тестовый TUN — проблема в клиенте пользователя")
				} else {
					r.Notes = append(r.Notes, "Приложение НЕ работает даже через наш TUN — проблема не в туннеле")
				}
			} else if ownTun.ErrorMsg != "" {
				fmt.Printf("%s%s>> НАШ TUN НЕ ПОДНЯЛСЯ: %s%s\n",
					colorBold, colorRed, ownTun.ErrorMsg, colorReset)
				if !ownTun.AdminPresent {
					fmt.Println()
					fmt.Println("Решение: закройте программу, нажмите ПКМ на diagnostik.exe →")
					fmt.Println("«Запустить от имени администратора», затем используйте флаг -only-tun.")
				}
			} else {
				fmt.Printf("%s%s>> НАШ TUN ПОДНЯЛСЯ, НО IP НЕ СМЕНИЛСЯ%s\n", colorBold, colorYellow, colorReset)
				fmt.Println("  • Возможно сам ключ не работает (попробуйте другой)")
				fmt.Println("  • Или default route не перехвачен (конфликт с другим VPN-адаптером)")
			}
		}
	}

	// ----- 8. Если приложение всё равно не работает — собираем инфо -----
	fmt.Println()
	fmt.Println(colorBold + "Собираем информацию для поддержки" + colorReset)
	fmt.Println()
	fmt.Print("Какой VPN-клиент вы используете? (название): ")
	r.UserClientName = readLine(reader)
	fmt.Print("Какое приложение не работает? (название): ")
	r.UserAppFailing = readLine(reader)
	fmt.Print("Если есть ссылка на сайт этого приложения — введите её (или Enter): ")
	site := readLine(reader)
	if site != "" {
		r.Notes = append(r.Notes, "Сайт приложения: "+site)
	}

	fmt.Println()
	fmt.Println(colorGreen + "Информация сохранена. После выхода из мастера она будет дописана в diagnostik_report.txt" + colorReset)
	fmt.Println(colorGreen + "Отправьте этот отчёт в поддержку." + colorReset)
	return r
}

// findRunningVPNProcesses возвращает список человеко-читаемых имён VPN-клиентов
// которые сейчас активны (через tasklist).
func findRunningVPNProcesses() []string {
	pl := getProcessList()
	if pl == "" {
		return nil
	}
	found := map[string]bool{}
	for _, p := range vpnClientProcesses {
		if strings.Contains(pl, strings.ToLower(p.exe)) {
			found[p.name] = true
		}
	}
	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// printActiveTUNAdapters выводит активные TUN/TAP/Wintun сетевые интерфейсы.
func printActiveTUNAdapters() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	hits := 0
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		nl := strings.ToLower(ifc.Name)
		isTun := strings.Contains(nl, "tun") || strings.Contains(nl, "tap") ||
			strings.Contains(nl, "wintun") || strings.Contains(nl, "wireguard") ||
			strings.Contains(nl, "wg")
		if !isTun {
			continue
		}
		addrs, _ := ifc.Addrs()
		strs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			strs = append(strs, a.String())
		}
		fmt.Printf("    • %s: %s\n", ifc.Name, strings.Join(strs, ", "))
		hits++
	}
	if hits == 0 {
		fmt.Printf("    (TUN/TAP-адаптеры не обнаружены — это и есть проблема, TUN не поднялся)\n")
	}
}

// === helpers ===

func yesNo(reader *bufio.Reader) bool {
	line := readLine(reader)
	l := strings.ToLower(line)
	return l == "y" || l == "yes" || l == "д" || l == "да" || l == "1"
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// formatTunReportForFile — секция в diagnostik_report.txt с результатами мастера.
func formatTunReportForFile(r *TunReport) string {
	if r == nil || !r.Used {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n==================================================\n")
	b.WriteString("TUN-TROUBLESHOOTER (мастер «приложения не ходят через VPN»)\n")
	b.WriteString("==================================================\n")
	if r.UserWantsApps {
		b.WriteString("Пользователю нужно: сайты + приложения (TUN обязателен)\n")
	} else {
		b.WriteString("Пользователю нужно: только сайты\n")
	}
	if r.TunReportedAsOn {
		b.WriteString("TUN-режим заявлен включённым: да\n")
	} else {
		b.WriteString("TUN-режим заявлен включённым: нет\n")
	}
	if r.BaselineIP != "" {
		fmt.Fprintf(&b, "Baseline IP (без VPN): %s (%s)\n", r.BaselineIP, r.BaselineCountry)
	}
	if r.WithVPNIP != "" {
		fmt.Fprintf(&b, "IP с включённым VPN: %s (%s)\n", r.WithVPNIP, r.WithVPNCountry)
	}
	if r.BaselineIP != "" && r.WithVPNIP != "" {
		if r.IPChanged {
			b.WriteString("Результат: IP СМЕНИЛСЯ — TUN работает корректно\n")
		} else {
			b.WriteString("Результат: IP НЕ СМЕНИЛСЯ — TUN не работает (см. список причин в основном отчёте)\n")
		}
	}
	if len(r.ResidualProcesses) > 0 {
		fmt.Fprintf(&b, "Активные VPN-процессы на момент замера baseline: %s\n",
			strings.Join(r.ResidualProcesses, ", "))
	}
	if r.UserClientName != "" {
		fmt.Fprintf(&b, "Используемый VPN-клиент: %s\n", r.UserClientName)
	}
	if r.UserAppFailing != "" {
		fmt.Fprintf(&b, "Приложение которое не работает: %s\n", r.UserAppFailing)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "Заметка: %s\n", n)
	}
	if r.OwnTUN != nil {
		b.WriteString(formatTestTUNForFile(r.OwnTUN))
	}
	return b.String()
}

// findBestCfgFor TUN — нам не подходят xhttp ключи (sing-box не имеет xhttp).
// Возвращает первый ключ из ranked-списка который sing-box умеет.
func pickBestCfgForTUN(verdicts []KeyVerdict, configs []*VPNConfig) *VPNConfig {
	type ranked struct {
		score int
		cfg   *VPNConfig
	}
	pool := make([]ranked, 0, len(verdicts))
	for i, v := range verdicts {
		if i >= len(configs) {
			break
		}
		if strings.EqualFold(configs[i].Transport, "xhttp") {
			continue // xhttp идёт через xray, у которого TUN не настроен
		}
		s := verdictScore(v.Verdict)
		if s <= 0 {
			continue
		}
		pool = append(pool, ranked{s, configs[i]})
	}
	if len(pool) == 0 {
		return nil
	}
	best := pool[0]
	for _, p := range pool[1:] {
		if p.score > best.score {
			best = p
		}
	}
	return best.cfg
}
