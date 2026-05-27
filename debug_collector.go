package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// DebugSection — блок сырого вывода консольной команды в финальный отчёт.
// Это нужно поддержке: чтобы видеть не только summary, но и реальные текстовые
// дампы ipconfig/route/netstat и т.п. — диагностика без них сильно слепее.
type DebugSection struct {
	Title  string
	Cmd    string
	Output string
}

// collectDebugDump запускает набор команд и складывает их сырой вывод.
// Все команды read-only и не меняют состояние системы.
//
// Каждая команда оборачивается в `cmd /c chcp 65001 >nul & <command>` чтобы
// получать UTF-8 вывод вместо OEM-кодировки (cp866 для русской Windows).
func collectDebugDump() []DebugSection {
	cmds := []struct {
		title string
		full  string
	}{
		{"ipconfig /all", "ipconfig /all"},
		{"route print", "route print"},
		{"netstat -rn (маршруты)", "netstat -rn"},
		{"netstat -an (открытые порты)", "netstat -an"},
		{"netsh winhttp show proxy", "netsh winhttp show proxy"},
		{"netsh advfirewall show currentprofile", "netsh advfirewall show currentprofile"},
		{"netsh advfirewall show allprofiles", "netsh advfirewall show allprofiles"},
		{"netsh int tcp show global", "netsh int tcp show global"},
		{"netsh int ipv4 show interfaces", "netsh int ipv4 show interfaces"},
		{"systeminfo (короткая выдержка)", "systeminfo"},
		{"tasklist /v (видимые процессы)", "tasklist /v /FO TABLE"},
	}

	out := make([]DebugSection, 0, len(cmds))
	for _, c := range cmds {
		s := DebugSection{
			Title: c.title,
			Cmd:   c.full,
		}
		raw, err := runUTF8Cmd(c.full)
		if err != nil && raw == "" {
			s.Output = "[ошибка выполнения: " + err.Error() + "]"
		} else {
			s.Output = trimDump(raw, 12000) // ограничим объём чтобы отчёт не разбух
		}
		out = append(out, s)
	}
	return out
}

// runUTF8Cmd выполняет команду через cmd /c и декодирует вывод из OEM-кодировки
// (cp866 для русской Windows, cp437 для англ.) в UTF-8.
//
// ipconfig/route/netstat игнорируют chcp 65001 и пишут в OEM хост-локали —
// поэтому проще не бороться, а декодировать на нашей стороне.
func runUTF8Cmd(command string) (string, error) {
	ctx, cancel := windowsCmdContext(25 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cmd", "/c", command)
	out, err := cmd.CombinedOutput()
	return decodeConsoleOutput(out), err
}

// decodeConsoleOutput пытается определить кодировку Windows-консоли и декодировать.
// Стратегия:
//   1. Если вывод уже валидный UTF-8 — возвращаем как есть.
//   2. Иначе пробуем cp866 (русская DOS).
//   3. Если результат содержит мусор — пробуем cp1251 (русская Windows).
//   4. Иначе оставляем как есть (англ. cp437 совпадает с ASCII в нижней половине).
func decodeConsoleOutput(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	// cp866 — самый частый случай для русской Windows-консоли
	if dec, err := decodeWith(b, charmap.CodePage866.NewDecoder()); err == nil {
		if utf8.ValidString(dec) {
			return dec
		}
	}
	if dec, err := decodeWith(b, charmap.Windows1251.NewDecoder()); err == nil {
		if utf8.ValidString(dec) {
			return dec
		}
	}
	// Fallback — Latin1, не теряем байты
	if dec, err := decodeWith(b, charmap.Windows1252.NewDecoder()); err == nil {
		return dec
	}
	return string(b)
}

func decodeWith(b []byte, dec transform.Transformer) (string, error) {
	r := transform.NewReader(strings.NewReader(string(b)), dec)
	out, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// runWindowsCmd — короткий хелпер для тестов которые хотят прочитать stdout одной командой.
func runWindowsCmd(name string, args ...string) (string, error) {
	ctx, cancel := windowsCmdContext(30 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runWindowsCmdRaw — аналогично, но всегда возвращает что собрали даже при таймауте.
func runWindowsCmdRaw(name string, args ...string) (string, error) {
	ctx, cancel := windowsCmdContext(20 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func trimDump(s string, max int) string {
	if len(s) <= max {
		return strings.TrimRight(s, "\r\n")
	}
	cut := s[:max]
	return strings.TrimRight(cut, "\r\n") + fmt.Sprintf("\n... [обрезано до %d символов]", max)
}

// формат итоговой секции дебага в отчёте
func debugDumpToString(sections []DebugSection) string {
	var b strings.Builder
	for _, s := range sections {
		fmt.Fprintf(&b, "\n----- %s (`%s`) -----\n", s.Title, s.Cmd)
		fmt.Fprintf(&b, "%s\n", s.Output)
	}
	return b.String()
}
