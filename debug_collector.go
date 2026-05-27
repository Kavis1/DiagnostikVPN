package main

import (
	"fmt"
	"strings"
)

// DebugSection — блок сырого вывода консольной команды в финальный отчёт.
// Это нужно поддержке: чтобы видеть не только summary, но и реальные текстовые
// дампы ipconfig/route/netstat и т.п. — диагностика без них сильно слепее.
type DebugSection struct {
	Title  string
	Cmd    string
	Output string
}

// collectDebugDump запускает набор команд (см. platformDebugCommands)
// и складывает их сырой вывод в секции отчёта.
func collectDebugDump() []DebugSection {
	cmds := platformDebugCommands()
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
			s.Output = trimDump(raw, 12000)
		}
		out = append(out, s)
	}
	return out
}

type debugCmd struct {
	title string
	full  string
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
