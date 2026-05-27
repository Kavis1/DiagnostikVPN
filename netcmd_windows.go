//go:build windows

package main

import "strconv"

// pingArgs возвращает аргументы для `ping` под Windows.
//   count — сколько пакетов
//   timeoutMs — таймаут на каждый пакет, мс
//   df — установить Don't Fragment + размер пакета (для MTU-теста)
func pingArgs(count int, timeoutMs int, df bool, size int, host string) []string {
	args := []string{"-n", strconv.Itoa(count), "-w", strconv.Itoa(timeoutMs)}
	if df {
		args = append(args, "-f", "-l", strconv.Itoa(size))
	}
	args = append(args, host)
	return args
}

// tracerouteCmd — строка для cmd /c с включением UTF-8 кодировки.
func tracerouteCmd(host string) (name string, args []string) {
	return "cmd", []string{"/c",
		"chcp 65001 >nul 2>&1 & tracert -d -w 1000 -h 15 " + host}
}
