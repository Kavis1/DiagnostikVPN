//go:build darwin

package main

import "strconv"

// pingArgs возвращает аргументы для `ping` под macOS.
// -c count, -W timeoutMs (BSD ping: -W в мс),
// -D — установить Don't Fragment bit (для MTU-теста),
// -s — payload size (без 8 байт ICMP-header'a + 20 IP).
func pingArgs(count int, timeoutMs int, df bool, size int, host string) []string {
	args := []string{"-c", strconv.Itoa(count), "-W", strconv.Itoa(timeoutMs)}
	if df {
		args = append(args, "-D", "-s", strconv.Itoa(size))
	}
	args = append(args, host)
	return args
}

// tracerouteCmd — на macOS встроенный traceroute.
// -n — без обратного DNS, -w 1 — таймаут на пакет 1 сек, -m 15 — макс TTL.
func tracerouteCmd(host string) (name string, args []string) {
	return "traceroute", []string{"-n", "-w", "1", "-m", "15", host}
}
