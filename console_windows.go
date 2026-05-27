//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// enableWindowsColors включает виртуальные терминальные коды в cmd.exe (Win10+).
// Без этого ANSI escape-последовательности будут показываться как мусор.
func enableWindowsColors() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	handle, _ := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	var mode uint32
	getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	setConsoleMode.Call(uintptr(handle), uintptr(mode|0x0004))
}
