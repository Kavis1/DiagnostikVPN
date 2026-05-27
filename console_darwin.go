//go:build darwin

package main

// macOS терминалы (Terminal.app / iTerm2) поддерживают ANSI-цвета по умолчанию,
// никакая инициализация не нужна.
func enableWindowsColors() {}
