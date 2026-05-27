package main

import (
	"context"
	"time"
)

// windowsCmdContext возвращает context.Context с заданным таймаутом для exec.CommandContext.
// Вынесено в отдельный файл чтобы избежать дублирования между debug_collector.go и другими тестами.
func windowsCmdContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
