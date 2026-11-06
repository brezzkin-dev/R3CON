package core

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

type Logger struct {
	mu    sync.Mutex
	level Level
}

var defaultLogger = &Logger{level: Info}

func InitLogger(l Level) { defaultLogger.level = l }

func (l *Logger) log(lv Level, tag, msg string) {
	if lv < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s [%s] %s\n", time.Now().Format("15:04:05"), tag, msg)
}

func Debugf(f string, a ...any) { defaultLogger.log(Debug, "DBG", fmt.Sprintf(f, a...)) }
func Infof(f string, a ...any)  { defaultLogger.log(Info, "INF", fmt.Sprintf(f, a...)) }
func Warnf(f string, a ...any)  { defaultLogger.log(Warn, "WRN", fmt.Sprintf(f, a...)) }
func Errorf(f string, a ...any) { defaultLogger.log(Error, "ERR", fmt.Sprintf(f, a...)) }
