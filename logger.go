package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Logger struct {
	mainLogFile    *os.File
	sessionLogFile *os.File
	logDir         string
}

// NewLogger cria um novo logger com diretório logs/
func NewLogger() (*Logger, error) {
	logDir := "logs"
	
	// Cria o diretório se não existir
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("error creating logs directory: %v", err)
	}

	// Abre/cria o arquivo main sniffer.log
	mainLogPath := filepath.Join(logDir, "sniffer.log")
	mainLog, err := os.OpenFile(mainLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening main log file: %v", err)
	}

	// Cria o arquivo com timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	sessionLogPath := filepath.Join(logDir, fmt.Sprintf("sniffer_%s.log", timestamp))
	sessionLog, err := os.OpenFile(sessionLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		mainLog.Close()
		return nil, fmt.Errorf("error opening session log file: %v", err)
	}

	return &Logger{
		mainLogFile:    mainLog,
		sessionLogFile: sessionLog,
		logDir:         logDir,
	}, nil
}

// Log escreve em ambos os arquivos
func (l *Logger) Log(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	formattedMessage := fmt.Sprintf("[%s] %s\n", timestamp, message)

	// Escreve no arquivo principal
	l.mainLogFile.WriteString(formattedMessage)

	// Escreve no arquivo da sessão
	l.sessionLogFile.WriteString(formattedMessage)
}

// Close fecha os arquivos
func (l *Logger) Close() {
	if l.mainLogFile != nil {
		l.mainLogFile.Close()
	}
	if l.sessionLogFile != nil {
		l.sessionLogFile.Close()
	}
}