package logger

import (
	"log"
	"os"
)

var (
	InfoLog  *log.Logger
	ErrorLog *log.Logger
	DebugLog *log.Logger
)

func Init(verbose bool) {
	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	
	if verbose {
		DebugLog = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		// Discard debug logs
		DebugLog = log.New(os.Stdout, "", 0)
		DebugLog.SetOutput(os.Stdout) // We will discard inside debug methods or just set to a discard writer
		file, _ := os.Open(os.DevNull)
		DebugLog.SetOutput(file)
	}
}

func Info(msg string, args ...interface{}) {
	InfoLog.Printf(msg, args...)
}

func Error(msg string, args ...interface{}) {
	ErrorLog.Printf(msg, args...)
}

func Debug(msg string, args ...interface{}) {
	DebugLog.Printf(msg, args...)
}
