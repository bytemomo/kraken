package logger

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

func SetLoggerToStructured(level logrus.Level, filePath string) {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(level)

	if filePath == "" {
		logrus.SetOutput(os.Stderr)
	} else {
		if file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
			wrt := io.MultiWriter(os.Stderr, file)
			logrus.SetOutput(wrt)
		} else {
			logrus.SetOutput(os.Stderr)
			logrus.WithError(err).Error("Could not create file for logging")
		}
	}
}
