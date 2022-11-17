package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"log/syslog"
)

type Loggy struct {
	io.Writer
	s *syslog.Writer
	l *log.Logger
}

func NewTermLoggy(w io.Writer, prefix string, flag int) *Loggy {
	l := log.New(w, prefix+": ", flag)
	return &Loggy{
		s: nil,
		l: l,
	}
}

func NewSysLoggy(priority syslog.Priority, tag string) (*Loggy, error) {
	w, err := syslog.New(priority, tag)
	if err != nil {
		return nil, err
	}
	return &Loggy{
		s: w,
		l: nil,
	}, nil
}

func (l *Loggy) Write(msg []byte) (int, error) {
	if l.l != nil {
		l.l.Println(msg)
		return len(msg), nil
	}
	if l.s != nil {
		return l.s.Write(msg)
	}
	return 0, errors.New("No backend logger defined")
}

func (l *Loggy) Debug(msg string) {
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Debug(msg)
	}
}

func (l *Loggy) Debugf(format string, v ...interface{}) {
	l.Debug(fmt.Sprintf(format, v...))
}

func (l *Loggy) Info(msg string) {
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Info(msg)
	}
}

func (l *Loggy) Infof(format string, v ...interface{}) {
	l.Info(fmt.Sprintf(format, v...))
}

func (l *Loggy) Notice(msg string) {
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Notice(msg)
	}
}

func (l *Loggy) Noticef(format string, v ...interface{}) {
	l.Notice(fmt.Sprintf(format, v...))
}

func (l *Loggy) Warning(msg string) {
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Warning(msg)
	}
}

func (l *Loggy) Warningf(format string, v ...interface{}) {
	l.Warning(fmt.Sprintf(format, v...))
}

func (l *Loggy) Err(msg string) {
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Err(msg)
	}
}

func (l *Loggy) Errf(format string, v ...interface{}) {
	l.Err(fmt.Sprintf(format, v...))
}
