// Copyright (C) 2020-2024 Pascal Lalonde <plalonde@overnet.ca>
//
// This file is part of PotatoFS, a FUSE filesystem implementation.
//
// PotatoFS is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"log/syslog"
)

// TODO: need throttled logging

type Loggy struct {
	io.Writer
	s       *syslog.Writer
	l       *log.Logger
	logMask syslog.Priority
}

func NewTermLoggy(w io.Writer, prefix string, flag int, logMask syslog.Priority) *Loggy {
	l := log.New(w, prefix+": ", flag)
	return &Loggy{
		s:       nil,
		l:       l,
		logMask: logMask,
	}
}

func NewSysLoggy(priority syslog.Priority, logMask syslog.Priority, tag string) (*Loggy, error) {
	w, err := syslog.New(priority, tag)
	if err != nil {
		return nil, err
	}
	return &Loggy{
		s:       w,
		l:       nil,
		logMask: logMask,
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
	if l.logMask < syslog.LOG_DEBUG {
		return
	}
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Debug(msg)
	}
}

func (l *Loggy) Debugf(format string, v ...interface{}) {
	if l.logMask < syslog.LOG_DEBUG {
		return
	}
	l.Debug(fmt.Sprintf(format, v...))
}

func (l *Loggy) Info(msg string) {
	if l.logMask < syslog.LOG_INFO {
		return
	}
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Info(msg)
	}
}

func (l *Loggy) Infof(format string, v ...interface{}) {
	if l.logMask < syslog.LOG_INFO {
		return
	}
	l.Info(fmt.Sprintf(format, v...))
}

func (l *Loggy) Notice(msg string) {
	if l.logMask < syslog.LOG_NOTICE {
		return
	}
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Notice(msg)
	}
}

func (l *Loggy) Noticef(format string, v ...interface{}) {
	if l.logMask < syslog.LOG_NOTICE {
		return
	}
	l.Notice(fmt.Sprintf(format, v...))
}

func (l *Loggy) Warning(msg string) {
	if l.logMask < syslog.LOG_WARNING {
		return
	}
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Warning(msg)
	}
}

func (l *Loggy) Warningf(format string, v ...interface{}) {
	if l.logMask < syslog.LOG_WARNING {
		return
	}
	l.Warning(fmt.Sprintf(format, v...))
}

func (l *Loggy) Err(msg string) {
	if l.logMask < syslog.LOG_ERR {
		return
	}
	if l.l != nil {
		l.l.Println(msg)
	}
	if l.s != nil {
		l.s.Err(msg)
	}
}

func (l *Loggy) Errf(format string, v ...interface{}) {
	if l.logMask < syslog.LOG_ERR {
		return
	}
	l.Err(fmt.Sprintf(format, v...))
}
