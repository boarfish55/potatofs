// Copyright (C) 2020-2022 Pascal Lalonde <plalonde@overnet.ca>
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
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	program = "backend_s3"
)

var (
	server = flag.Bool("server", false, "Starts a S3 backend service")
)

type Config struct {
	S3Endpoint            string `toml:"s3_endpoint"`
	S3Bucket              string `toml:"s3_bucket"`
	S3Region              string `toml:"s3_region"`
	AccessKeyID           string `toml:"access_key_id"`
	SecretAccessKey       string `toml:"secret_access_key"`
	SocketPath            string `toml:"socket_path"`
	BackendBytes          uint64 `toml:"backend_bytes"`
	BackendTimeoutSeconds int64  `toml:"backend_timeout_seconds"`
}

func NewConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding configuration: %v", err)
	}
	return cfg, nil
}

var config Config
var logger *Loggy

type MgrMsgArgs struct {
	BackendName string `json:"backend_name"`
	LocalPath   string `json:"local_path"`
	Inode       uint64 `json:"inode"`
	Base        int64  `json:"base"`
}

type MgrMsg struct {
	Command string     `json:"command"`
	Args    MgrMsgArgs `json:"args"`
}

type MgrMsgDfResponse struct {
	Status     string `json:"status"`
	UsedBytes  uint64 `json:"used_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
}

type MgrMsgGetResponse struct {
	Status  string `json:"status"`
	InBytes int64  `json:"in_bytes"`
}

type MgrMsgPutResponse struct {
	Status   string `json:"status"`
	OutBytes int64  `json:"out_bytes"`
}

type MgrMsgErrResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func sendErrResponse(c net.Conn, format string, v ...interface{}) {
	enc := json.NewEncoder(c)
	resp := &MgrMsgErrResponse{
		Status: "ERR",
		Msg:    fmt.Sprintf(format, v...),
	}
	logger.Errf(resp.Msg)
	if err := enc.Encode(resp); err != nil {
		logger.Errf("sendErrResponse: %v", err)
	}
}

func handleClient(c net.Conn, s3c *s3.S3) {
	var msg MgrMsg

	ctx := context.Background()

	var cancelFn func()
	if config.BackendTimeoutSeconds > 0 {
		ctx, cancelFn = context.WithTimeout(ctx, time.Duration(config.BackendTimeoutSeconds)*time.Second)
	}

	if cancelFn != nil {
		defer cancelFn()
	}

	defer c.Close()
	dec := json.NewDecoder(c)
	if err := dec.Decode(&msg); err != nil {
		if err != io.EOF {
			logger.Errf("handleClient: Decode: %v", err)
		}
		return
	}

	var resp interface{}
	switch msg.Command {
	case "df":
		var used_bytes uint64
		var ctoken *string
		for {
			out, err := s3c.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
				Bucket:            aws.String(config.S3Bucket),
				MaxKeys:           aws.Int64(2),
				ContinuationToken: ctoken,
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
					sendErrResponse(c, "df canceled: %v", err)
				} else {
					sendErrResponse(c, "df failed: %v", err)
				}
				return
			}

			for _, o := range out.Contents {
				if o.Size != nil {
					used_bytes += uint64(*o.Size)
				}
			}
			if out.IsTruncated != nil && *out.IsTruncated {
				ctoken = out.NextContinuationToken
			} else {
				break
			}
		}

		resp = MgrMsgDfResponse{
			Status:     "OK",
			UsedBytes:  used_bytes,
			TotalBytes: config.BackendBytes,
		}
	case "get":
		// We use the syscall file interface here because we want to use
		// Flock(). This will be important once we start doing things
		// like "predictive" downloading.
		fd, err := syscall.Open(msg.Args.LocalPath, syscall.O_RDWR|syscall.O_CREAT, 0600)
		if err != nil {
			sendErrResponse(c, "failed to open file: %q, %v", msg.Args.LocalPath, err)
			return
		}
		defer syscall.Close(fd)

		err = syscall.Flock(fd, syscall.LOCK_EX)
		if err != nil {
			sendErrResponse(c, "failed to flock file: %q, %v", msg.Args.LocalPath, err)
			return
		}

		out, err := s3c.GetObjectWithContext(ctx, &s3.GetObjectInput{
			Bucket: aws.String(config.S3Bucket),
			Key:    aws.String(msg.Args.BackendName),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
				sendErrResponse(c, "download canceled for %q: %v", msg.Args.LocalPath, err)
			} else {
				sendErrResponse(c, "download failed for %q: %v", msg.Args.LocalPath, err)
			}
			return
		}

		buf := make([]byte, 4096)
		for {
			n, err := out.Body.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				sendErrResponse(c, "S3 GET: Read: %v", err)
				return
			}
			n, err = syscall.Write(fd, buf[:n])
			if err != nil {
				sendErrResponse(c, "S3 GET: Write: %v", err)
				return
			}
		}

		var st syscall.Stat_t
		err = syscall.Fstat(fd, &st)
		if err != nil {
			sendErrResponse(c, "failed to stat file: %q, %v", msg.Args.LocalPath, err)
			return
		}

		resp = MgrMsgGetResponse{
			Status:  "OK",
			InBytes: st.Size,
		}
	case "put":
		f, err := os.Open(msg.Args.LocalPath)
		if err != nil {
			sendErrResponse(c, "failed to open file: %q, %v", msg.Args.LocalPath, err)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			sendErrResponse(c, "failed to stat file: %q, %v", msg.Args.LocalPath, err)
			return
		}

		_, err = s3c.PutObjectWithContext(ctx, &s3.PutObjectInput{
			Bucket: aws.String(config.S3Bucket),
			Key:    aws.String(msg.Args.BackendName),
			Body:   f,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
				sendErrResponse(c, "upload canceled for %q: %v", msg.Args.LocalPath, err)
			} else {
				sendErrResponse(c, "upload failed for %q: %v", msg.Args.LocalPath, err)
			}
			return
		}
		resp = MgrMsgPutResponse{
			Status:   "OK",
			OutBytes: st.Size(),
		}
	default:
		resp = MgrMsgErrResponse{
			Status: "ERR",
			Msg:    "unknown command " + msg.Command,
		}
	}

	enc := json.NewEncoder(c)
	if err := enc.Encode(resp); err != nil {
		logger.Errf("Encode: %v", err)
	}
}

func die(code int, format string, v ...interface{}) {
	enc := json.NewEncoder(os.Stderr)
	resp := &MgrMsgErrResponse{
		Status: "ERR",
		Msg:    fmt.Sprintf(format, v...),
	}
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding error in die(): %v\n", err)
	}
	os.Exit(code)
}

func serve() error {
	os.Remove(config.SocketPath)

	laddr, err := net.ResolveUnixAddr("unix", config.SocketPath)
	if err != nil {
		return fmt.Errorf("net.ResolveUnixAddr: %v", err)
	}

	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return fmt.Errorf("net.UnixListener: %v", err)
	}
	defer l.Close()

	// See https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html

	// See: https://docs.aws.amazon.com/sdk-for-go/api/aws/#Config
	sess, err := session.NewSession(&aws.Config{
		Endpoint:    aws.String(config.S3Endpoint),
		Region:      aws.String(config.S3Region),
		Credentials: credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, ""),
	})
	if err != nil {
		return err
	}

	s3c := s3.New(sess)
	for {
		l.SetDeadline(time.Now().Add(60 * time.Second))
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			logger.Errf("Accept: %v", err)
			continue
		}
		go handleClient(c, s3c)
	}
	return nil
}

func main() {
	flag.Parse()

	var err error

	if os.Getenv("POTATOFS_BACKEND_CONFIG") == "" {
		die(2, "POTATOFS_BACKEND_CONFIG is not set")
	}

	config, err = NewConfig(os.Getenv("POTATOFS_BACKEND_CONFIG"))
	if err != nil {
		die(2, "%v", err)
	}

	logger, err = NewSysLoggy(syslog.LOG_NOTICE|syslog.LOG_USER, program)
	if err != nil {
		die(2, "could not initialize logger: %v\n", err)
	}

	if *server {
		if err := serve(); err != nil {
			logger.Errf("%v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	var c net.Conn
	for i := 0; i < 300; i++ {
		c, err = net.DialTimeout("unix", config.SocketPath, 10*time.Second)
		if err == nil {
			break
		}

		if i == 0 {
			cmd := exec.Command(os.Args[0], "-server")
			if err = cmd.Start(); err != nil {
				die(2, "failed to start S3 backend: %v\n", err)
			}
		}

		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		die(2, "%v", err)
	}

	var msg MgrMsg
	msg.Command = flag.Arg(0)

	dec := json.NewDecoder(os.Stdin)
	var reply interface{}
	switch msg.Command {
	case "df":
		reply = MgrMsgDfResponse{}
	case "get":
		reply = MgrMsgGetResponse{}
		if err := dec.Decode(&msg.Args); err != nil {
			die(2, "invalid JSON passed to %q: %v", msg.Command, err)
		}
	case "put":
		reply = MgrMsgPutResponse{}
		if err := dec.Decode(&msg.Args); err != nil {
			die(2, "invalid JSON passed to %q: %v", msg.Command, err)
		}
	default:
		die(2, "unknown command %q", msg.Command)
	}

	enc := json.NewEncoder(c)
	if err := enc.Encode(msg); err != nil {
		die(2, "failed to encode JSON for command %q: %v", msg.Command, err)
	}

	dec = json.NewDecoder(c)
	if err := dec.Decode(&reply); err != nil {
		reply = MgrMsgErrResponse{}
		if err := dec.Decode(&reply); err != nil {
			die(2, "Decode: %v", err)
		}
	}

	enc = json.NewEncoder(os.Stdout)
	if err := enc.Encode(reply); err != nil {
		die(2, "failed to encode JSON for command %q: %v", msg.Command, err)
	}
}
