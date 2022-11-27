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
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	program = "backend_s3"
)

var (
	server        = flag.Bool("server", false, "Starts a S3 backend service")
	decrypt       = flag.Bool("decrypt", false, "Decrypt STDIN")
	encrypt       = flag.Bool("encrypt", false, "Encrypt STDIN")
	encrypt_inode = flag.Uint64("encrypt_inode", 0, "Inode for encrypt nonce")
	encrypt_base  = flag.Int64("encrypt_base", 0, "Base for encrypt nonce")
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
	BackendSecretKeyPath  string `toml:"backend_secret_key_path"`
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
var secretKey [32]byte

// S3 gives us a io.ReadCloser on a GET operation.
func NewGetStream(f io.ReadCloser) (io.Reader, error) {
	var nonce [24]byte
	n, err := f.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	if n < len(nonce) {
		return nil, fmt.Errorf("slab is shorter than nonce length of %d bytes", len(nonce))
	}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	data, ok := secretbox.Open(nil, b, &nonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	var buf bytes.Buffer
	if _, err := buf.Write(data); err != nil {
		return nil, err
	}

	zr, err := zlib.NewReader(&buf)
	if err != nil {
		return nil, err
	}
	return zr, nil
}

// Because S3 wants a io.ReadSeeker object in PUT operations, we need
// to implement Seek(). However this means we have to load the entire slab
// in memory then encrypt it before letting our S3 client read it if we
// wish to use CBC mode.
type PutStream struct {
	buf    []byte
	offset int64
}

func NewPutStream(f *os.File, inode uint64, base int64) (*PutStream, error) {
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	io.Copy(zw, f)
	zw.Close()

	var nonce [24]byte
	binary.LittleEndian.PutUint64(nonce[0:], inode)
	binary.LittleEndian.PutUint64(nonce[8:], uint64(base))
	binary.LittleEndian.PutUint64(nonce[16:], uint64(time.Now().UnixNano()))

	return &PutStream{
		buf: secretbox.Seal(nonce[:], b.Bytes(), &nonce, &secretKey),
	}, nil
}

func (ps *PutStream) Size() int64 {
	return int64(len(ps.buf))
}

func (ps *PutStream) Seek(offset int64, whence int) (n int64, err error) {
	switch whence {
	case io.SeekStart:
		if offset < 0 {
			return 0, fmt.Errorf("Seek: cannot seek before the start of the buffer")
		}
		if offset > int64(len(ps.buf)) {
			return 0, fmt.Errorf("Seek: cannot seek beyond the end of the buffer")
		}
		ps.offset = offset
	case io.SeekCurrent:
		if ps.offset+offset > int64(len(ps.buf)) {
			return 0, fmt.Errorf("Seek: cannot seek beyond the end of the buffer")
		}
		if ps.offset+offset < 0 {
			return 0, fmt.Errorf("Seek: cannot seek before the start of the buffer")
		}
		ps.offset += offset
	case io.SeekEnd:
		if offset > 0 {
			return 0, fmt.Errorf("Seek: cannot seek beyond the end of the buffer")
		}
		if int64(len(ps.buf))+offset < 0 {
			return 0, fmt.Errorf("Seek: cannot seek before the start of the buffer")
		}
		ps.offset = int64(len(ps.buf)) + offset
	default:
		return 0, fmt.Errorf("Seek: whence is invalid")
	}
	return ps.offset, nil
}

func (ps *PutStream) Read(p []byte) (n int, err error) {
	n = copy(p, ps.buf[ps.offset:])
	ps.offset += int64(n)
	if ps.offset == int64(len(ps.buf)) {
		return n, io.EOF
	}
	return n, nil
}

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

type MgrMsgHintResponse struct {
	Status string `json:"status"`
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

func sendErrResponse(c net.Conn, status string, format string, v ...interface{}) {
	enc := json.NewEncoder(c)
	resp := &MgrMsgErrResponse{
		Status: status,
		Msg:    fmt.Sprintf(format, v...),
	}
	logger.Errf(resp.Msg)
	if err := enc.Encode(resp); err != nil {
		logger.Errf("sendErrResponse: %v", err)
	}
}

func handleClient(c net.Conn, s3c *s3.S3) {
	start := time.Now()
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
				ContinuationToken: ctoken,
			})
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
					sendErrResponse(c, "ERR", "df canceled: %v", err)
				} else {
					sendErrResponse(c, "ERR", "df failed: %v", err)
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
	case "hint":
		logger.Infof("slab hint: inode=%d/base=%d", msg.Args.Inode, msg.Args.Base)
		resp = MgrMsgHintResponse{
			Status: "OK",
		}
	case "get":
		f, err := os.OpenFile(msg.Args.LocalPath, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			sendErrResponse(c, "ERR", "failed to open file: %q, %v", msg.Args.LocalPath, err)
			return
		}
		defer f.Close()

		out, err := s3c.GetObjectWithContext(ctx, &s3.GetObjectInput{
			Bucket: aws.String(config.S3Bucket),
			Key:    aws.String(msg.Args.BackendName),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
				sendErrResponse(c, "ERR", "download canceled for %q: %v", msg.Args.LocalPath, err)
			} else if reqErr, ok := err.(awserr.RequestFailure); ok && reqErr.StatusCode() == 404 {
				sendErrResponse(c, "ERR_NOSLAB", "download failed for %q: %v", msg.Args.LocalPath, err)
			} else {
				sendErrResponse(c, "ERR", "download failed for %q: %v", msg.Args.LocalPath, err)
			}
			return
		}

		gs, err := NewGetStream(out.Body)
		if err != nil {
			sendErrResponse(c, "ERR", "NewGetStream: %v", err)
			return
		}

		if _, err := io.Copy(f, gs); err != nil {
			sendErrResponse(c, "ERR", "io.Copy: %v", err)
			return
		}

		resp = MgrMsgGetResponse{
			Status:  "OK",
			InBytes: *out.ContentLength,
		}
	case "put":
		f, err := os.Open(msg.Args.LocalPath)
		if err != nil {
			sendErrResponse(c, "ERR", "failed to open file: %q, %v", msg.Args.LocalPath, err)
			return
		}
		defer f.Close()

		ps, err := NewPutStream(f, msg.Args.Inode, msg.Args.Base)
		if err != nil {
			sendErrResponse(c, "ERR", "NewPutStream: %v", err)
			return
		}

		_, err = s3c.PutObjectWithContext(ctx, &s3.PutObjectInput{
			Bucket: aws.String(config.S3Bucket),
			Key:    aws.String(msg.Args.BackendName),
			Body:   ps,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
				sendErrResponse(c, "ERR", "upload canceled for %q: %v", msg.Args.LocalPath, err)
			} else {
				sendErrResponse(c, "ERR", "upload failed for %q: %v", msg.Args.LocalPath, err)
			}
			return
		}
		resp = MgrMsgPutResponse{
			Status:   "OK",
			OutBytes: ps.Size(),
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
	elapsed := time.Now().Sub(start)
	logger.Infof("%s completed in %.6f seconds", msg.Command, elapsed.Seconds())
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

func loadSecretKey() error {
	secretKeyBytes, err := ioutil.ReadFile(config.BackendSecretKeyPath)
	if err != nil {
		return fmt.Errorf("failed to open secret key file: %v", err)
	}
	if len(secretKeyBytes) < 32 {
		return fmt.Errorf("backend secret key is too short; must be 32 bytes at minimum")
	}
	copy(secretKey[:], secretKeyBytes)
	return nil
}

func serve() error {
	laddr, err := net.ResolveUnixAddr("unix", config.SocketPath)
	if err != nil {
		return fmt.Errorf("net.ResolveUnixAddr: %v", err)
	}

	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return fmt.Errorf("net.UnixListener: %v", err)
	}
	defer l.Close()

	if err = loadSecretKey(); err != nil {
		return err
	}

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

	if *encrypt {
		if err = loadSecretKey(); err != nil {
			die(2, "%v", err)
		}
		s, err := NewPutStream(os.Stdin, *encrypt_inode, *encrypt_base)
		if err != nil {
			die(2, "%v", err)
		}
		_, err = io.Copy(os.Stdout, s)
		if err != nil {
			die(2, "%v", err)
		}
		os.Exit(0)
	}
	if *decrypt {
		if err = loadSecretKey(); err != nil {
			die(2, "%v", err)
		}
		s, err := NewGetStream(os.Stdin)
		if err != nil {
			die(2, "%v", err)
		}
		_, err = io.Copy(os.Stdout, s)
		if err != nil {
			die(2, "%v", err)
		}
		os.Exit(0)
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
	case "hint":
		reply = MgrMsgHintResponse{}
		if err := dec.Decode(&msg.Args); err != nil {
			die(2, "invalid JSON passed to %q: %v", msg.Command, err)
		}
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
