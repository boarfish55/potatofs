// Copyright (C) 2020-2023 Pascal Lalonde <plalonde@overnet.ca>
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
	"container/heap"
	"context"
	"database/sql"
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
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	_ "github.com/mattn/go-sqlite3"
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
	LogLevel              string `toml:"log_level"`
	IdleTimeoutSeconds    int64  `toml:"idle_timeout_seconds"`
	S3Endpoint            string `toml:"s3_endpoint"`
	S3Bucket              string `toml:"s3_bucket"`
	S3Region              string `toml:"s3_region"`
	AccessKeyID           string `toml:"access_key_id"`
	SecretAccessKey       string `toml:"secret_access_key"`
	SocketPath            string `toml:"socket_path"`
	BackendBytes          uint64 `toml:"backend_bytes"`
	BackendTimeoutSeconds int64  `toml:"backend_timeout_seconds"`
	BackendSecretKeyPath  string `toml:"backend_secret_key_path"`
	BackendClaimCommand   string `toml:"backend_claim_command"`
	HintsDBPath           string `toml:"hints_database_path"`
	HintSkewMs            int64  `toml:"hint_skew_ms"`
	HintsPreloadQueueSize int    `toml:"hints_preload_queue_size"`
}

func loadConfig(path string) error {
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return fmt.Errorf("error decoding configuration: %v", err)
	}
	if config.HintsPreloadQueueSize < 10 {
		config.HintsPreloadQueueSize = 10
	}
	if config.HintsPreloadQueueSize > 1000000 {
		config.HintsPreloadQueueSize = 1000000
	}
	return nil
}

var config Config
var logger *Loggy
var secretKey [32]byte
var hintsDB *HintsDB

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

type Slab struct {
	Ino      uint64
	Base     int64
	LoadedAt time.Time
}

type SlabQueue []Slab

func (q SlabQueue) Len() int {
	return len(q)
}

func (q SlabQueue) Less(i, j int) bool {
	return q[i].LoadedAt.Before(q[j].LoadedAt)
}

func (q SlabQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
}

func (q *SlabQueue) Push(x interface{}) {
	*q = append(*q, x.(Slab))
}

func (q *SlabQueue) Pop() interface{} {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

func (q *SlabQueue) Peek() interface{} {
	h := *q
	return h[0]
}

type HintsDB struct {
	Db           *sql.DB
	LastOpenSlab Slab
	Mtx          sync.Mutex
	PreloadQueue SlabQueue
	QMtx         sync.Mutex
}

func OpenHintsDB(stop <-chan bool, wg *sync.WaitGroup) (*HintsDB, error) {
	db, err := sql.Open("sqlite3", config.HintsDBPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec("pragma foreign_keys = on")
	if err != nil {
		return nil, err
	}

	s := `
	create table if not exists slabs(
	ino int not null,
	base int not null,
	primary key(ino, base))
	`

	_, err = db.Exec(s)
	if err != nil {
		return nil, err
	}

	s = `
	create table if not exists hints(
	parent_ino int not null,
	parent_base int not null,
	ino int not null,
	base int not null,
	last_used_ms int not null,
	load_after_ms int not null,
	foreign key(parent_ino, parent_base) references slabs(ino, base)
	on delete cascade)
	`

	_, err = db.Exec(s)
	if err != nil {
		return nil, err
	}

	s = `create unique index if not exists hints_ino_base
	on hints(parent_ino, parent_base, ino, base)
	`

	_, err = db.Exec(s)
	if err != nil {
		return nil, err
	}

	h := &HintsDB{
		Db: db,
	}

	heap.Init(&h.PreloadQueue)
	wg.Add(1)
	go h.ProcessPreloadQueue(stop, wg)

	return h, nil
}

func DoClaim(ino uint64, base int64) {
	if config.BackendClaimCommand == "" {
		return
	}

	inoStr := strconv.FormatUint(ino, 10)
	baseStr := strconv.FormatInt(base, 10)
	cmd := strings.ReplaceAll(config.BackendClaimCommand, "%inode%", inoStr)
	cmd = strings.ReplaceAll(cmd, "%base%", baseStr)
	logger.Debugf("DoClaim: %s", cmd)
	cmdParts := strings.Fields(cmd)
	args := cmdParts[1:]
	e := exec.Command(cmdParts[0], args...)
	if err := e.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Don't print an error if the exit code is 2, that is,
			// the claim command couldn't get a lock on the slab,
			// meaning it's already local.
			if exitErr.ExitCode() == 2 {
				logger.Errf("DoClaim: already locked")
			} else {
				logger.Errf("DoClaim: %v", err)
			}
		} else {
			logger.Errf("DoClaim: %v", err)
		}
	}
}

func (h *HintsDB) ClaimProcessor(claims <-chan Slab, wg *sync.WaitGroup) {
	defer wg.Done()

	for slab := range claims {
		logger.Infof("preloading: ino=%d/base=%d", slab.Ino, slab.Base)
		DoClaim(slab.Ino, slab.Base)
	}
}

func (h *HintsDB) ProcessPreloadQueue(stop <-chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	// There is no use in having too many workers here. At some point
	// we would hit a ulimit on open files and we want to be nice to
	// the filesystem and leave workers free for actual FS tasks.
	claims := make(chan Slab, config.HintsPreloadQueueSize)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go h.ClaimProcessor(claims, wg)
	}

	for {
		select {
		case <-stop:
			logger.Info("ProcessPreloadQueue: stop received")
			close(claims)
			return
		case <-ticker.C:
			now := time.Now()
			h.QMtx.Lock()
			for h.PreloadQueue.Len() > 0 {
				slab := h.PreloadQueue.Peek().(Slab)
				if now.After(slab.LoadedAt) {
					claims <- heap.Pop(&h.PreloadQueue).(Slab)
				} else {
					break
				}
			}
			h.QMtx.Unlock()
		}
	}
}

func Rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil {
		logger.Errf("Rollback: %v", err)
	}
}

func minZero(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Duration(0)
	}
	return d
}

func (h *HintsDB) AddHint(ino uint64, base int64) error {
	h.Mtx.Lock()
	now := time.Now()
	var emptySlab Slab
	if h.LastOpenSlab == emptySlab {
		h.LastOpenSlab.Ino = ino
		h.LastOpenSlab.Base = base
		h.LastOpenSlab.LoadedAt = now
		h.Mtx.Unlock()
		return nil
	}
	lastSlab := h.LastOpenSlab
	h.LastOpenSlab.Ino = ino
	h.LastOpenSlab.Base = base
	h.LastOpenSlab.LoadedAt = now
	h.Mtx.Unlock()

	tx, err := h.Db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(
		"insert or ignore into slabs(ino, base) values(?, ?)")
	if err != nil {
		Rollback(tx)
		return err
	}
	defer stmt.Close()
	stmt.Exec(lastSlab.Ino, lastSlab.Base)
	if err != nil {
		Rollback(tx)
		return err
	}

	s := `
	select load_after_ms from hints where
	parent_ino = ? and parent_base = ? and ino = ? and base = ?
	`
	stmt, err = tx.Prepare(s)
	if err != nil {
		Rollback(tx)
		return err
	}
	defer stmt.Close()

	var loadAfterMs int64
	var lastUsedMs int64
	lastUsedMs = now.UnixNano() / 1000000

	err = stmt.QueryRow(lastSlab.Ino, lastSlab.Base, ino, base).Scan(&loadAfterMs)
	if err != nil {
		if err == sql.ErrNoRows {
			s = `
			insert into hints(parent_ino, parent_base,
			ino, base, last_used_ms, load_after_ms) values(?, ?, ?, ?, ?, ?)
			`
			stmt, err = tx.Prepare(s)
			if err != nil {
				Rollback(tx)
				return err
			}
			defer stmt.Close()
			_, err = stmt.Exec(lastSlab.Ino, lastSlab.Base, ino, base, lastUsedMs, now.Sub(lastSlab.LoadedAt).Milliseconds())
			if err != nil {
				Rollback(tx)
				return err
			}

			tx.Commit()
			if err != nil {
				Rollback(tx)
				return err
			}
			return nil
		} else {
			Rollback(tx)
			return err
		}
	}

	after := now.Sub(lastSlab.LoadedAt).Milliseconds()
	if after < loadAfterMs {
		loadAfterMs = after
	}

	s = `
	update hints set last_used_ms = ?, load_after_ms = ? where
	parent_ino = ? and parent_base = ? and ino = ? and base = ?
	`

	stmt, err = tx.Prepare(s)
	if err != nil {
		Rollback(tx)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(lastUsedMs, loadAfterMs, lastSlab.Ino, lastSlab.Base, ino, base)
	if err != nil {
		Rollback(tx)
		return err
	}

	tx.Commit()
	if err != nil {
		Rollback(tx)
		return err
	}

	return nil
}

func (h *HintsDB) PreloadSlabs(ino uint64, base int64) error {
	tx, err := h.Db.Begin()
	if err != nil {
		return err
	}

	s := `
	select ino, base, last_used_ms, load_after_ms from hints where
	parent_ino = ? and parent_base = ? order by last_used_ms desc
	`

	stmt, err := tx.Prepare(s)
	if err != nil {
		Rollback(tx)
		return err
	}
	defer stmt.Close()

	rows, err := stmt.Query(ino, base)
	if err != nil {
		Rollback(tx)
		return err
	}
	defer rows.Close()

	n := 0
	var deleteOlderThanEq int64
	for rows.Next() {
		var childIno uint64
		var childBase int64
		var loadAfterMs int64
		var lastUsedMs int64
		err = rows.Scan(&childIno, &childBase, &lastUsedMs, &loadAfterMs)
		if err != nil {
			Rollback(tx)
			return err
		}

		n++
		if n > 10 {
			deleteOlderThanEq = lastUsedMs
			break
		}

		skew := time.Duration(config.HintSkewMs) * time.Millisecond
		slab := Slab{
			Ino:      childIno,
			Base:     childBase,
			LoadedAt: time.Now().Add(minZero((time.Duration(loadAfterMs) * time.Millisecond) - skew)),
		}

		queued := false
		var length int
		h.QMtx.Lock()
		// Cap memory usage by preventing too many insertions in the
		// heap.
		length = h.PreloadQueue.Len()
		if length < config.HintsPreloadQueueSize {
			heap.Push(&h.PreloadQueue, slab)
			queued = true
		}
		h.QMtx.Unlock()
		if queued {
			logger.Infof("queued preload: inode=%d/base=%d at %v (in %.3fs)", slab.Ino, slab.Base, slab.LoadedAt.Format("2006-01-02T15:04:05 -0700"), minZero((time.Duration(loadAfterMs)*time.Millisecond)-skew).Seconds())
		} else {
			logger.Infof("queue full at %d/%d elements; could not preload: inode=%d/base=%d", length, config.HintsPreloadQueueSize, slab.Ino, slab.Base)
		}
	}
	err = rows.Err()
	if err != nil {
		Rollback(tx)
		return err
	}

	if n > 10 {
		s = `
		delete from hints where parent_ino = ? and parent_base = ? and
		last_used_ms <= ?
		`

		stmt, err := tx.Prepare(s)
		if err != nil {
			Rollback(tx)
			return err
		}
		defer stmt.Close()

		_, err = stmt.Exec(ino, base, deleteOlderThanEq)
		if err != nil {
			Rollback(tx)
			return err
		}

		tx.Commit()
		if err != nil {
			Rollback(tx)
			return err
		}
		return nil
	}
	Rollback(tx)
	return nil
}

func handleClient(c net.Conn, s3c *s3.S3, wg *sync.WaitGroup) {
	defer wg.Done()
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

		if err := hintsDB.AddHint(msg.Args.Inode, msg.Args.Base); err != nil {
			logger.Errf("handleClient: AddHint(ino=%d, base=%d): %v", msg.Args.Inode, msg.Args.Base, err)
		}

		if err := hintsDB.PreloadSlabs(msg.Args.Inode, msg.Args.Base); err != nil {
			logger.Errf("handleClient: AddHint(ino=%d, base=%d): %v", msg.Args.Inode, msg.Args.Base, err)
		}

		resp = MgrMsgHintResponse{
			Status: "OK",
		}
	case "get":
		if err := hintsDB.AddHint(msg.Args.Inode, msg.Args.Base); err != nil {
			logger.Errf("handleClient: AddHint(ino=%d, base=%d): %v", msg.Args.Inode, msg.Args.Base, err)
		}

		if err := hintsDB.PreloadSlabs(msg.Args.Inode, msg.Args.Base); err != nil {
			logger.Errf("handleClient: AddHint(ino=%d, base=%d): %v", msg.Args.Inode, msg.Args.Base, err)
		}

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
	var wg sync.WaitGroup

	// We don't want this process to be killed early in the system
	// shutdown sequence
	signal.Ignore(syscall.SIGTERM)

	laddr, err := net.ResolveUnixAddr("unix", config.SocketPath)
	if err != nil {
		return fmt.Errorf("net.ResolveUnixAddr: %v", err)
	}

	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return fmt.Errorf("net.UnixListener: %v", err)
	}

	if err = loadSecretKey(); err != nil {
		l.Close()
		return err
	}

	sess, err := session.NewSession(&aws.Config{
		Endpoint:    aws.String(config.S3Endpoint),
		Region:      aws.String(config.S3Region),
		Credentials: credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, ""),
	})
	if err != nil {
		l.Close()
		return err
	}

	stop := make(chan bool)
	hintsDB, err = OpenHintsDB(stop, &wg)
	if err != nil {
		l.Close()
		return err
	}

	s3c := s3.New(sess)
	for {
		l.SetDeadline(time.Now().Add(time.Duration(config.IdleTimeoutSeconds) * time.Second))
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				l.Close()
				break
			}
			logger.Errf("Accept: %v", err)
			continue
		}
		wg.Add(1)
		go handleClient(c, s3c, &wg)
	}
	stop <- true
	wg.Wait()
	return nil
}

func parseLogLevel(logLevel string) syslog.Priority {
	switch logLevel {
	case "debug":
		return syslog.LOG_DEBUG
	case "info":
		return syslog.LOG_INFO
	case "notice":
		return syslog.LOG_NOTICE
	case "warning":
		return syslog.LOG_WARNING
	case "error":
		return syslog.LOG_ERR
	case "crit":
		return syslog.LOG_CRIT
	case "alert":
		return syslog.LOG_ALERT
	case "emerg":
		return syslog.LOG_EMERG
	default:
		return syslog.LOG_INFO
	}
}

func main() {
	flag.Parse()

	var err error

	if os.Getenv("POTATOFS_BACKEND_CONFIG") == "" {
		die(2, "POTATOFS_BACKEND_CONFIG is not set")
	}

	if err = loadConfig(os.Getenv("POTATOFS_BACKEND_CONFIG")); err != nil {
		die(2, "%v", err)
	}

	logger, err = NewSysLoggy(syslog.LOG_USER, parseLogLevel(config.LogLevel), program)
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

		// If the error is ECONNREFUSED, it's likely the server died
		// and the unix socket file was left behind. In this case we
		// can just remove that file and try again.
		if opErr, ok := err.(*net.OpError); ok {
			if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
				os.Remove(config.SocketPath)
			}
		}

		if i == 0 {
			cmd := exec.Command(os.Args[0], "-server")
			if err = cmd.Start(); err != nil {
				logger.Errf("failed to start S3 backend: %v", err)
				die(2, "failed to start S3 backend: %v\n", err)
			}
		}

		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		logger.Errf("%v", err)
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
		logger.Errf("unknown command %q", msg.Command)
		die(2, "unknown command %q", msg.Command)
	}

	enc := json.NewEncoder(c)
	if err := enc.Encode(msg); err != nil {
		logger.Errf("failed to encode JSON for command %q: %v", msg.Command, err)
		die(2, "failed to encode JSON for command %q: %v", msg.Command, err)
	}

	dec = json.NewDecoder(c)
	if err := dec.Decode(&reply); err != nil {
		reply = MgrMsgErrResponse{}
		if err := dec.Decode(&reply); err != nil {
			logger.Errf("Decode: %v", err)
			die(2, "Decode: %v", err)
		}
	}

	enc = json.NewEncoder(os.Stdout)
	if err := enc.Encode(reply); err != nil {
		logger.Errf("failed to encode JSON for command %q: %v", msg.Command, err)
		die(2, "failed to encode JSON for command %q: %v", msg.Command, err)
	}
}
