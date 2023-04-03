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
	confPath     = flag.String("config", "", "Configuration file path")
	server       = flag.Bool("server", false, "Starts a S3 backend service")
	decrypt      = flag.Bool("decrypt", false, "Decrypt STDIN")
	encrypt      = flag.Bool("encrypt", false, "Encrypt STDIN")
	encryptInode = flag.Uint64("encrypt_inode", 0, "Inode for encrypt nonce")
	encryptBase  = flag.Int64("encrypt_base", 0, "Base for encrypt nonce")
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
	MaxPreloadPerHint     int64  `toml:"max_preload_per_hint"`
	HintSlabMaxAgeSeconds int64  `toml:"hint_slab_max_age_seconds"`
	HintSlabsMaxOpen      int    `toml:"hint_slabs_max_open"`
}

func loadConfig(path string) error {
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return fmt.Errorf("error decoding configuration: %v", err)
	}
	if config.HintsPreloadQueueSize < 1 {
		config.HintsPreloadQueueSize = 10
	}
	if config.HintsPreloadQueueSize > 1000000 {
		config.HintsPreloadQueueSize = 1000000
	}
	if config.MaxPreloadPerHint < 1 {
		config.MaxPreloadPerHint = 10
	}
	if config.HintSlabMaxAgeSeconds < 1 {
		config.HintSlabMaxAgeSeconds = 300
	}
	if config.HintSlabsMaxOpen < 1 {
		config.HintSlabsMaxOpen = 50
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
	IsPreload   bool   `json:"is_preload"`
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

type HintsDB struct {
	Db           *sql.DB
	OpenSlabs    SlabQueue
	HitTracker   *SlabHitTracker
	PreloadQueue SlabQueue
	TokenBucket  chan struct{}
}

func OpenHintsDB(stop <-chan bool, wg *sync.WaitGroup) (*HintsDB, error) {
	dsn := fmt.Sprintf("file:%s?_busy_timeout=10000&_fk=on", config.HintsDBPath)
	db, err := sql.Open("sqlite3", dsn)
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
	hits int not null default 2,
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

	s = `create index if not exists hints_by_hits
	on hints(parent_ino, parent_base, hits)
	`
	_, err = db.Exec(s)
	if err != nil {
		return nil, err
	}

	h := &HintsDB{
		Db: db,
	}

	// We don't want to fill our hints for a given parent inode/base
	// with a bunch of slabs that are loaded in a burst.
	h.TokenBucket = make(chan struct{}, config.MaxPreloadPerHint/2)
	sleepInterval := time.Duration(config.HintSlabMaxAgeSeconds/(config.MaxPreloadPerHint/2)) * time.Second
	if sleepInterval < 1*time.Second {
		sleepInterval = 1 * time.Second
	}
	go func() {
		for {
			time.Sleep(sleepInterval)
			select {
			case <-h.TokenBucket:
			default:
			}
		}
	}()

	h.OpenSlabs = NewSlabQueue()
	h.PreloadQueue = NewSlabQueue()
	wg.Add(1)
	h.HitTracker = NewSlabHitTracker(stop, wg, h.incrementHintHits, h.decrementHintHits)

	wg.Add(1)
	go h.ProcessPreloadQueue(stop, wg)

	return h, nil
}

func (h *HintsDB) DoClaim(slab *SlabHint) {
	if config.BackendClaimCommand == "" {
		return
	}

	inoStr := strconv.FormatUint(slab.Ino, 10)
	baseStr := strconv.FormatInt(slab.Base, 10)
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
				h.PreloadQueue.Empty()
			}
		} else {
			logger.Errf("DoClaim: %v", err)
			h.PreloadQueue.Empty()
		}
	}
}

func (h *HintsDB) ClaimProcessor(claims <-chan SlabHint, wg *sync.WaitGroup) {
	defer wg.Done()

	for slab := range claims {
		logger.Infof("preloading: ino=%d/base=%d", slab.Ino, slab.Base)
		h.DoClaim(&slab)
	}
}

func (h *HintsDB) decrementHintHits(parentIno uint64, parentBase int64, ino uint64, base int64) {
	s := `
	update hints set hits = (hits - 1) where
	parent_ino = ? and parent_base = ? and
	ino = ? and base = ? and hits > 0
	`
	stmt, err := h.Db.Prepare(s)
	if err != nil {
		logger.Errf("decrementHintHits: %v", err)
		return
	}
	defer stmt.Close()
	stmt.Exec(parentIno, parentBase, ino, base)
	if err != nil {
		logger.Errf("decrementHintHits: %v", err)
		return
	}
}

func (h *HintsDB) incrementHintHits(parentIno uint64, parentBase int64, ino uint64, base int64) {
	s := `
	update hints set hits = (hits + 1) where
	parent_ino = ? and parent_base = ? and
	ino = ? and base = ? and hits < 3
	`
	stmt, err := h.Db.Prepare(s)
	if err != nil {
		logger.Errf("incrementHintHits: %v", err)
		return
	}
	defer stmt.Close()
	stmt.Exec(parentIno, parentBase, ino, base)
	if err != nil {
		logger.Errf("incrementHintHits: %v", err)
	}
}

func (h *HintsDB) ProcessPreloadQueue(stop <-chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	// There is no use in having too many workers here. At some point
	// we would hit a ulimit on open files and we want to be nice to
	// the filesystem and leave workers free for actual FS tasks.
	claims := make(chan SlabHint, config.HintsPreloadQueueSize)
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
			h.PreloadQueue.Purge(claims)
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

func (h *HintsDB) AddOpenSlab(ino uint64, base int64) error {
	now := time.Now()

	h.OpenSlabs.Mtx.Lock()
	defer h.OpenSlabs.Mtx.Unlock()

	// Clear slabs that have been open for longer then the max age
	for h.OpenSlabs.Len() > 0 {
		slab := h.OpenSlabs.Peek().(*SlabHint)
		if now.Sub(slab.LoadedAt) > (time.Duration(config.HintSlabMaxAgeSeconds) * time.Second) {
			heap.Pop(&h.OpenSlabs)
		} else {
			break
		}
	}

	// Limit how many open slabs we can have at a time. Each new hint has
	// to loop through all of them, so we want to keep that under control.
	if h.OpenSlabs.Len() >= config.HintSlabsMaxOpen {
		logger.Noticef("AddOpenSlab: reached hint_slabs_max_open (%d); not tracking new slabs", config.HintSlabsMaxOpen)
		return nil
	}

	slab := h.OpenSlabs.Lookup(ino, base)
	if slab == nil {
		// If the slab is already in memory, for sure it's already
		// in the DB.
		stmt, err := h.Db.Prepare(
			"insert or ignore into slabs(ino, base) values(?, ?)")
		if err != nil {
			return err
		}
		defer stmt.Close()
		stmt.Exec(ino, base)
		if err != nil {
			return err
		}

		slab = &SlabHint{
			Ino:      ino,
			Base:     base,
			LoadedAt: now,
		}
	}

	heap.Push(&h.OpenSlabs, slab)

	return nil
}

func (h *HintsDB) AddHint(ino uint64, base int64) error {
	now := time.Now()
	defer func() {
		elapsed := time.Now().Sub(now)
		logger.Infof("AddHint: completed in %.6f seconds", elapsed.Seconds())
	}()

	h.AddOpenSlab(ino, base)

	select {
	case h.TokenBucket <- struct{}{}:
	default:
		logger.Noticef("AddHint: token bucket full at %d", len(h.TokenBucket))
		return nil
	}
	logger.Infof("AddHint: token bucket at %d", len(h.TokenBucket))

	// Get a copy of the list of loaded slabs to avoid holding the lock
	h.OpenSlabs.Mtx.Lock()
	openSlabs := h.OpenSlabs.AllSlabs()
	h.OpenSlabs.Mtx.Unlock()
	logger.Infof("%d open slabs", len(openSlabs))

	for _, slab := range openSlabs {
		if slab.Ino == ino && slab.Base == base {
			// No preloading needed for itself
			continue
		}
		tx, err := h.Db.Begin()
		if err != nil {
			return err
		}

		s := `
		select load_after_ms from hints where
		parent_ino = ? and parent_base = ? and ino = ? and base = ?
		`
		stmt, err := tx.Prepare(s)
		if err != nil {
			Rollback(tx)
			return err
		}
		defer stmt.Close()

		var loadAfterMs int64

		err = stmt.QueryRow(slab.Ino, slab.Base, ino, base).Scan(&loadAfterMs)
		if err != nil {
			if err == sql.ErrNoRows {
				s = `
				insert into hints(parent_ino, parent_base,
				ino, base, load_after_ms)
				values(?, ?, ?, ?, ?)
				`
				stmt, err = tx.Prepare(s)
				if err != nil {
					Rollback(tx)
					return err
				}
				defer stmt.Close()
				_, err = stmt.Exec(slab.Ino, slab.Base, ino, base, now.Sub(slab.LoadedAt).Milliseconds())
				if err != nil {
					Rollback(tx)
					return err
				}

				if err := tx.Commit(); err != nil {
					Rollback(tx)
					logger.Errf("AddHint: inserting new hint: %v")
				}
			} else {
				Rollback(tx)
				logger.Errf("AddHint: %v")
			}
			continue
		}

		after := now.Sub(slab.LoadedAt).Milliseconds()
		if after < loadAfterMs {
			loadAfterMs = after
		}

		s = `
		update hints set load_after_ms = ? where
		parent_ino = ? and parent_base = ? and ino = ? and base = ?
		`

		stmt, err = tx.Prepare(s)
		if err != nil {
			Rollback(tx)
			return err
		}
		defer stmt.Close()
		_, err = stmt.Exec(loadAfterMs, slab.Ino, slab.Base, ino, base)
		if err != nil {
			Rollback(tx)
			return err
		}

		if err := tx.Commit(); err != nil {
			Rollback(tx)
			return err
		}
	}

	return nil
}

func (h *HintsDB) PreloadSlabs(ino uint64, base int64) error {
	var preloads []*SlabHint
	tx, err := h.Db.Begin()
	if err != nil {
		return err
	}

	s := `
	select ino, base, hits, load_after_ms from hints where
	parent_ino = ? and parent_base = ? and hits > 0 order by hits desc
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

	var n int64
	for rows.Next() {
		var childIno uint64
		var childBase int64
		var loadAfterMs int64
		var hits int64
		err = rows.Scan(&childIno, &childBase, &hits, &loadAfterMs)
		if err != nil {
			Rollback(tx)
			return err
		}

		n++
		// We want to keep a limit over how many slabs to preload for each
		// hint, both to keep the DB size under control, but also because
		// preloading is exponential by that factor.
		if n > config.MaxPreloadPerHint {
			// We continue to keep counting how many we actually have
			continue
		}

		skew := time.Duration(config.HintSkewMs) * time.Millisecond
		preloads = append(preloads, &SlabHint{
			Ino:      childIno,
			Base:     childBase,
			LoadedAt: time.Now().Add(minZero((time.Duration(loadAfterMs) * time.Millisecond) - skew)),
		})

	}
	err = rows.Err()
	if err != nil {
		Rollback(tx)
		return err
	}

	if n > config.MaxPreloadPerHint {
		s = `
		delete from hints where parent_ino = ? and parent_base = ?
		order by hits asc limit ?
		`

		stmt, err := tx.Prepare(s)
		if err != nil {
			Rollback(tx)
			return err
		}
		defer stmt.Close()

		logger.Infof("deleting hints for inode=%d/base=%d (max hints is %d)", ino, base, config.MaxPreloadPerHint)
		_, err = stmt.Exec(ino, base, n-config.MaxPreloadPerHint)
		if err != nil {
			Rollback(tx)
			return err
		}

		if err := tx.Commit(); err != nil {
			Rollback(tx)
			return err
		}
		return nil
	}
	Rollback(tx)

	for _, slab := range preloads {
		queued := false
		var length int
		h.PreloadQueue.Mtx.Lock()
		// Cap memory usage by preventing too many insertions in the
		// heap.
		length = h.PreloadQueue.Len()
		if length < config.HintsPreloadQueueSize {
			heap.Push(&h.PreloadQueue, slab)
			queued = true
			h.HitTracker.Add(ino, base, slab.Ino, slab.Base, slab.LoadedAt.Add(time.Duration(config.HintSlabMaxAgeSeconds)*time.Second))
		}
		h.PreloadQueue.Mtx.Unlock()
		if queued {
			logger.Infof("queued preload: inode=%d/base=%d at %v (in %.3fs)", slab.Ino, slab.Base, slab.LoadedAt.Format("2006-01-02T15:04:05 -0700"), minZero(slab.LoadedAt.Sub(time.Now())).Seconds())
		} else {
			logger.Infof("queue full at %d/%d elements; could not preload: inode=%d/base=%d", length, config.HintsPreloadQueueSize, slab.Ino, slab.Base)
		}
	}
	return nil
}

func processHints(ino uint64, base int64) {
	if err := hintsDB.AddHint(ino, base); err != nil {
		logger.Errf("handleClient: AddHint(ino=%d, base=%d): %v", ino, base, err)
	}

	if err := hintsDB.PreloadSlabs(ino, base); err != nil {
		logger.Errf("handleClient: PreloadSlabs(ino=%d, base=%d): %v", ino, base, err)
	}
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
		go processHints(msg.Args.Inode, msg.Args.Base)
		go hintsDB.HitTracker.UpdateHits(msg.Args.Inode, msg.Args.Base)
		resp = MgrMsgHintResponse{
			Status: "OK",
		}
	case "get":
		logger.Infof("slab get: inode=%d/base=%d, is_preload=%v", msg.Args.Inode, msg.Args.Base, msg.Args.IsPreload)
		if !msg.Args.IsPreload {
			go processHints(msg.Args.Inode, msg.Args.Base)
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
		opErr, ok := err.(*net.OpError)
		if ok && errors.Is(opErr.Err, syscall.EADDRINUSE) {
			return fmt.Errorf("net.ListenUnix: already running")
		} else {
			return fmt.Errorf("net.ListenUnix: %v", err)
		}
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
	var cfg string

	if *confPath == "" {
		if os.Getenv("POTATOFS_BACKEND_CONFIG") == "" {
			die(2, "POTATOFS_BACKEND_CONFIG is not set")
		}
		cfg = os.Getenv("POTATOFS_BACKEND_CONFIG")
	} else {
		cfg = *confPath
		os.Setenv("POTATOFS_BACKEND_CONFIG", cfg)
	}

	if err = loadConfig(cfg); err != nil {
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
		s, err := NewPutStream(os.Stdin, *encryptInode, *encryptBase)
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
