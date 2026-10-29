// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/worker"
)

func runWorker() error {
	f := flag.NewFlagSet("worker", flag.ContinueOnError)
	identities := f.String("identities", "", "private JSON object with a token_files array; one dedicated worker credential per tenant")
	root := f.String("objects", ".private/objects", "same durable object directory as the registry")
	name := f.String("name", "cratectl-worker", "worker process name")
	events := f.Int("event-concurrency", 1, "reserved event projection slots")
	integrity := f.Int("integrity-concurrency", 1, "reserved integrity verification slots")
	lease := f.Duration("lease", 30*time.Second, "renewed fenced job lease; 1 second–5 minutes")
	poll := f.Duration("poll", 250*time.Millisecond, "idle queue polling interval")
	timeout := f.Duration("job-timeout", 2*time.Minute, "maximum duration of one attempt")
	maxBytes := f.Int64("max-job-bytes", 1<<30, "maximum bytes per integrity task")
	maxEvent := f.Int64("max-event-bytes", 16<<20, "maximum event payload bytes per projection")
	rate := f.Int64("verify-bytes-per-second", 16<<20, "I/O pacing per integrity slot; zero disables pacing")
	budget := f.Int64("identity-config-bytes", 1<<20, "maximum private identity configuration bytes")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if *budget < 1 || *budget > 1<<30 {
		return errors.New("identity configuration budget must be positive and at most 1 GiB")
	}
	file, e := os.Open(*identities)
	if e != nil {
		return errors.New("open private worker identity configuration")
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || info.Mode().Perm()&0077 != 0 || info.Size() > *budget {
		return errors.New("worker identity configuration must be bounded and readable only by its owner")
	}
	var config struct {
		TokenFiles []string `json:"token_files"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, *budget+1))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&config); e != nil {
		return errors.New("invalid worker identity configuration")
	}
	var rest any
	if decoder.Decode(&rest) != io.EOF {
		return errors.New("send one worker identity object")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	opts := worker.Options{Name: *name, EventConcurrency: *events, IntegrityConcurrency: *integrity, Lease: *lease, Poll: *poll, Timeout: *timeout, MaxObjectBytes: *maxBytes, MaxEventBytes: *maxEvent, BytesPerSecond: *rate}
	for _, path := range config.TokenFiles {
		file, e := os.Open(path)
		if e != nil {
			return errors.New("open a configured worker token file")
		}
		info, e := file.Stat()
		if e != nil || info.Mode().Perm()&0077 != 0 || info.Size() > 257 {
			file.Close()
			return errors.New("worker token files must be bounded and readable only by their owner")
		}
		token, e := io.ReadAll(io.LimitReader(file, 258))
		file.Close()
		if e != nil {
			return errors.New("read a configured worker token")
		}
		identity, e := db.AuthenticateWorker(ctx, strings.TrimSpace(string(token)))
		clear(token)
		if e != nil {
			return errors.New("worker credential expired, revoked or has the wrong purpose")
		}
		opts.Identities = append(opts.Identities, identity)
	}
	if e = opts.Validate(); e != nil {
		return errors.New("invalid worker budgets or duplicate tenant identities; use worker --help")
	}
	objects, e := blob.New(*root, *maxBytes)
	if e != nil {
		return e
	}
	encoder := json.NewEncoder(os.Stdout)
	opts.Notice = func(n worker.Notice) { encoder.Encode(n) }
	return worker.Run(ctx, db, objects, opts)
}
