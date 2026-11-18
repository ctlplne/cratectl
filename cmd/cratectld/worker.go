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
	"ctlplne.dev/cratectl/internal/configfile"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/worker"
)

func workerTokenFiles(path string, maximum int64) ([]string, error) {
	file, err := configfile.OpenBounded(path, maximum, true)
	if err != nil {
		return nil, errors.New("worker identity configuration requires a bounded private regular file")
	}
	defer file.Close()
	var config struct {
		TokenFiles []string `json:"token_files"`
	}
	bounded := &io.LimitedReader{R: file, N: maximum + 1}
	decoder := json.NewDecoder(bounded)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		return nil, errors.New("invalid worker identity configuration")
	}
	var rest any
	if decoder.Decode(&rest) != io.EOF || bounded.N == 0 {
		return nil, errors.New("worker identity configuration must contain one object within its byte budget")
	}
	return config.TokenFiles, nil
}

func runWorker() error {
	f := flag.NewFlagSet("worker", flag.ContinueOnError)
	configuration := f.String("config", "", "private runtime JSON from cratectld init")
	identities := f.String("identities", "", "private JSON object with a token_files array; one dedicated worker credential per tenant")
	root := f.String("objects", ".private/objects", "same durable object directory as the registry")
	name := f.String("name", "cratectl-worker", "worker process name")
	events := f.Int("event-concurrency", 1, "reserved event projection slots")
	integrity := f.Int("integrity-concurrency", 1, "reserved integrity verification slots")
	maintenance := f.Int("maintenance-concurrency", 1, "reserved lease reconciliation slots")
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
	dsn := os.Getenv("CRATECTL_DSN")
	if *configuration != "" {
		c, e := runtimeConfiguration(*configuration)
		if e != nil {
			return e
		}
		set := flagSet(f)
		dsn = c.DSN
		if !set["objects"] {
			*root = c.Objects
		}
		if !set["identities"] {
			*identities = c.WorkerIdentities
		}
	}
	if *budget < 1 || *budget > 1<<30 {
		return errors.New("identity configuration budget must be positive and at most 1 GiB")
	}
	tokenFiles, e := workerTokenFiles(*identities, *budget)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	opts := worker.Options{Name: *name, EventConcurrency: *events, IntegrityConcurrency: *integrity, MaintenanceConcurrency: *maintenance, Lease: *lease, Poll: *poll, Timeout: *timeout, MaxObjectBytes: *maxBytes, MaxEventBytes: *maxEvent, BytesPerSecond: *rate}
	for _, path := range tokenFiles {
		token, e := configfile.ReadBytes(path, 257, true)
		if e != nil {
			return errors.New("worker token requires a private regular file within 257 bytes")
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
