// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/server"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: cratectld migrate|provision|revoke|serve|worker")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "worker":
		return runWorker()
	case "migrate":
		return store.Migrate(ctx, os.Getenv("CRATECTL_OWNER_DSN"))
	case "provision":
		f := flag.NewFlagSet("provision", flag.ContinueOnError)
		tenant := f.String("tenant", "", "tenant")
		actor := f.String("actor", "", "actor")
		role := f.String("role", "reader", "admin, writer, reader, worker (worker credentials cannot use the public API)")
		out := f.String("token-file", "", "new private credential file")
		expiresIn := f.Duration("expires-in", 24*time.Hour, "credential lifetime")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		if *expiresIn <= 0 {
			return errors.New("expires-in must be positive")
		}
		if *out == "" {
			return errors.New("token-file required")
		}
		token, e := crypt.Token()
		if e != nil {
			return e
		}
		file, e := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer file.Close()
		ok := false
		defer func() {
			if !ok {
				os.Remove(*out)
			}
		}()
		if _, e = file.WriteString(token + "\n"); e != nil {
			return e
		}
		if e = file.Sync(); e != nil {
			return e
		}
		if e = store.Provision(ctx, os.Getenv("CRATECTL_OWNER_DSN"), *tenant, *actor, *role, token, time.Now().Add(*expiresIn)); e != nil {
			return e
		}
		ok = true
		fmt.Println("Created expiring tenant-scoped credential. Credential is in the private file.")
		return nil
	case "revoke":
		f := flag.NewFlagSet("revoke", flag.ContinueOnError)
		file := f.String("token-file", "", "credential to revoke")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		b, e := os.ReadFile(*file)
		if e != nil {
			return e
		}
		defer clear(b)
		if e = store.Revoke(ctx, os.Getenv("CRATECTL_OWNER_DSN"), strings.TrimSpace(string(b))); e != nil {
			return e
		}
		fmt.Println("Credential revoked; subsequent authentication fails.")
		return nil
	case "serve":
		f := flag.NewFlagSet("serve", flag.ContinueOnError)
		listen := f.String("listen", "127.0.0.1:38443", "listener")
		public := f.String("public-url", "https://localhost:38443", "client-visible authority")
		root := f.String("objects", ".private/objects", "durable object directory")
		cert := f.String("tls-cert", "", "TLS certificate")
		key := f.String("tls-key", "", "TLS key file")
		dev := f.Bool("dev-loopback-http", false, "explicit development HTTP exception")
		max := f.Int64("max-object-bytes", 1<<30, "per-object byte limit")
		privateNetworks := f.String("allow-private-upstreams", "", "operator-authorized private upstream CIDRs, comma separated")
		transfers := f.Int("transfer-concurrency", 16, "maximum admitted requests")
		fills := f.Int("proxy-concurrency", 4, "maximum local proxy retrievals; reserve capacity for cached reads")
		tenantFills := f.Int("tenant-proxy-concurrency", 32, "maximum durable active retrievals per tenant across nodes")
		proxyLease := f.Duration("proxy-lease", 150*time.Second, "renewed proxy retrieval lease; 1 second–5 minutes")
		uploads := f.Int("tenant-upload-concurrency", 32, "maximum active OCI upload sessions per tenant")
		uploadParts := f.Int("upload-part-budget", 4096, "maximum immutable parts per OCI upload")
		uploadMetadata := f.Int64("upload-metadata-bytes", 1<<20, "maximum upload part metadata bytes")
		uploadLease := f.Duration("upload-lease", 30*time.Second, "renewed OCI operation lease; 1 second–5 minutes")
		uploadTTL := f.Duration("upload-ttl", 30*time.Minute, "rolling OCI session lifetime; at least the lease and at most 24 hours")
		sweepTargets := f.Int("integrity-sweep-target-budget", 100000, "maximum immutable targets admitted in one referenced-storage snapshot")

		nativeTags := f.Int("native-tag-budget", 128, "maximum tags in a complete native package index")
		nativeVersions := f.Int("native-version-budget", 10000, "maximum versions in a complete native index")
		nativeBytes := f.Int64("native-metadata-bytes", 8<<20, "maximum metadata bytes in a complete native index")
		npmPublish := f.Int64("npm-publish-bytes", 24<<20, "maximum encoded npm publication document bytes")
		npmExpanded := f.Int64("npm-expanded-bytes", 64<<20, "maximum expanded npm tarball bytes, including headers and padding")
		npmFiles := f.Int("npm-file-budget", 10000, "maximum npm archive entries")
		npmJSON := f.Int64("npm-package-json-bytes", 1<<20, "maximum package.json bytes in an npm archive")
		pythonUpload := f.Int64("python-upload-bytes", 64<<20, "maximum encoded Python publication or cached distribution bytes")
		pythonExpanded := f.Int64("python-expanded-bytes", 256<<20, "maximum expanded Python archive bytes")
		pythonFiles := f.Int("python-file-budget", 10000, "maximum Python archive entries")
		pythonMetadata := f.Int64("python-metadata-bytes", 1<<20, "maximum embedded Python core metadata bytes")
		ociGraphBytes := f.Int64("oci-graph-bytes", 4<<30, "maximum aggregate bytes staged by one OCI graph/catalog retrieval")
		ociPages := f.Int("oci-catalog-pages", 32, "maximum pages in one complete OCI upstream discovery walk")
		ociPageSize := f.Int("oci-page-size", 1000, "default and maximum entries in an OCI discovery response page")
		ociDescriptorURLs := f.Int("oci-descriptor-urls", 32, "maximum alternate descriptor URI candidates per OCI retrieval; zero disables fallback")
		ociDescriptorParents := f.Int("oci-descriptor-parents", 64, "maximum retained parent manifests inspected for a direct OCI member refresh")
		ociRedirects := f.Int("oci-delivery-redirects", 5, "maximum approved delivery redirect hops per OCI request; zero disables redirects")
		ociURLBytes := f.Int("oci-delivery-url-bytes", 16384, "maximum ephemeral OCI delivery URL bytes, within the response-header ceiling")
		ociQueryBytes := f.Int("oci-delivery-query-bytes", 8192, "maximum opaque query bytes on explicitly approved OCI sources")
		ociQueryPairs := f.Int("oci-delivery-query-pairs", 64, "maximum opaque OCI delivery query parameter pairs")

		credentials := f.String("upstream-credentials", "", "private JSON map of named upstream tokens; values never enter repository configuration")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		host, _, e := net.SplitHostPort(*listen)
		if e != nil {
			return e
		}
		u, e := url.Parse(*public)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
			return errors.New("public-url must contain only scheme and authority")
		}
		if *dev {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() || u.Scheme != "http" {
				return errors.New("HTTP development mode requires a literal loopback listener and HTTP public URL")
			}
		} else if *cert == "" || *key == "" || u.Scheme != "https" {
			return errors.New("TLS certificate/key and HTTPS public URL required")
		}
		db, e := store.Open(ctx, os.Getenv("CRATECTL_DSN"))
		if e != nil {
			return e
		}
		defer db.Pool.Close()
		b, e := blob.New(*root, *max)
		if e != nil {
			return e
		}
		h := server.New(db, b, *public)
		if e := h.ConfigureSweepBudget(*sweepTargets); e != nil {
			return errors.New("integrity sweep target budget must be 1–2147483646")
		}
		if *proxyLease < time.Second || *proxyLease > 5*time.Minute {
			return errors.New("proxy lease must be 1 second–5 minutes")
		}
		h.ProxyLease = *proxyLease
		if e := h.ConfigureUploads(*uploads, *uploadParts, *uploadMetadata, *uploadLease, *uploadTTL); e != nil {
			return errors.New("invalid upload session, part, byte or lease budgets")
		}
		if *nativeVersions <= 0 || *nativeBytes <= 0 || *nativeTags <= 0 {
			return errors.New("native metadata budgets must be positive")
		}
		h.NativeTagLimit = *nativeTags
		h.NativeVersionLimit = *nativeVersions
		h.NativeMetadataBytes = *nativeBytes
		if *npmPublish <= 0 || *npmExpanded <= 0 || *npmExpanded >= 1<<62 || *npmFiles <= 0 || *npmJSON <= 0 || *npmJSON > *npmExpanded {
			return errors.New("npm publication and archive budgets must be positive; package.json must fit the expanded-byte budget")
		}
		h.NPMPublishBytes, h.NPMExpandedBytes, h.NPMFileLimit, h.NPMPackageJSONBytes = *npmPublish, *npmExpanded, *npmFiles, *npmJSON
		if *pythonUpload <= 0 || *pythonExpanded <= 0 || *pythonExpanded >= 1<<62 || *pythonFiles <= 0 || *pythonMetadata <= 0 || *pythonMetadata > *pythonExpanded {
			return errors.New("Python upload/archive budgets must be positive and core metadata must fit expanded bytes")
		}
		h.PythonUploadBytes, h.PythonExpandedBytes, h.PythonFileLimit, h.PythonMetadataBytes = *pythonUpload, *pythonExpanded, *pythonFiles, *pythonMetadata
		if *ociGraphBytes <= 0 || *ociGraphBytes >= 1<<62 {
			return errors.New("OCI graph byte budget must be positive and below 2^62")
		}
		h.OCIGraphBytes = *ociGraphBytes
		if *ociPages <= 0 || *ociPages > 4096 || *ociPageSize <= 0 || *ociPageSize > 100000 {
			return errors.New("OCI catalog pages must be 1–4096 and response page size 1–100000")
		}
		h.OCICatalogPages, h.OCIPageSize = *ociPages, *ociPageSize
		if *ociDescriptorURLs < 0 || *ociDescriptorURLs > 4096 || *ociDescriptorParents < 1 || *ociDescriptorParents > 4096 {
			return errors.New("OCI descriptor URL budget must be 0–4096 and parent budget 1–4096")
		}
		h.OCIDescriptorURLs, h.OCIDescriptorParents = *ociDescriptorURLs, *ociDescriptorParents
		if e := h.ConfigureOCIDelivery(*ociRedirects, upstream.RegistryDeliveryLimits{URLBytes: *ociURLBytes, QueryBytes: *ociQueryBytes, QueryPairs: *ociQueryPairs}); e != nil {
			return e
		}
		if e := h.ConfigureConcurrency(*transfers, *fills, *tenantFills); e != nil {
			return e
		}
		if *privateNetworks != "" {
			for _, cidr := range strings.Split(*privateNetworks, ",") {
				if _, e := netip.ParsePrefix(cidr); e != nil {
					return errors.New("invalid private upstream network")
				}
				h.PrivateUpstreamNetworks = append(h.PrivateUpstreamNetworks, cidr)
			}
		}
		if *credentials != "" {
			info, e := os.Stat(*credentials)
			if e != nil || info.Mode().Perm()&0077 != 0 {
				return errors.New("upstream credential file must exist with private permissions")
			}
			data, e := os.ReadFile(*credentials)
			if e != nil {
				return errors.New("cannot read upstream credential file")
			}
			defer clear(data)
			if len(data) > 64<<10 || json.Unmarshal(data, &h.UpstreamCredentials) != nil {
				return errors.New("invalid private upstream credentials JSON")
			}
			if e := h.ValidateCredentials(); e != nil {
				return e
			}
		}
		srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
		stop, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		go func() {
			<-stop.Done()
			c, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			srv.Shutdown(c)
		}()
		fmt.Printf("cratectl listening on %s\n", *listen)
		if *dev {
			e = srv.ListenAndServe()
		} else {
			e = srv.ListenAndServeTLS(*cert, *key)
		}
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "cratectld failed:", e)
		os.Exit(1)
	}
}
