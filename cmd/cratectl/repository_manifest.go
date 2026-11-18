// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"regexp"
	"slices"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/management"
)

const repositoryManifestLimit = 4096

var repositoryPlanDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type repositoryManifestDocument struct {
	Version int    `json:"version"`
	Tenant  string `json:"tenant"`
	management.RepositorySpec
}

type repositoryPlan struct {
	Version        int                               `json:"version"`
	Authority      string                            `json:"authority"`
	Desired        repositoryManifestDocument        `json:"desired"`
	Current        *management.RepositoryObservation `json:"current"`
	Action         string                            `json:"action"`
	Drift          []string                          `json:"drift"`
	ApprovalSHA256 string                            `json:"approval_sha256,omitempty"`
}

func runRepositoryManifest(args []string, command string, out io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	config := flags.String("config", "", "private cratectl client JSON")
	var manifestFile, approval, tenant, name string
	if command == "repository-import" {
		flags.StringVar(&tenant, "tenant", "", "expected tenant")
		flags.StringVar(&name, "name", "", "existing active hosted repository")
	} else {
		flags.StringVar(&manifestFile, "manifest", "", "version 1 repository manifest JSON")
		if command == "repository-apply" {
			flags.StringVar(&approval, "approve", "", "SHA-256 from the reviewed creation plan")
		}
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *config == "" {
		return errors.New("a private --config is required")
	}
	var desired repositoryManifestDocument
	if command == "repository-import" {
		if !management.ValidRepositoryName(tenant) || !management.ValidRepositoryName(name) {
			return errors.New("repository-import requires a valid --tenant and --name")
		}
		desired = repositoryManifestDocument{Version: 1, Tenant: tenant, RepositorySpec: management.RepositorySpec{Name: name}}
	} else {
		var err error
		desired, err = readRepositoryManifest(manifestFile)
		if err != nil {
			return err
		}
		if command == "repository-apply" && !repositoryPlanDigest.MatchString(approval) {
			return errors.New("repository-apply requires the exact --approve SHA-256 from a creation plan")
		}
	}
	repositories, err := management.OpenRepositories(*config)
	if err != nil {
		return err
	}
	defer repositories.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	formats, err := repositories.Authorize(ctx, desired.Tenant)
	if err != nil {
		return err
	}
	if desired.Format != "" && !slices.Contains(formats, desired.Format) {
		return errors.New("repository_manifest_format_unavailable: the authenticated registry does not serve the requested format")
	}
	current, err := repositories.Inspect(ctx, desired.Name)
	if err != nil {
		return err
	}
	if command == "repository-import" {
		if current == nil || current.Mode != "hosted" || current.State != "active" || !slices.Contains(formats, current.Format) {
			return errors.New("repository_import_unavailable: choose an active hosted repository in the specified tenant")
		}
		desired.RepositorySpec = current.RepositorySpec
		return writeRepositoryDocument(out, desired)
	}
	creation := planRepository(repositories.Authority(), desired, nil)
	plan := creation
	if current != nil {
		plan = planRepository(repositories.Authority(), desired, current)
	}
	if command == "repository-plan" {
		return writeRepositoryDocument(out, plan)
	}
	if approval != creation.ApprovalSHA256 {
		return errors.New("repository_plan_changed: review the current plan and use its exact approval digest")
	}
	if plan.Action == "drift" {
		if err := writeRepositoryDocument(out, plan); err != nil {
			return err
		}
		return errors.New("repository_drift: inspect the current repository before proceeding")
	}
	if plan.Action == "unchanged" {
		return writeRepositoryDocument(out, plan)
	}
	if err := repositories.Create(ctx, desired.RepositorySpec, "repository-create-"+approval); err != nil {
		return err
	}
	current, err = repositories.Inspect(ctx, desired.Name)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("repository_create_readback: the repository could not be verified after creation")
	}
	plan = planRepository(repositories.Authority(), desired, current)
	if plan.Action != "unchanged" {
		if err := writeRepositoryDocument(out, plan); err != nil {
			return err
		}
		return errors.New("repository_drift: the current repository changed during creation")
	}
	plan.Action = "created"
	return writeRepositoryDocument(out, plan)
}

func planRepository(authority string, desired repositoryManifestDocument, current *management.RepositoryObservation) repositoryPlan {
	plan := repositoryPlan{Version: 1, Authority: authority, Desired: desired, Current: current, Action: "create", Drift: []string{}}
	if current == nil {
		// All fields in a creation plan are validated scalars or fixed literals.
		body, _ := json.Marshal(plan)
		plan.ApprovalSHA256 = crypt.Digest(body)
		return plan
	}
	for _, field := range []struct {
		name    string
		differs bool
	}{
		{"format", desired.Format != current.Format},
		{"mode", current.Mode != "hosted"},
		{"access", desired.Access != current.Access},
		{"require_review", desired.RequireReview != current.RequireReview},
		{"state", current.State != "active"},
	} {
		if field.differs {
			plan.Drift = append(plan.Drift, field.name)
		}
	}
	plan.Action = "unchanged"
	if len(plan.Drift) != 0 {
		plan.Action = "drift"
	}
	return plan
}

func readRepositoryManifest(path string) (repositoryManifestDocument, error) {
	var document repositoryManifestDocument
	if path == "" {
		return document, errors.New("a --manifest JSON file is required")
	}
	data, err := configfile.ReadBytes(path, repositoryManifestLimit, false)
	if err != nil {
		return document, err
	}
	if !decodeRepositoryManifest(data, &document) || document.Version != 1 ||
		!management.ValidRepositoryName(document.Tenant) || !document.RepositorySpec.Valid() {
		return repositoryManifestDocument{}, errors.New("invalid_repository_manifest: supply version 1, tenant, name, format, access and require_review exactly once")
	}
	return document, nil
}

func decodeRepositoryManifest(data []byte, document *repositoryManifestDocument) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	fields := map[string]any{
		"version": &document.Version, "tenant": &document.Tenant, "name": &document.Name,
		"format": &document.Format, "access": &document.Access, "require_review": &document.RequireReview,
	}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		destination := fields[name]
		if err != nil || !ok || destination == nil {
			return false
		}
		delete(fields, name)
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) || json.Unmarshal(value, destination) != nil {
			return false
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(fields) != 0 {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func writeRepositoryDocument(out io.Writer, document any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}
