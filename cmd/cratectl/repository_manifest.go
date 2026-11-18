// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

const repositoriesAPI = "/api/v1/repositories"
const repositoryManifestLimit = 4096

var repositoryPlanDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type hostedRepository struct {
	Name          string `json:"name"`
	Format        string `json:"format"`
	Access        string `json:"access"`
	RequireReview bool   `json:"require_review"`
}

type repositoryManifestDocument struct {
	Version int    `json:"version"`
	Tenant  string `json:"tenant"`
	hostedRepository
}

type repositoryObservation struct {
	hostedRepository
	Mode          string `json:"mode"`
	State         string `json:"state"`
	StateRevision int64  `json:"state_revision"`
}

type repositoryPlan struct {
	Version        int                        `json:"version"`
	Authority      string                     `json:"authority"`
	Desired        repositoryManifestDocument `json:"desired"`
	Current        *repositoryObservation     `json:"current"`
	Action         string                     `json:"action"`
	Drift          []string                   `json:"drift"`
	ApprovalSHA256 string                     `json:"approval_sha256,omitempty"`
}

type repositoryManagement struct {
	client    *http.Client
	authority string
	token     string
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
		if !repositoryName.MatchString(tenant) || !repositoryName.MatchString(name) {
			return errors.New("repository-import requires a valid --tenant and --name")
		}
		desired = repositoryManifestDocument{Version: 1, Tenant: tenant, hostedRepository: hostedRepository{Name: name}}
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
	client, authority, token, closeClient, err := configuredClient(*config)
	if err != nil {
		return err
	}
	defer closeClient()
	management := repositoryManagement{client: client, authority: authority, token: token}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var session struct {
		Tenant  string   `json:"tenant"`
		Role    string   `json:"role"`
		Formats []string `json:"formats"`
	}
	if _, err = management.request(ctx, "GET", "/api/v1/session", "", nil, &session); err != nil {
		return err
	}
	if session.Role != "admin" || session.Tenant != desired.Tenant {
		return errors.New("repository_manifest_tenant_access: use a current administrator credential for the specified tenant")
	}
	if desired.Format != "" && !slices.Contains(session.Formats, desired.Format) {
		return errors.New("repository_manifest_format_unavailable: the authenticated registry does not serve the requested format")
	}
	current, err := management.inspect(ctx, desired.Name)
	if err != nil {
		return err
	}
	if command == "repository-import" {
		if current == nil || current.Mode != "hosted" || current.State != "active" || !slices.Contains(session.Formats, current.Format) {
			return errors.New("repository_import_unavailable: choose an active hosted repository in the specified tenant")
		}
		desired.hostedRepository = current.hostedRepository
		return writeRepositoryDocument(out, desired)
	}
	creation := planRepository(authority, desired, nil)
	plan := creation
	if current != nil {
		plan = planRepository(authority, desired, current)
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
	body, err := json.Marshal(struct {
		hostedRepository
		Mode string `json:"mode"`
	}{desired.hostedRepository, "hosted"})
	if err != nil {
		return err
	}
	_, err = management.request(ctx, "POST", repositoriesAPI, "repository-create-"+approval, body, nil)
	if err != nil {
		return err
	}
	current, err = management.inspect(ctx, desired.Name)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("repository_create_readback: the repository could not be verified after creation")
	}
	plan = planRepository(authority, desired, current)
	if plan.Action != "unchanged" {
		if err := writeRepositoryDocument(out, plan); err != nil {
			return err
		}
		return errors.New("repository_drift: the current repository changed during creation")
	}
	plan.Action = "created"
	return writeRepositoryDocument(out, plan)
}

func planRepository(authority string, desired repositoryManifestDocument, current *repositoryObservation) repositoryPlan {
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
		!repositoryName.MatchString(document.Tenant) || !repositoryName.MatchString(document.Name) ||
		!slices.Contains([]string{"generic", "maven", "npm", "pypi", "oci", "nuget", "go"}, document.Format) ||
		(document.Access != "tenant" && document.Access != "restricted") {
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

func (m repositoryManagement) inspect(ctx context.Context, name string) (*repositoryObservation, error) {
	var repository struct {
		Name   string `json:"name"`
		Format string `json:"format"`
		Access string `json:"access"`
		Mode   string `json:"mode"`
		Review *bool  `json:"require_review"`
	}
	path := repositoriesAPI + "/" + name
	found, err := m.request(ctx, "GET", path+"/configuration", "", nil, &repository)
	if err != nil || !found {
		return nil, err
	}
	var lifecycle struct {
		Repository string `json:"repository"`
		State      string `json:"state"`
		Revision   *int64 `json:"revision"`
	}
	found, err = m.request(ctx, "GET", path+"/state", "", nil, &lifecycle)
	if err != nil {
		return nil, err
	}
	if !found || lifecycle.Repository != name || lifecycle.Revision == nil || *lifecycle.Revision < 0 ||
		!slices.Contains([]string{"active", "suspended", "removed"}, lifecycle.State) ||
		repository.Name != name || repository.Format == "" || repository.Mode == "" ||
		repository.Review == nil || (repository.Access != "tenant" && repository.Access != "restricted") {
		return nil, errors.New("repository_manifest_readback: registry returned incomplete or inconsistent repository identity")
	}
	return &repositoryObservation{
		hostedRepository: hostedRepository{repository.Name, repository.Format, repository.Access, *repository.Review},
		Mode:             repository.Mode, State: lifecycle.State, StateRevision: *lifecycle.Revision,
	}, nil
}

func (m repositoryManagement) request(ctx context.Context, method, path, key string, body []byte, result any) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, method, m.authority+path, bytes.NewReader(body))
	if err != nil {
		return false, errors.New("repository_manifest_request: invalid registry authority")
	}
	request.Header.Set("Authorization", "Bearer "+m.token)
	request.Header.Set("Accept", "application/json")
	expected := http.StatusOK
	if method == "POST" {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		expected = http.StatusCreated
	}
	response, err := m.client.Do(request)
	if err != nil {
		return false, errors.New("repository_manifest_request: check registry connectivity and configured trust")
	}
	defer response.Body.Close()
	const limit = 256 << 10
	if response.ContentLength > limit {
		return false, errors.New("repository_manifest_response_limit: registry response exceeds 256 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(data) > limit {
		return false, errors.New("repository_manifest_response_limit: incomplete or oversized registry response")
	}
	if response.StatusCode == http.StatusNotFound && method == "GET" && path != "/api/v1/session" {
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &failure) == nil && failure.Error.Code == "not_found" {
			return false, nil
		}
	}
	if response.StatusCode != expected {
		return false, fmt.Errorf("repository_manifest_http: %s returned HTTP %d; refresh the plan before retrying", method, response.StatusCode)
	}
	if result != nil && json.Unmarshal(data, result) != nil {
		return false, errors.New("repository_manifest_readback: registry returned invalid JSON")
	}
	return true, nil
}

func writeRepositoryDocument(out io.Writer, document any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}
