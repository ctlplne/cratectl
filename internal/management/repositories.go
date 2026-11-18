// SPDX-License-Identifier: BUSL-1.1
package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
)

const repositoriesAPI = "/api/v1/repositories"

var repositoryName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func ValidRepositoryName(name string) bool {
	return repositoryName.MatchString(name)
}

type RepositorySpec struct {
	Name          string `json:"name"`
	Format        string `json:"format"`
	Access        string `json:"access"`
	RequireReview bool   `json:"require_review"`
}

func (s RepositorySpec) Valid() bool {
	return ValidRepositoryName(s.Name) && slices.Contains([]string{"generic", "maven", "npm", "pypi", "oci", "nuget", "go"}, s.Format) &&
		(s.Access == "tenant" || s.Access == "restricted")
}

type RepositoryObservation struct {
	RepositorySpec
	Mode          string `json:"mode"`
	State         string `json:"state"`
	StateRevision int64  `json:"state_revision"`
}

type Repositories struct {
	client      *http.Client
	authority   string
	token       string
	closeClient func()
}

func OpenRepositories(path string) (*Repositories, error) {
	client, authority, token, closeClient, err := OpenClient(path)
	if err != nil {
		return nil, err
	}
	return &Repositories{client: client, authority: authority, token: token, closeClient: closeClient}, nil
}

func (m *Repositories) Close() { m.closeClient() }

func (m *Repositories) Authority() string { return m.authority }

func (m *Repositories) Authorize(ctx context.Context, tenant string) ([]string, error) {
	var session struct {
		Tenant  string   `json:"tenant"`
		Role    string   `json:"role"`
		Formats []string `json:"formats"`
	}
	if _, err := m.request(ctx, "GET", "/api/v1/session", "", nil, &session); err != nil {
		return nil, err
	}
	if !ValidRepositoryName(tenant) || session.Tenant != tenant || session.Role != "admin" {
		return nil, errors.New("repository_manifest_tenant_access: use a current administrator credential for the specified tenant")
	}
	return session.Formats, nil
}

func (m *Repositories) Create(ctx context.Context, desired RepositorySpec, key string) error {
	if !desired.Valid() {
		return errors.New("repository_manifest_input: supply valid hosted repository settings")
	}
	body, err := json.Marshal(struct {
		RepositorySpec
		Mode string `json:"mode"`
	}{desired, "hosted"})
	if err != nil {
		return err
	}
	_, err = m.request(ctx, "POST", repositoriesAPI, key, body, nil)
	return err
}

func (m *Repositories) Inspect(ctx context.Context, name string) (*RepositoryObservation, error) {
	if !ValidRepositoryName(name) {
		return nil, errors.New("repository_manifest_input: supply a valid repository name")
	}
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
	return &RepositoryObservation{
		RepositorySpec: RepositorySpec{repository.Name, repository.Format, repository.Access, *repository.Review},
		Mode:           repository.Mode, State: lifecycle.State, StateRevision: *lifecycle.Revision,
	}, nil
}

func (m *Repositories) request(ctx context.Context, method, path, key string, body []byte, result any) (bool, error) {
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
