// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type profile struct {
	phase, executable, config, authority, tenant, repository, artifact, digest string
}

type result struct {
	Phase    string   `json:"phase"`
	Protocol string   `json:"protocol"`
	Checks   []string `json:"checks"`
}

type observation struct {
	Source struct {
		Registry string `json:"registry"`
		Tenant   string `json:"tenant"`
	} `json:"source"`
	Page struct {
		Items []struct {
			Name     string `json:"name"`
			Digest   string `json:"digest"`
			Decision string `json:"decision"`
		} `json:"items"`
		Next string `json:"next"`
	} `json:"page"`
	Record struct {
		Name          string `json:"name"`
		Role          string `json:"role"`
		Repository    string `json:"repository"`
		Path          string `json:"path"`
		Digest        string `json:"digest"`
		Decision      string `json:"decision"`
		RequireReview bool   `json:"require_review"`
	} `json:"record"`
}

func qualify(ctx context.Context, p profile) (record result, err error) {
	command := exec.CommandContext(ctx, p.executable, "--client-config", p.config, "--authority", p.authority, "--tenant", p.tenant, "--allow-metadata")
	command.Stderr = os.Stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "cratectl-qualification", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		return record, errors.New("the official MCP client could not connect to the candidate process")
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	version := session.InitializeResult().ProtocolVersion
	if version != "2026-07-28" {
		return record, errors.New("expected the official MCP 2026-07-28 protocol")
	}
	record = result{Phase: p.phase, Protocol: version, Checks: []string{"native candidate stdio over MCP 2026-07-28"}}
	check := func(label string, condition bool) error {
		if !condition {
			return errors.New(label)
		}
		record.Checks = append(record.Checks, label)
		return nil
	}
	call := func(name string, args any) (observation, string, error) {
		var observed observation
		answer, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || answer == nil {
			return observed, "", fmt.Errorf("%s tool call did not complete", name)
		}
		if answer.IsError {
			for _, content := range answer.Content {
				if block, ok := content.(*mcp.TextContent); ok {
					return observed, block.Text, nil
				}
			}
			return observed, "", fmt.Errorf("%s tool returned an error without a decision", name)
		}
		raw, err := json.Marshal(answer.StructuredContent)
		if err != nil || len(raw) > 512<<10 || json.Unmarshal(raw, &observed) != nil ||
			observed.Source.Registry != p.authority || observed.Source.Tenant != p.tenant {
			return observed, "", fmt.Errorf("%s tool returned an invalid evidence scope", name)
		}
		return observed, "", nil
	}
	repository := map[string]any{"repository": p.repository}
	reference := map[string]any{"repository": p.repository, "path": p.artifact}
	expect := func(label, toolName string, args any, code string, match func(observation) bool) error {
		item, failure, err := call(toolName, args)
		if err != nil {
			return err
		}
		if code != "" {
			return check(label, strings.Contains(failure, code))
		}
		return check(label, failure == "" && match(item))
	}
	matchesReference := func(decision string) func(observation) bool {
		return func(v observation) bool {
			return v.Record.Repository == p.repository && v.Record.Path == p.artifact &&
				v.Record.Digest == p.digest && v.Record.Decision == decision
		}
	}
	switch p.phase {
	case "admin-pending":
		inventory, err := session.ListTools(ctx, nil)
		if err != nil {
			return record, err
		}
		names := make([]string, 0, len(inventory.Tools))
		for _, tool := range inventory.Tools {
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				return record, errors.New("found an unreviewed tool capability")
			}
			names = append(names, tool.Name)
		}
		slices.Sort(names)
		if err := check("exact inventory of five read-only tools",
			reflect.DeepEqual(names, []string{"cratectl_get_artifact", "cratectl_get_repository", "cratectl_list_artifacts", "cratectl_list_repositories", "cratectl_session"})); err != nil {
			return record, err
		}
		first, msg, err := call("cratectl_list_repositories", map[string]any{"limit": 1, "search": "cratectl-"})
		if err != nil || msg != "" || len(first.Page.Items) != 1 || first.Page.Next == "" {
			return record, errors.New("the real registry did not return a bounded live continuation")
		}
		err = expect("authorized repository cursor returns the next distinct repository", "cratectl_list_repositories",
			map[string]any{"limit": 1, "search": "cratectl-", "cursor": first.Page.Next}, "",
			func(v observation) bool {
				return len(v.Page.Items) == 1 && v.Page.Items[0].Name != first.Page.Items[0].Name
			})
		if err != nil {
			return record, err
		}
		return record, expect("administrator sees the exact unassessed artifact digest", "cratectl_get_artifact", reference, "", matchesReference("unassessed"))
	case "reader-ungranted":
		err = expect("current repository grant denies the reader", "cratectl_get_repository", repository, "registry_denied", nil)
	case "reader-pending":
		err = expect("granted reader can inspect repository review settings", "cratectl_get_repository", repository, "",
			func(v observation) bool { return v.Record.Name == p.repository && v.Record.RequireReview })
		if err != nil {
			return record, err
		}
		err = expect("unassessed digest is withheld by current policy", "cratectl_get_artifact", reference, "registry_denied", nil)
		if err != nil {
			return record, err
		}
		err = expect("pending references stay outside the reader inventory", "cratectl_list_artifacts", repository, "",
			func(v observation) bool { return len(v.Page.Items) == 0 })
	case "reader-approved":
		err = expect("approved artifact identity survives restart under the same reader grant", "cratectl_get_artifact", reference, "", matchesReference("allowed"))
	case "other-tenant":
		err = expect("different live tenant credential is refused by the adapter", "cratectl_session", nil, "registry_scope", nil)
	case "revoked":
		err = expect("currently revoked credential cannot return registry metadata", "cratectl_session", nil, "registry_unauthenticated", nil)
	default:
		err = errors.New("unknown owned MCP verification phase")
	}
	return record, err
}

func main() {
	var p profile
	flag.StringVar(&p.phase, "phase", "", "owned verification phase")
	flag.StringVar(&p.executable, "server", "", "exact candidate stdio binary")
	flag.StringVar(&p.config, "config", "", "private fixture client configuration")
	flag.StringVar(&p.authority, "authority", "", "owned HTTPS registry")
	flag.StringVar(&p.tenant, "tenant", "", "expected fixture tenant")
	flag.StringVar(&p.repository, "repository", "", "owned repository")
	flag.StringVar(&p.artifact, "artifact-path", "", "exact fixture artifact path")
	flag.StringVar(&p.digest, "digest", "", "expected artifact SHA-256")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	record, err := qualify(ctx, p)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(record)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
