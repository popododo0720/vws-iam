// Command gensimres generates the simulator catalog from pinned AWS reference JSON.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/format"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type reference struct {
	Resources []struct {
		Name       string
		ARNFormats []string
	}
	Actions []struct {
		Name      string
		Resources []struct{ Name string }
	}
}

func main() {
	if err := run(); err != nil {
		slog.ErrorContext(context.Background(), "generate simulation resources", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	data, err := generate("testdata/simulation-resources")
	if err != nil {
		return err
	}
	if err := os.WriteFile("simulation_resources_gen.go", data, 0o644); err != nil {
		return fmt.Errorf("write simulation resources: %w", err)
	}
	return nil
}

func generate(dir string) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("// Code generated from the AWS service authorization reference on 2026-11-11; DO NOT EDIT.\n")
	out.WriteString("// Sources: https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json\n")
	out.WriteString("// Only unambiguous IAM/STS types and S3 bucket/object types are included.\n")
	out.WriteString("package grpcapi\n\nvar simulationResourceTemplates = map[string]string{\n")
	for _, service := range []string{"iam", "sts", "s3"} {
		data, err := os.ReadFile(filepath.Join(dir, service+".json"))
		if err != nil {
			return nil, fmt.Errorf("read %s snapshot: %w", service, err)
		}
		var ref reference
		if err := json.Unmarshal(data, &ref); err != nil {
			return nil, fmt.Errorf("decode %s snapshot: %w", service, err)
		}
		resources := make(map[string]string, len(ref.Resources))
		for _, resource := range ref.Resources {
			if len(resource.ARNFormats) == 0 {
				return nil, fmt.Errorf("%s resource %s has no ARN format", service, resource.Name)
			}
			resources[resource.Name] = strings.ReplaceAll(resource.ARNFormats[0], "${Partition}", "vws")
		}
		for _, action := range ref.Actions {
			var types []string
			for _, resource := range action.Resources {
				if service != "s3" || resource.Name == "bucket" || resource.Name == "object" {
					types = append(types, resource.Name)
				}
			}
			if len(types) != 1 {
				continue
			}
			arn, ok := resources[types[0]]
			if !ok {
				return nil, fmt.Errorf("%s action %s references unknown resource %s", service, action.Name, types[0])
			}
			fmt.Fprintf(&out, "\t%q: %q,\n", service+":"+strings.ToLower(action.Name), arn)
		}
	}
	out.WriteString("}\n")
	data, err := format.Source(out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format simulation resources: %w", err)
	}
	return data, nil
}
