#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
go generate ./internal/grpcapi
git diff --exit-code -- internal/grpcapi/simulation_resources_gen.go
