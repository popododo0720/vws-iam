# Simulator service reference snapshot

Fetched on 2026-11-11 with curl from:

- https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json
- https://servicereference.us-east-1.amazonaws.com/v1/sts/sts.json
- https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json

These are the unmodified input documents. Generation makes no network calls:
run `go generate ./internal/grpcapi` from the repository root.

To refresh, download all three documents with `curl --fail --location` into
this directory, update this fetch date and the date in
`internal/grpcapi/internal/gensimres/main.go`, then regenerate and review the
catalog diff. Run the simulator tests and `bash scripts/check-generated-go.sh`.
The catalog includes only unambiguous IAM/STS resource types and S3 bucket/object
types; adding support for other services is separate work.
