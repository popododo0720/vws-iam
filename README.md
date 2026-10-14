# vws-iam

Identity and access management for VWS: users, groups, roles, JSON policy
evaluation, access keys, STS AssumeRole and MFA (TOTP). console-api calls this
service over gRPC (API in vws-proto) to verify SigV4 requests and authorize
every EC2/S3/IAM call.

Status: Phase 1 design, see the "IAM Phase 1 design" issue.

License: Apache-2.0
