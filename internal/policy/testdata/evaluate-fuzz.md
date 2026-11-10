# Evaluate fuzz model

`FuzzEvaluate` generates bounded identity and restriction policies. Its independent dynamic-programming reference models Action, NotAction, Resource, NotResource, Bool, StringEquals, and IfExists. Context keys in this reference are unique ignoring case. Principals, policy variables, and other condition operators remain covered by the existing example tests, not this reference.

The explicit-deny and implicit-deny corpus cases use the examples already exercised by `policy_test.go`. The boundary corpus encodes the intersection described in https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html. The VWS ARN partition replaces the AWS partition. No AWS account is contacted.

Native fuzzing saves any disagreement under `testdata/fuzz/FuzzEvaluate`; the failure includes the input. PR runs use 30 seconds and the weekly run uses five minutes. A mismatch must be fixed or tracked with its exact corpus input before the PR is published.

The first fuzz run found `Match` treated a pattern asterisk as literal when the input also contained an asterisk at that position. That could skip a matching resource Deny. `TestMatchWildcardInValue` covers an S3-style object key containing an asterisk, and the minimized native corpus input is retained. Pattern asterisks now take precedence over literal equality.
