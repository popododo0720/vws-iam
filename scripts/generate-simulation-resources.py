#!/usr/bin/env python3
"""Generate the first simulator catalog from downloaded AWS reference JSON.

Download iam.json, sts.json and s3.json from
https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json
into one directory. Run this script with that directory, then gofmt its output.
No credentials or AWS account calls are used.
"""

import json
import pathlib
import sys

print("// Code generated from the AWS service authorization reference on 2026-11-10; DO NOT EDIT.")
print("// Sources: https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json")
print("// Only unambiguous IAM/STS types and S3 bucket/object types are included.")
print("package grpcapi\n\nvar simulationResourceTemplates = map[string]string{")
for service in ("iam", "sts", "s3"):
    data = json.loads((pathlib.Path(sys.argv[1]) / (service + ".json")).read_text())
    resources = {r["Name"]: r["ARNFormats"][0].replace("${Partition}", "vws") for r in data["Resources"]}
    for action in data["Actions"]:
        types = [r["Name"] for r in action.get("Resources", ()) if service != "s3" or r["Name"] in ("bucket", "object")]
        if len(types) == 1:
            print("\t" + json.dumps(service + ":" + action["Name"].lower()) + ": " + json.dumps(resources[types[0]]) + ",")
print("}")
