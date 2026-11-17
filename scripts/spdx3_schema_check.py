"""Validate an SPDX 3 JSON-LD document against the official SPDX 3 JSON schema.

Uses jsonschema-rs (Rust engine): the pure-Python validator needed ~24 minutes
for the 15 MB Java image SBOM in CI; this takes under a second for the same work.

Usage: python spdx3_schema_check.py <schema.json> <document.json>
Exit code: 0 = valid, 1 = invalid (errors printed, most frequent first).
"""

import collections
import json
import sys

import jsonschema_rs


def main() -> int:
    schema_path, doc_path = sys.argv[1], sys.argv[2]
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    with open(doc_path, encoding="utf-8") as fh:
        doc = json.load(fh)

    errors = [str(e).splitlines()[0][:300] for e in jsonschema_rs.validator_for(schema).iter_errors(doc)]
    if not errors:
        print("valid")
        return 0
    print(f"ERROR: {len(errors)} schema violation(s)")
    for message, count in collections.Counter(errors).most_common(10):
        print(f"Message: {message} (x{count})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
