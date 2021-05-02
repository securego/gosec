#!/bin/bash -e

go install github.com/a-h/generate

schema-generate -i schema/sarif-schema-2.1.0.json -p sarif -o sarif/types.go