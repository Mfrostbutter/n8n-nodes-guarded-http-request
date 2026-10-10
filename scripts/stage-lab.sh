#!/usr/bin/env bash
# Build and stage the package for a mounted N8N_CUSTOM_EXTENSIONS directory.
# Only package.json and dist/ are staged, so the node resolves n8n-workflow from the
# instance, not from this repo's node_modules.
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build >/dev/null
stage=".lab-stage/n8n-nodes-guarded-http-request"
rm -rf "$stage"
mkdir -p "$stage"
cp package.json "$stage/"
cp -R dist "$stage/dist"
echo "staged $(find "$stage" -type f | wc -l | tr -d ' ') files in $stage"
