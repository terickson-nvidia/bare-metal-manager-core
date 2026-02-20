#!/usr/bin/env bash
set -euo pipefail

#
# Parses the give JSON configuration file and calls issue_certs.sh with the
# parsed option values. The config file should have this structure:
#
# {
#   "client-ca-bundle-secret": "<required>",
#   "common-name": "<required>",
#   "issuer-role": "<required>",
#   "vault-secret": "<required>",
#
#   "client-ca-bundle-namespace": "<optional>"
#   "ca-issuer-role": "<optional>",
#   "ca-ttl": "<optional>",
#   "spiffe-uri": "<optional>",
#   "ttl": "<optional>",
#   "vault-namespace": "<optional>",
# }
#

CONFIG_FILE=${1:-}

if [[ -z "$CONFIG_FILE" ]]; then
  echo "Usage: $(basename "$0") <config.json>" >&2
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
fi

# Extract fields from JSON (empty string if key is missing or null)
SPIFFE_URI=$(jq -r '."spiffe-uri" // ""' "$CONFIG_FILE")
VAULT_NAMESPACE=$(jq -r '."vault-namespace" // ""' "$CONFIG_FILE")
VAULT_SECRET=$(jq -r '."vault-secret" // ""' "$CONFIG_FILE")
ISSUER_ROLE=$(jq -r '."issuer-role" // ""' "$CONFIG_FILE")
CA_ISSUER_ROLE=$(jq -r '."ca-issuer-role" // ""' "$CONFIG_FILE")
COMMON_NAME=$(jq -r '."common-name" // ""' "$CONFIG_FILE")
TTL=$(jq -r '."ttl" // ""' "$CONFIG_FILE")
CA_TTL=$(jq -r '."ca-ttl" // ""' "$CONFIG_FILE")
CLIENT_CA_BUNDLE_SECRET=$(jq -r '."client-ca-bundle-secret" // ""' "$CONFIG_FILE")
CLIENT_CA_BUNDLE_NAMESPACE=$(jq -r '."client-ca-bundle-namespace" // ""' "$CONFIG_FILE")

# Build argument list for issue_certs.sh
args=()

# Required options
if [[ -z "$COMMON_NAME" ]]; then
  echo "Config error: \"common-name\" is required" >&2
  exit 1
fi
args+=(-c "$COMMON_NAME")

if [[ -z "$VAULT_SECRET" ]]; then
  echo "Config error: \"vault-secret\" is required" >&2
  exit 1
fi
args+=(-V "$VAULT_SECRET")

if [[ -z "$ISSUER_ROLE" ]]; then
  echo "Config error: \"issuer-role\" is required" >&2
  exit 1
fi
args+=(-r "$ISSUER_ROLE")

if [[ -z "$CLIENT_CA_BUNDLE_SECRET" ]]; then
  echo "Config error: \"client-ca-bundle-secret\" is required" >&2
  exit 1
fi
args+=(-x "$CLIENT_CA_BUNDLE_SECRET")

# Optional options: only add if non-empty
if [[ -n "$SPIFFE_URI" ]]; then
  args+=(-s "$SPIFFE_URI")
fi

if [[ -n "$VAULT_NAMESPACE" ]]; then
  args+=(-N "$VAULT_NAMESPACE")
fi

if [[ -n "$CA_ISSUER_ROLE" ]]; then
  args+=(-R "$CA_ISSUER_ROLE")
fi

if [[ -n "$TTL" ]]; then
  args+=(-t "$TTL")
fi

if [[ -n "$CA_TTL" ]]; then
  args+=(-T "$CA_TTL")
fi

if [[ -n "$CLIENT_CA_BUNDLE_NAMESPACE" ]]; then
  args+=(-n "$CLIENT_CA_BUNDLE_NAMESPACE")
fi

# Call issue_certs.sh in the same directory as this wrapper, or rely on $PATH
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
"$SCRIPT_DIR/issue_certs.sh" "${args[@]}"
