#!/usr/bin/env bash
set -euo pipefail

# Issue certs needed for client OpenTelemetry otlp exporter tls configuration
#
#     ca_file: ca.pem
#     cert_file: client-cert.pem
#     key_file: client-key.pem
#

shopt -s xpg_echo

SCRIPT=$(basename $0)

USAGE=$(cat <<EOF
usage: \t$SCRIPT [-h] -c <common-name> -r <issuer-role> -x <client-ca-bundle-secret> -V <vault-secret>\n
\t\t[-n <client-ca-bundle-namespace>] [-o <output-tarfile>] [-s <spiffe-uri>] [-t <ttl>]\n
\t\t[-N <vault-namespace>] [-R <ca-issuer-role>] [-T <ca-ttl>]\n
\n
\t-c common name\n
\t-h show usage and exit\n
\t-n namespace of client CA bundle to verify issued certs\n
\t-o output tarfile\n
\t-r vault role for issuing client certificate and private key\n
\t-s spiffe uri\n
\t-t time to live: default 516h\n
\t-x secret for client CA bundle to verify issued certs\n
\t-N vault namespace\n
\t-R vault role for issuing CA, if it differs from client certificates and private key\n
\t-T CA time to live: default 175200h\n
\t-V vault secret\n
\n
Generates a tarfile with the following contents:\n
\tcerts/\n
\t\tca.pem\n
\t\tclient-cert.pem\n
\t\tclient-key.pem\n
\n
You can configure OpenTelemetry otlp exporter tls like this:\n
\tca_file: ca.pem\n
\tcert_file: client-cert.pem\n
\tkey_file: client-key.pem\n
\n
Client CA bundle namespace and secret identify the Kubernetes Secret\n
containing the CA certificate bundle (ca.crt) that the script uses as the\n
trust root when verifying the issued client certificate. This should match\n
the Secret configured for the server endpoint.\n
EOF
)

function usage {
    echo "$1" >&2
    echo "$USAGE" >&2
    exit 1
}

function help {
    echo "$USAGE"
    exit 0
}

OPTIND=1; while getopts ':hc:n:o:r:s:t:x:N:R:T:V:' c; do
    case "$c" in
    h) eval opt_$c=true ;;
    c|n|o|r|s|t|x|N|R|T|V) eval opt_$c="'"$OPTARG"'" ;;
    :) usage "option requires an argument -- $OPTARG" ;;
    *) usage "illegal option -- $OPTARG" ;;
    esac
done
shift $((--OPTIND))

if [[ ${opt_h:-} ]]; then
    help
fi

if [[ -z ${opt_c:-} ]]; then
    usage "missing required option -c <common-name>"
fi
COMMON_NAME="$opt_c"
if [[ -z ${opt_V:-} ]]; then
    usage "missing required option -V <vault-secret>"
fi
VAULT_SECRET="$opt_V"
if [[ -z ${opt_r:-} ]]; then
    usage "missing required option -r <issuer-role>"
fi
ISSUER_ROLE="$opt_r"
if [[ -z ${opt_x:-} ]]; then
    usage "missing required option -x <client-ca-bundle-secret>"
fi
CLIENT_CA_BUNDLE_SECRET="$opt_x"

VAULT_NAMESPACE="${opt_N:-default}"
CLIENT_CA_BUNDLE_NAMESPACE="${opt_n:-default}"
TTL="${opt_t:-516h}"
CA_TTL="${opt_T:-175200h}"
SPIFFE_URI="${opt_s:-}"
OUTPUT_TARFILE="${opt_o:-mtls-certs.tar}"
CA_ISSUER_ROLE="${opt_R:-$ISSUER_ROLE}"

VAULT_TOKEN=$(
    kubectl --namespace "$VAULT_NAMESPACE" \
    get secret "$VAULT_SECRET" -o json | \
    jq -r .data.token | \
    base64 --decode
)

CA_CERTS_FILE=$(mktemp /tmp/ca-certs-XXXXXX.json)
CERTS_FILE=$(mktemp /tmp/client-certs-XXXXXX.json)
CLIENT_CA_BUNDLE=$(mktemp /tmp/client-ca-bundle-XXXXXX.pem)
CERTS_DIR=$(mktemp -d /tmp/certs-XXXXXX)
trap 'rm -rf "$CERTS_DIR" "$CERTS_FILE" "$CA_CERTS_FILE" "$CLIENT_CA_BUNDLE"' EXIT

# Login to Vault inside the pod
kubectl exec vault-0 -c vault -n vault -- \
    vault login -tls-skip-verify "$VAULT_TOKEN"

# Issue cert and capture JSON locally
kubectl exec vault-0 -c vault -n vault -- \
    vault write -tls-skip-verify -format=json \
    "$ISSUER_ROLE" \
    uri_sans="$SPIFFE_URI" \
    common_name="$COMMON_NAME" \
    ttl="$TTL" > "$CERTS_FILE"

# Issue cert and capture JSON locally
kubectl exec vault-0 -c vault -n vault -- \
    vault write -tls-skip-verify -format=json \
    "$CA_ISSUER_ROLE" \
    uri_sans="$SPIFFE_URI" \
    common_name="$COMMON_NAME" \
    ttl="$CA_TTL" > "$CA_CERTS_FILE"

# Get CA bundle from secret for cert validation
kubectl get secret "$CLIENT_CA_BUNDLE_SECRET" -n "$CLIENT_CA_BUNDLE_NAMESPACE" \
    -o jsonpath='{.data.ca\.crt}' | base64 -d > "$CLIENT_CA_BUNDLE"

mkdir -p "$CERTS_DIR"

jq -r '.data.certificate' "$CERTS_FILE" > "$CERTS_DIR/client-cert.pem"
jq -r '.data.private_key' "$CERTS_FILE" > "$CERTS_DIR/client-key.pem"
jq -r '.data.ca_chain[]' "$CA_CERTS_FILE" > "$CERTS_DIR/client-ca-chain.pem"

# Concatenate client cert and CA chain
cat "$CERTS_DIR/client-cert.pem" "$CERTS_DIR/client-ca-chain.pem" \
    > "$CERTS_DIR/client-cert-with-chain.pem"

# Validate the issued certs against the CA bundle
openssl verify -verbose \
  -CAfile "$CLIENT_CA_BUNDLE" \
  -untrusted "$CERTS_DIR/client-ca-chain.pem" \
  "$CERTS_DIR/client-cert.pem"

# Bundle certs in a tar file
rm "$CERTS_DIR/client-cert.pem"
OUTDIR_NAME=certs

mkdir -p "$CERTS_DIR/$OUTDIR_NAME"
mv "$CERTS_DIR/client-ca-chain.pem" "$CERTS_DIR/$OUTDIR_NAME/ca.pem"
mv "$CERTS_DIR/client-cert-with-chain.pem" "$CERTS_DIR/$OUTDIR_NAME/client-cert.pem"
mv "$CERTS_DIR/client-key.pem" "$CERTS_DIR/$OUTDIR_NAME/client-key.pem"

OUTPUT_DIR=$PWD
tar -C "$CERTS_DIR" -cf "$OUTPUT_DIR"/"$OUTPUT_TARFILE" "$OUTDIR_NAME"
echo "Wrote $OUTPUT_TARFILE"
