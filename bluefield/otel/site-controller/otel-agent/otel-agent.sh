#!/bin/sh

# Build and run the containerized otel-agent to renew mTLS certs for the
# OpenTelemetry collector.

set -e

CARBIDE_API=carbide-api.forge
CARBIDE_API_IP_ADDR=$(getent hosts $CARBIDE_API | awk '{print $1}')

if [ $? -ne 0 ] || [ -z "$CARBIDE_API_IP_ADDR" ]; then
    echo "Failed to resolve $CARBIDE_API" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d /tmp/otel-agent-build.XXXXXX)
trap 'rm -rf "$BUILD_DIR"' EXIT

OTEL_AGENT=/usr/bin/otel-agent
DOCKERFILE=/usr/share/otelcol-contrib/docker/otel-agent/Dockerfile

if [ ! -f "$OTEL_AGENT" ]; then
    echo "Expected $OTEL_AGENT is missing" >&2
    exit 1
fi

if [ ! -f "$DOCKERFILE" ]; then
    echo "Expected $DOCKERFILE is missing" >&2
    exit 1
fi

cp "$OTEL_AGENT" "$BUILD_DIR"/
cp "$DOCKERFILE" "$BUILD_DIR"/
docker build -t otel-agent "$BUILD_DIR"/
ip vrf exec mgmt docker run --rm \
        --name otel-agent \
        --network host \
        --add-host ${CARBIDE_API}:${CARBIDE_API_IP_ADDR} \
        --mount type=bind,source=/etc/otelcol-contrib/certs,target=/etc/otelcol-contrib/certs \
        --mount type=bind,source=/etc/otelcol-contrib/otel-agent.toml,target=/config/config.toml,readonly \
        otel-agent --config-path /config/config.toml run
