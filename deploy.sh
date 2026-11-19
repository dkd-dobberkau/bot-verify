#!/usr/bin/env bash
#
# Build, push and deploy bot-verify to Mittwald container hosting.
#
# Usage:
#   ./deploy.sh              # tags as <short-sha> (+ latest)
#   ./deploy.sh v0.2.0       # tags as v0.2.0 (+ latest)
#
# Requires: docker (buildx), gh (authed), mw (authed), python3, curl

set -euo pipefail

IMAGE="ghcr.io/dkd-dobberkau/bot-verify"
SERVICE="bot-verify"
BASE_URL="https://verify.goodbot-badbot.com"

if [[ ! -f .deploy.env ]]; then
  echo "ERROR: .deploy.env not found. Copy .deploy.env.example and fill in." >&2
  exit 1
fi
set -a
# shellcheck source=/dev/null
. .deploy.env
set +a
: "${STACK_ID:?STACK_ID missing from .deploy.env}"
: "${PROJECT_ID:?PROJECT_ID missing from .deploy.env}"

if [[ $# -ge 1 ]]; then
  TAG="$1"
else
  TAG="$(git rev-parse --short HEAD)"
  # The image is built from the working tree, so say when it is not HEAD.
  [[ -z "$(git status --porcelain)" ]] || TAG="${TAG}-dirty"
fi

command -v docker  >/dev/null || { echo "ERROR: docker not found";  exit 1; }
command -v gh      >/dev/null || { echo "ERROR: gh not found";      exit 1; }
command -v mw      >/dev/null || { echo "ERROR: mw not found";      exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found"; exit 1; }
command -v curl    >/dev/null || { echo "ERROR: curl not found";    exit 1; }

echo "Deploying ${IMAGE}:${TAG}"

# The project holds containers of several stacks, so a container is picked by
# stack and service name, never by its position in the list.
container_id() {
  local stack="$1" service="$2"
  mw container list --project-id "${PROJECT_ID}" --output json \
    | python3 -c 'import sys, json
stack, service = sys.argv[1], sys.argv[2]
ids = [c["shortId"] for c in json.load(sys.stdin)
       if c["stackId"] == stack and c["serviceName"] == service]
print(ids[0] if ids else "")' "${stack}" "${service}"
}

echo "[1/4] Login to ghcr.io"
gh auth token | docker login ghcr.io -u dkd-dobberkau --password-stdin >/dev/null

echo "[2/4] Build linux/amd64 and push (${TAG} + latest)"
docker buildx build \
  --platform linux/amd64 \
  --build-arg "VERSION=${TAG}" \
  -t "${IMAGE}:${TAG}" \
  -t "${IMAGE}:latest" \
  --push .

echo "[3/4] Deploy stack and recreate container"
ENV_FILE="$(mktemp -t deploy.env.XXXX)"
trap 'rm -f "${ENV_FILE}"' EXIT
echo "VERSION=${TAG}" > "${ENV_FILE}"
mw stack deploy --stack-id "${STACK_ID}" -c docker-compose.mittwald.yml --env-file "${ENV_FILE}"

# Mittwald's reported image can name the new tag while the old code still
# runs, and a stack deploy does not always pull. Recreate, then trust only the
# version the process logs at start.
CID="$(container_id "${STACK_ID}" "${SERVICE}")"
[[ -n "${CID}" ]] || { echo "ERROR: no ${SERVICE} container in stack ${STACK_ID}" >&2; exit 1; }
for attempt in 1 2 3; do
  if mw container recreate "${CID}" --project-id "${PROJECT_ID}" --force; then
    break
  fi
  (( attempt < 3 )) || { echo "ERROR: recreate failed after 3 attempts" >&2; exit 1; }
  echo "  recreate attempt ${attempt} failed, retrying in $((attempt * 5))s..."
  sleep $((attempt * 5))
done
CID="$(container_id "${STACK_ID}" "${SERVICE}")"

echo "  waiting for the container to log version ${TAG}..."
LIVE=""
for _ in $(seq 1 30); do
  LIVE="$(mw container logs "${CID}" --project-id "${PROJECT_ID}" --no-pager 2>/dev/null \
    | python3 -c 'import sys, json
version = ""
for line in sys.stdin:
    # Mittwald prefixes each line with its own timestamp.
    try:
        entry = json.loads(line[line.find("{"):])
    except ValueError:
        continue
    if entry.get("msg") == "starting":
        version = entry.get("version", "")
print(version)' || true)"
  [[ "${LIVE}" == "${TAG}" ]] && break
  sleep 2
done
if [[ "${LIVE}" != "${TAG}" ]]; then
  echo "ERROR: container logs version '${LIVE:-<none>}', expected '${TAG}'" >&2
  exit 1
fi

# Through the public domain, so the check covers the ingress and its
# certificate too.
echo "[4/4] Health check at ${BASE_URL}"
HEALTH=""
for _ in $(seq 1 12); do
  HEALTH="$(curl -s --max-time 10 "${BASE_URL}/healthz" || true)"
  [[ "${HEALTH}" == *'"status":"ok"'* ]] && break
  sleep 3
done
if [[ "${HEALTH}" != *'"status":"ok"'* ]]; then
  echo "FAIL: ${BASE_URL}/healthz did not answer ok"
  mw container logs "${CID}" --project-id "${PROJECT_ID}" --no-pager 2>/dev/null | tail -30 || true
  exit 1
fi

echo "Live: ${BASE_URL} (${IMAGE}:${TAG})"
echo "  ${HEALTH}"
