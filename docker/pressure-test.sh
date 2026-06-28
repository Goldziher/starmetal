#!/usr/bin/env bash
set -euo pipefail

for dependency in curl docker jq; do
  if ! command -v "${dependency}" >/dev/null 2>&1; then
    echo "missing required command: ${dependency}" >&2
    exit 1
  fi
done

image="${SM_PRESSURE_IMAGE:-starmetal:local}"
inspect_image="${SM_PRESSURE_INSPECT_IMAGE:-cgr.dev/chainguard/busybox:latest}"
port="${SM_PRESSURE_PORT:-18080}"
base_url="http://127.0.0.1:${port}"
container="starmetal-pressure-${RANDOM}-${RANDOM}"
volume="starmetal-pressure-data-${RANDOM}-${RANDOM}"
tmp_dir="$(mktemp -d)"

cleanup() {
  docker logs "${container}" >"${tmp_dir}/container.log" 2>&1 || true
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker volume rm "${volume}" >/dev/null 2>&1 || true
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

run_burst() {
  local label="$1"
  local total="$2"
  local concurrency="$3"
  shift 3

  local failures="${tmp_dir}/${label}.failures"
  : >"${failures}"

  for request in $(seq 1 "${total}"); do
    (curl -fsS "$@" -o /dev/null || echo "${label} request ${request}" >>"${failures}") &
    if ((request % concurrency == 0)); then
      wait || true
    fi
  done
  wait || true

  if [[ -s "${failures}" ]]; then
    cat "${failures}" >&2
    return 1
  fi
}

docker rm -f "${container}" >/dev/null 2>&1 || true
docker volume rm "${volume}" >/dev/null 2>&1 || true

docker run \
  --detach \
  --name "${container}" \
  --publish "127.0.0.1:${port}:8080" \
  --volume "${volume}:/var/lib/starmetal" \
  "${image}" >/dev/null

for attempt in $(seq 1 30); do
  if curl -fsS "${base_url}/pypi/simple/" >"${tmp_dir}/index.html" 2>"${tmp_dir}/curl.err"; then
    break
  fi
  if [[ "${attempt}" == "30" ]]; then
    cat "${tmp_dir}/curl.err" >&2 || true
    docker logs "${container}" >&2 || true
    exit 1
  fi
  sleep 1
done

curl -fsS \
  -H "Accept: application/vnd.pypi.simple.v1+json" \
  "${base_url}/pypi/simple/six/" >"${tmp_dir}/six.json"
jq -e '.name == "six" and (.files | length) > 0' "${tmp_dir}/six.json" >/dev/null

curl -fsS \
  "${base_url}/pypi/packages/six/1.16.0/six-1.16.0.tar.gz" \
  >"${tmp_dir}/six-1.16.0.tar.gz"
artifact_bytes="$(wc -c <"${tmp_dir}/six-1.16.0.tar.gz" | tr -d ' ')"
if [[ "${artifact_bytes}" -le 10000 ]]; then
  echo "cached artifact is unexpectedly small: ${artifact_bytes} bytes" >&2
  exit 1
fi

run_burst pypi-index 100 20 "${base_url}/pypi/simple/"
run_burst pypi-six-json 60 15 \
  -H "Accept: application/vnd.pypi.simple.v1+json" \
  "${base_url}/pypi/simple/six/"
run_burst pypi-six-artifact 40 10 \
  "${base_url}/pypi/packages/six/1.16.0/six-1.16.0.tar.gz"

docker run \
  --rm \
  --volume "${volume}:/data:ro" \
  --entrypoint /bin/sh \
  "${inspect_image}" \
  -c 'find /data -maxdepth 5 -type f | sort' >"${tmp_dir}/stored-files.txt"

grep -Eq '/six-1\.16\.0\.tar\.gz$' "${tmp_dir}/stored-files.txt"
grep -Eq '/six-1\.16\.0\.tar\.gz\.blake3$' "${tmp_dir}/stored-files.txt"
grep -Eq '/six/_raw_upstream$' "${tmp_dir}/stored-files.txt"

docker image inspect "${image}" \
  --format 'user={{json .Config.User}} entrypoint={{json .Config.Entrypoint}} cmd={{json .Config.Cmd}}' \
  >"${tmp_dir}/image.txt"
grep -F 'user="65532:65532"' "${tmp_dir}/image.txt" >/dev/null
grep -F 'entrypoint=["/usr/local/bin/sm"]' "${tmp_dir}/image.txt" >/dev/null
grep -F 'cmd=["serve"]' "${tmp_dir}/image.txt" >/dev/null

echo "pressure test passed"
cat "${tmp_dir}/image.txt"
echo "stored files:"
sed -n '1,40p' "${tmp_dir}/stored-files.txt"
