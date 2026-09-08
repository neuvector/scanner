#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ghcr-vulndb-artifact.sh publish <artifact-name> <payload-file> <version-file> <version> [ref-file]
  ghcr-vulndb-artifact.sh download <artifact-name> <payload-file> <destination-file> <version> [ref-file]

Environment:
  OCI_REPOSITORY_PREFIX   Defaults to ghcr.io/${GITHUB_REPOSITORY_OWNER}/vul
EOF
}

repo_prefix() {
  if [ -n "${OCI_REPOSITORY_PREFIX:-}" ]; then
    printf '%s\n' "$OCI_REPOSITORY_PREFIX"
    return 0
  fi

  if [ -n "${GITHUB_REPOSITORY_OWNER:-}" ]; then
    printf 'ghcr.io/%s/vul\n' "$GITHUB_REPOSITORY_OWNER"
    return 0
  fi

  echo "OCI_REPOSITORY_PREFIX or GITHUB_REPOSITORY_OWNER is required" >&2
  exit 1
}

default_ref_file() {
  local artifact_name=$1
  printf '.github/vul-refs/%s.ref\n' "$artifact_name"
}

publish_artifact() {
  local artifact_name=$1
  local payload_file=$2
  local version_file=$3
  local version=$4
  local ref_file=${5:-$(default_ref_file "$artifact_name")}
  local prefix
  local repository
  local reference
  local digest
  local latest_digest
  local full_reference
  local temp_dir
  local layer_dir
  local layer_tar
  local payload_basename

  prefix=$(repo_prefix)

  if [ ! -f "$payload_file" ]; then
    echo "Payload file not found: $payload_file" >&2
    exit 1
  fi

  if [ ! -f "$version_file" ]; then
    echo "Version file not found: $version_file" >&2
    exit 1
  fi

  temp_dir=$(mktemp -d)
  trap "rm -rf -- '$temp_dir'" EXIT

  layer_dir="$temp_dir/$artifact_name"
  layer_tar="$temp_dir/${artifact_name}.tar.gz"
  payload_basename=$(basename "$payload_file")

  mkdir -p "$layer_dir/db" "$(dirname "$ref_file")"
  cp "$payload_file" "$layer_dir/db/$payload_basename"
  cp "$version_file" "$layer_dir/db/"

  tar -czf "$layer_tar" -C "$layer_dir" db/

  repository="${prefix}/${artifact_name}"
  reference="${repository}:${version}"

  crane append \
    --new_layer "$layer_tar" \
    --new_tag "$reference" \
    --oci-empty-base

  crane tag "$reference" latest

  digest=$(crane digest "$reference")
  latest_digest=$(crane digest "${repository}:latest")

  if [ "$digest" != "$latest_digest" ]; then
    echo "latest tag verification failed for ${artifact_name}" >&2
    echo "Version digest: $digest" >&2
    echo "Latest digest:  $latest_digest" >&2
    exit 1
  fi

  full_reference="${repository}:${version}@${digest}"

  printf '%s\n' "$full_reference" > "$ref_file"
  echo "Published ${artifact_name} to: $full_reference"
}

download_artifact() {
  local artifact_name=$1
  local payload_file=$2
  local destination_file=$3
  local version=$4
  local ref_file=${5:-$(default_ref_file "$artifact_name")}
  local prefix
  local reference
  local temp_dir
  local temp_tar

  prefix=$(repo_prefix)
  reference="${prefix}/${artifact_name}:${version}"

  if [ -f "$ref_file" ]; then
    reference=$(tr -d '\n' < "$ref_file")
  fi

  temp_dir=$(mktemp -d)
  trap "rm -rf -- '$temp_dir'" EXIT
  temp_tar="$temp_dir/${artifact_name}.tar"

  mkdir -p "$(dirname "$destination_file")"

  crane export "$reference" "$temp_tar"
  tar -xf "$temp_tar" -C "$temp_dir"
  cp "$temp_dir/db/$payload_file" "$destination_file"
}

main() {
  if [ "$#" -lt 1 ]; then
    usage >&2
    exit 1
  fi

  case "$1" in
    publish)
      if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
        usage >&2
        exit 1
      fi
      shift
      publish_artifact "$@"
      ;;
    download)
      if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
        usage >&2
        exit 1
      fi
      shift
      download_artifact "$@"
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
