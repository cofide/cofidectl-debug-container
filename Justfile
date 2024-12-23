
set export
set shell := ["bash", "-euo", "pipefail", "-c"]

export KO_DOCKER_REPO := env_var_or_default("KO_DOCKER_REPO", "kind.local")
export KIND_CLUSTER_NAME := env_var_or_default("KIND_CLUSTER_NAME", "kind")
export KO_TAG := env_var_or_default("KO_TAG", "latest")

lint *args:
    golangci-lint run --show-stats {{args}}

check-deps:
    # Check for demo script dependencies
    for cmd in ko kubectl; do \
        if ! command -v $cmd &> /dev/null; then \
            echo "Error: $cmd is not installed" >&2; \
            exit 1; \
        fi \
    done
    echo "All dependencies installed"

# Build
build: check-deps
    ko build github.com/cofide/cofidectl-debug-container

# Build application
build-release: check-deps
    ko build --bare --tags="$KO_TAG" github.com/cofide/cofidectl-debug-container
