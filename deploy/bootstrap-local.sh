#!/bin/sh
# Build ASP images from this checkout and deploy the Compose stack on this host.
# Use this instead of deploy/asp-compose/scripts/init.sh when no published GHCR
# images exist for the repository, for example a fork or an air-gapped host.
#
# Run it from a shell that can reach Docker, such as WSL or a Linux host.
set -eu

skip_build=false
skip_seed=false

usage() {
    cat <<'EOF'
Usage: deploy/bootstrap-local.sh [--skip-build] [--skip-seed]

  --skip-build  Reuse existing asp-backend:local and asp-frontend:local images.
  --skip-seed   Do not load SOC automation rules and branding.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-build) skip_build=true; shift ;;
        --skip-seed) skip_seed=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not available in this shell." >&2
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose v2 is not available in this shell." >&2
    exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
deployment="$root/deploy/asp-compose"
backend_image="asp-backend:local"
frontend_image="asp-frontend:local"
branding_fixture="$root/deploy/fixtures/shb-branding"

if [ "$skip_build" = false ]; then
    docker build -t "$backend_image" "$root/backend"
    docker build -t "$frontend_image" "$root/frontend"
fi

cd "$deployment"

mkdir -p \
    certs \
    custom/data/modules \
    custom/data/playbooks \
    custom/data/siem \
    custom/modules \
    custom/playbooks \
    logs/nginx

if [ ! -e custom/requirements.txt ]; then
    cat > custom/requirements.txt <<'EOF'
# Add Python packages required by custom Module or Playbook scripts.
# Example:
# requests==2.32.5
EOF
fi

if [ ! -e compose.override.yaml ]; then
    cat > compose.override.yaml <<'EOF'
# User-managed Docker Compose overrides.
# ASP upgrades never overwrite this file.
# Keep supported passwords, ports, and image settings in .env.
services: {}
EOF
fi

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import secrets; print(secrets.token_hex(32))'
        return
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

set_env_value() {
    key="$1"
    value="$2"
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        printf '%s=%s\n' "$key" "$value" >> .env
    fi
}

if [ ! -f .env ]; then
    cp .env.example .env

    set_env_value DJANGO_SECRET_KEY "$(generate_secret)"
    set_env_value POSTGRES_PASSWORD "$(generate_secret)"
    set_env_value REDIS_PASSWORD "$(generate_secret)"
    set_env_value RUSTFS_SECRET_KEY "$(generate_secret)"

    # Images are built locally, so the published GHCR tags do not apply.
    set_env_value ASP_BACKEND_IMAGE "$backend_image"
    set_env_value ASP_FRONTEND_IMAGE "$frontend_image"

    # Sizing for a small single host. Raise these on a larger server.
    set_env_value ASP_WEB_WORKERS 2
    set_env_value POSTGRES_MAX_CONNECTIONS 100
    set_env_value POSTGRES_SHARED_BUFFERS 256MB
    set_env_value POSTGRES_EFFECTIVE_CACHE_SIZE 1GB
    set_env_value POSTGRES_MAINTENANCE_WORK_MEM 128MB

    echo "Generated .env with random service secrets. Review .env before exposing the deployment."
fi

if grep -Eq '^(DJANGO_SECRET_KEY|POSTGRES_PASSWORD|REDIS_PASSWORD|RUSTFS_SECRET_KEY)=change-me' .env; then
    echo "Refusing to initialize with placeholder secrets in .env. Delete .env to regenerate or update the values manually." >&2
    exit 1
fi

# Branding fixtures reach the containers through the ./custom bind mount.
if [ "$skip_seed" = false ] && [ -d "$branding_fixture" ]; then
    mkdir -p custom/fixtures
    cp -a "$branding_fixture" custom/fixtures/
fi

chmod +x scripts/*.sh

# Third-party images still come from a registry. The locally built ASP images
# have no registry to pull from, so their pull failures are expected.
docker compose pull --ignore-pull-failures

docker compose run --rm asp-migrate

if [ "$skip_seed" = false ]; then
    docker compose run --rm asp-web python manage.py seed_soc_automation
    if [ -d custom/fixtures/shb-branding ]; then
        docker compose run --rm asp-web \
            python manage.py seed_branding --fixture-dir /app/custom/fixtures/shb-branding
    fi
fi

docker compose up -d

echo
echo "ASP is starting. Verify the deployment:"
echo "  cd deploy/asp-compose && ./scripts/doctor.sh"
echo "Create an administrator:"
echo "  cd deploy/asp-compose && docker compose exec asp-web python manage.py createsuperuser"
