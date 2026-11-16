#!/bin/sh
# Print the labels for a pull request, or create those labels.
# File list on stdin: status<TAB>path
# Status is added, modified, removed, renamed, copied, or changed.
set -eu

catalog() {
	cat <<'EOF'
docs|0075ca|Documentation and other Markdown
tests-added|0e8a16|New test files
tests-updated|c2e0c6|Changes to existing tests
core|5319e7|Server, service, and repository code
flows|fbca04|OAuth grant and authorization flows
db-updates|d93f0b|Migrations and the database layer
openapi-changes|006b75|OpenAPI specification
e2e|bfd4f2|Browser end-to-end suite
frontend|e99695|HTML templates and brand assets
api|1d76db|HTTP controllers and routes
ci|c5def5|GitHub Actions and automation
config|fef2c0|Server configuration
oauth|0052cc|OAuth handlers and protocol helpers
hashalgos|b60205|Password hashers
oidc|6f42c1|OpenID Connect
cli|cfd3d7|atrium-cli and atrium-mobile
docker|0db7ed|Container image and deploy files
mail|f9d0c4|Mail delivery and templates
push|ffa657|Push approval
aauth|d4c5f9|AAuth discovery
telemetry|0e8a16|Logs and traces
queue|fbca04|Queue, cache, and notifications
EOF
}

is_test() {
	case "$1" in
	*_test.go | *.test.js) return 0 ;;
	*) return 1 ;;
	esac
}

add() {
	printf '%s\n' "$1" >> "$labels"
}

label_path() {
	path=$1
	case "$path" in
	docs/* | *.md) add docs ;;
	esac
	case "$path" in
	migrations/* | internal/database/*) add db-updates ;;
	esac
	case "$path" in
	openapi/*) add openapi-changes ;;
	esac
	case "$path" in
	e2e/*) add e2e ;;
	esac
	case "$path" in
	internal/templates/* | internal/branding/* | docs/brand/*) add frontend ;;
	esac
	case "$path" in
	internal/controller/* | internal/route/* | internal/auth/*) add api ;;
	esac
	case "$path" in
	.github/*) add ci ;;
	esac
	case "$path" in
	internal/config/* | config.yaml | deploy/* | docs/CONFIG.md) add config ;;
	esac
	case "$path" in
	internal/handlers/oauth/* | pkg/crypto/*) add oauth ;;
	esac
	case "$path" in
	internal/handlers/oauth/grant_* | internal/handlers/oauth/device.go | internal/handlers/oauth/ciba.go | internal/handlers/oauth/authorize.go | internal/handlers/oauth/par.go) add flows ;;
	esac
	case "$path" in
	internal/hashalgo/* | pkg/passhash/*) add hashalgos ;;
	esac
	case "$path" in
	internal/oidc/*) add oidc ;;
	esac
	case "$path" in
	cmd/atrium-cli/* | cmd/atrium-mobile/*) add cli ;;
	esac
	case "$path" in
	Dockerfile | Dockerfile.* | .dockerignore | deploy/*) add docker ;;
	esac
	case "$path" in
	internal/mailer/*) add mail ;;
	esac
	case "$path" in
	internal/push/*) add push ;;
	esac
	case "$path" in
	internal/aauth/*) add aauth ;;
	esac
	case "$path" in
	internal/telemetry/* | internal/log/*) add telemetry ;;
	esac
	case "$path" in
	internal/queue/* | internal/notify/* | internal/cache/*) add queue ;;
	esac
	case "$path" in
	cmd/atrium/* | internal/app/* | internal/server/* | internal/service/* | internal/repository/* | internal/models/*) add core ;;
	esac
}

if [ "${1:-}" = "--ensure" ]; then
	catalog | while IFS='|' read -r name color description; do
		gh label create "$name" --color "$color" --description "$description" --force >/dev/null
	done
	exit 0
fi

labels=$(mktemp)
trap 'rm -f "$labels"' EXIT

while IFS='	' read -r status path; do
	[ -n "$path" ] || continue
	label_path "$path"
	if is_test "$path"; then
		case "$status" in
		added | copied) add tests-added ;;
		*) add tests-updated ;;
		esac
	fi
done

sort -u "$labels"
