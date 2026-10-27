#!/bin/sh
# Print the next preview tag for VERSION. Pass --push to tag HEAD and
# push that tag. Logs go to stderr. The tag name is the only stdout.
set -eu

push=0
if [ "${1:-}" = "--push" ]; then
	push=1
elif [ -n "${1:-}" ]; then
	echo "usage: next-preview-tag.sh [--push]" >&2
	exit 2
fi

cd "$(git rev-parse --show-toplevel)"
version=$(tr -d '[:space:]' < VERSION)
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
	echo "VERSION must be X.Y.Z" >&2
	exit 1
}

sha=$(git rev-parse HEAD)
remote=$(git ls-remote --tags origin)
names=$(printf '%s\n' "$remote" | awk '{ print $2 }' | sed 's#refs/tags/##; s/\^{}$//')

if printf '%s\n' "$remote" | awk -v sha="$sha" '$1 == sha { print $2 }' | sed 's#refs/tags/##; s/\^{}$//' | grep -Eq '^v[0-9]'; then
	echo "Commit ${sha} already has a release tag." >&2
	exit 0
fi

if printf '%s\n' "$names" | grep -qx "v${version}"; then
	echo "v${version} already exists. Bump VERSION to the next release line." >&2
	exit 1
fi

highest_rc() {
	highest=0
	prefix="v${version}-rc."
	old=$IFS
	IFS='
'
	for name in $names; do
		case "$name" in
		"$prefix"*)
			n=${name#"$prefix"}
			case "$n" in
			'' | *[!0-9]*) continue ;;
			esac
			if [ "$n" -gt "$highest" ]; then
				highest=$n
			fi
			;;
		esac
	done
	IFS=$old
	printf '%s\n' "$highest"
}

attempt=0
highest=$(highest_rc)
while [ "$attempt" -lt 3 ]; do
	attempt=$((attempt + 1))
	next=$((highest + 1))
	tag="v${version}-rc.${next}"
	if [ "$push" -eq 0 ]; then
		printf '%s\n' "$tag"
		exit 0
	fi
	git tag "$tag" "$sha"
	if git push origin "refs/tags/${tag}" >&2; then
		printf '%s\n' "$tag"
		exit 0
	fi
	git tag -d "$tag" >/dev/null 2>&1 || true
	echo "Tag ${tag} was taken. Trying the next number." >&2
	remote=$(git ls-remote --tags origin)
	names=$(printf '%s\n' "$remote" | awk '{ print $2 }' | sed 's#refs/tags/##; s/\^{}$//')
	highest=$(highest_rc)
done

echo "Could not push a preview tag." >&2
exit 1
