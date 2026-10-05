#!/bin/sh
set -eu

case "${1-}" in
    --check|--write) mode=$1; shift ;;
    *) printf '%s\n' 'usage: sync-authmux-skill.sh <--check|--write> <skill-directory> [...]' >&2; exit 2 ;;
esac
if [ "$#" -eq 0 ]; then
    printf '%s\n' 'at least one skill directory is required' >&2
    exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_file="$repo_root/integrations/skills/authmux/SKILL.md"
result=0
index=0
for skill_directory do
    index=$((index + 1))
    target_file="$skill_directory/SKILL.md"
    if cmp -s "$source_file" "$target_file"; then
        printf 'skill %s matches\n' "$index"
    elif [ "$mode" = '--write' ]; then
        mkdir -p -- "$skill_directory"
        cp -- "$source_file" "$target_file"
        cmp -s "$source_file" "$target_file"
        printf 'skill %s synchronized\n' "$index"
    else
        printf 'skill %s differs or is missing; review changes before running --write\n' "$index" >&2
        result=1
    fi
done
exit "$result"
