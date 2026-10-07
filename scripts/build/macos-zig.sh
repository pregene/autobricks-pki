#!/usr/bin/env bash
set -euo pipefail
# Zig requires the OS version in its target triple for deployment metadata.
arguments=()
for argument in "$@"; do
    case "$argument" in
        aarch64-macos-none) argument=aarch64-macos.11.0-none ;;
        x86_64-macos-none) argument=x86_64-macos.11.0-none ;;
    esac
    arguments+=("$argument")
done
exec "${ABPKI_MACOS_ZIG:?Set ABPKI_MACOS_ZIG to the Zig executable}" "${arguments[@]}"
