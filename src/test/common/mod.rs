use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub fn truelog(directory: &Path) -> PathBuf {
    let executable = directory.join("ab-truelog-cli");
    std::fs::write(&executable, r#"#!/bin/sh
[ "$1" = write ] && [ "$2" = --service ] && [ "$3" = abpkid ] && [ "$4" = --data ] || exit 2
printf '%s\n' "$5" >> "$0.events" || exit 3
printf '%s\n' '{"hostname":"fixture","service":"abpkid","before":{"file":"truelog-2026-09-27.log","filesize":0,"checksum":"before"},"after":{"file":"truelog-2026-09-27.log","filesize":128,"checksum":"after"}}'
"#).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    executable
}
