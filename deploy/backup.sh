#!/bin/sh
# Scheduled PostgreSQL backups for the ASM Platform (see docker-compose.backup.yml).
#
# Every run: pg_dump in custom format -> verify the archive can be read back -> write a SHA-256 -> prune old ones.
# A dump only gets its final name after verification, so a half-written or unreadable file is never mistaken for a backup.
#
# Settings (environment):
#   BACKUP_DIR              where dumps go                          (default /backups)
#   BACKUP_INTERVAL_HOURS   hours between backups                   (default 24)
#   BACKUP_KEEP             how many of the newest dumps to keep    (default 14)
#   BACKUP_ONCE=1           take one backup and exit (exit code 1 if it failed)
#   PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE   standard libpq settings
set -eu

DIR="${BACKUP_DIR:-/backups}"
INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
KEEP="${BACKUP_KEEP:-14}"

log() { printf '%s [backup] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

backup_once() {
  mkdir -p "$DIR"
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  part="$DIR/.asm_db_$ts.dump.part"
  final="$DIR/asm_db_$ts.dump"
  if ! pg_dump -F c -f "$part"; then
    rm -f "$part"; log "ERROR: pg_dump failed"; return 1
  fi
  if [ ! -s "$part" ] || ! pg_restore --list "$part" >/dev/null 2>&1; then
    rm -f "$part"; log "ERROR: the dump is empty or unreadable, discarded"; return 1
  fi
  mv "$part" "$final"
  ( cd "$DIR" && sha256sum "asm_db_$ts.dump" > "asm_db_$ts.dump.sha256" )
  size="$(wc -c < "$final" | tr -d ' ')"
  log "ok: asm_db_$ts.dump ($size bytes)"
  prune
}

prune() {
  # newest first; everything after the first KEEP is removed together with its checksum
  ls -1t "$DIR"/asm_db_*.dump 2>/dev/null | tail -n "+$((KEEP + 1))" | while read -r old; do
    rm -f "$old" "$old.sha256"; log "pruned $(basename "$old")"
  done
}

if [ "${BACKUP_ONCE:-0}" = "1" ]; then
  backup_once
  exit $?
fi

log "starting: every ${INTERVAL_HOURS}h into $DIR, keeping the newest $KEEP"
while true; do
  backup_once || log "will retry at the next interval"
  sleep "$((INTERVAL_HOURS * 3600))"
done
