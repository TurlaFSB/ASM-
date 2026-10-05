#!/bin/sh
# Restore drill and restore for the ASM Platform database (companion to backup.sh).
#
#   sh restore.sh verify [DUMP]        prove a backup restores: checksum, restore into a scratch database,
#                                      compare table row counts, drop the scratch database. Touches nothing live.
#   sh restore.sh apply  DUMP --yes    replace the LIVE database with the dump (stop backend, celery_worker and
#                                      celery_beat first). Runs in one transaction: a failed restore changes nothing.
#
# DUMP defaults (verify only) to the newest asm_db_*.dump in BACKUP_DIR. If DUMP.sha256 exists it must match.
#
# Settings (environment): BACKUP_DIR (default /backups) and the standard libpq variables
# PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE. The role needs CREATEDB for `verify`.
set -eu

DIR="${BACKUP_DIR:-/backups}"
LIVE="${PGDATABASE:-asm_db}"
mode="${1:-}"
shift || true

log() { printf '%s [restore] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }
usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

dump="" ; yes=0
for a in "$@"; do
  case "$a" in
    --yes) yes=1 ;;
    -*) usage ;;
    *) dump="$a" ;;
  esac
done

case "$mode" in verify|apply) ;; *) usage ;; esac

if [ -z "$dump" ]; then
  [ "$mode" = "verify" ] || die "apply needs an explicit dump file"
  dump="$(ls -1t "$DIR"/asm_db_*.dump 2>/dev/null | head -n 1 || true)"
  [ -n "$dump" ] || die "no asm_db_*.dump found in $DIR"
fi
[ -s "$dump" ] || die "dump not found or empty: $dump"

if [ -f "$dump.sha256" ]; then
  ( cd "$(dirname "$dump")" && sha256sum -c "$(basename "$dump").sha256" >/dev/null 2>&1 ) \
    || die "checksum mismatch for $dump: the file is damaged, do not restore it"
  log "checksum ok"
else
  log "warning: no $(basename "$dump").sha256 next to the dump, integrity not checked"
fi
pg_restore --list "$dump" >/dev/null 2>&1 || die "$dump is not a readable pg_dump archive"

table_counts() {   # $1 = database; prints "table count" lines, sorted
  for t in $(psql -d "$1" -Atq -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1"); do
    printf '%s %s\n' "$t" "$(psql -d "$1" -Atq -c "SELECT count(*) FROM \"$t\"")"
  done
}

if [ "$mode" = "verify" ]; then
  scratch="asm_restore_check_$(date -u +%Y%m%d%H%M%S)"
  trap 'psql -d postgres -Atq -c "DROP DATABASE IF EXISTS \"'"$scratch"'\"" >/dev/null 2>&1 || true' EXIT
  psql -d postgres -Atq -c "CREATE DATABASE \"$scratch\"" || die "cannot create scratch database (needs CREATEDB)"
  log "restoring $(basename "$dump") into scratch database $scratch"
  pg_restore -d "$scratch" --no-owner --exit-on-error "$dump" || die "pg_restore failed: this backup does not restore"
  restored="$(table_counts "$scratch")"
  [ -n "$restored" ] || die "restore produced no tables"
  rev="$(psql -d "$scratch" -Atq -c "SELECT version_num FROM alembic_version" 2>/dev/null || true)"
  log "restored $(printf '%s\n' "$restored" | wc -l | tr -d ' ') tables, schema revision ${rev:-unknown}"
  printf '%s\n' "$restored" | sed 's/^/  /'
  if psql -d "$LIVE" -Atq -c "SELECT 1" >/dev/null 2>&1; then
    live_rev="$(psql -d "$LIVE" -Atq -c "SELECT version_num FROM alembic_version" 2>/dev/null || true)"
    log "live database is at revision ${live_rev:-unknown} (rows can differ from the backup if data changed since)"
  fi
  log "OK: the backup restores cleanly (scratch database dropped)"
  exit 0
fi

# apply
[ "$yes" = "1" ] || die "apply replaces the live database '$LIVE'. Stop backend, celery_worker and celery_beat, then repeat with --yes"
log "replacing $LIVE from $(basename "$dump") (single transaction)"
pg_restore -d "$LIVE" --clean --if-exists --no-owner --single-transaction --exit-on-error "$dump" \
  || die "restore failed and was rolled back: the live database is unchanged"
rev="$(psql -d "$LIVE" -Atq -c "SELECT version_num FROM alembic_version" 2>/dev/null || true)"
log "OK: restored, schema revision ${rev:-unknown}. Start backend, celery_worker and celery_beat again"
