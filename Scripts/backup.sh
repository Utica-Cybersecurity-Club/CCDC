#!/bin/bash

# to run automatically with cron
# 0 2 * * * /path/to/backup.sh


set -euo pipefail

# -------- CONFIG --------

files_to_backup=(
    "/etc/default/grub"
    "/etc/ssh/sshd_config"
    "/etc/pam.d/common-password"
    "/etc/login.defs"
    "/etc/sysctl.conf"
)

LOCAL_BACKUP_DIR="/var/backups"
LOG_FILE="/var/log/config-backup.log"

REMOTE_USER="backupuser"
REMOTE_HOST="backup.example.com"
REMOTE_DIR="/backups/linux"

# -------- END CONFIG --------

TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
ARCHIVE_NAME="config-backup-${TIMESTAMP}.tar.gz"
CHECKSUM_NAME="${ARCHIVE_NAME}.sha256"

ARCHIVE_PATH="${LOCAL_BACKUP_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${LOCAL_BACKUP_DIR}/${CHECKSUM_NAME}"

mkdir -p "${LOCAL_BACKUP_DIR}"
touch "${LOG_FILE}"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${LOG_FILE}"
}

log "Starting backup job"

# Create tarball
tar -czf "${ARCHIVE_PATH}" "${files_to_backup[@]}"
log "Created archive ${ARCHIVE_NAME}"

# Generate checksum
sha256sum "${ARCHIVE_PATH}" > "${CHECKSUM_PATH}"
NEW_HASH="$(cut -d ' ' -f1 "${CHECKSUM_PATH}")"
log "Generated SHA256: ${NEW_HASH}"

# Deduplication: remove older backups with same checksum
for old_checksum in "${LOCAL_BACKUP_DIR}"/config-backup-*.tar.gz.sha256; do
    [[ "$old_checksum" == "$CHECKSUM_PATH" ]] && continue

    OLD_HASH="$(cut -d ' ' -f1 "$old_checksum")"

    if [[ "$OLD_HASH" == "$NEW_HASH" ]]; then
        OLD_ARCHIVE="${old_checksum%.sha256}"
        rm -f "$old_checksum" "$OLD_ARCHIVE"
        log "Removed duplicate backup: $(basename "$OLD_ARCHIVE")"
    fi
done

# Copy to remote server
scp "${ARCHIVE_PATH}" "${CHECKSUM_PATH}" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/" \
    >> "${LOG_FILE}" 2>&1

log "Copied backup to remote server"
log "Backup job completed successfully"
