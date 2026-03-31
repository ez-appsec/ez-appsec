#!/bin/bash
# Resize rootfs disk on Proxmox LXC containers 102-105 from 20G to 100G.
# Must be run on the Proxmox host as root.
# Usage: ./resize-lxc-disk.sh [--dry-run]

set -euo pipefail

TARGET_SIZE="100G"
CONTAINER_IDS=(102 103 104 105)
DRY_RUN=false

[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: must be run as root on the Proxmox host" >&2
  exit 1
fi

for CTID in "${CONTAINER_IDS[@]}"; do
  echo "=== Container ${CTID} ==="

  # Verify the container exists
  if ! pct status "${CTID}" &>/dev/null; then
    echo "  SKIP: container ${CTID} not found"
    continue
  fi

  STATUS=$(pct status "${CTID}" | awk '{print $2}')
  echo "  Status: ${STATUS}"

  # Get current rootfs disk size
  CURRENT=$(pct config "${CTID}" | awk -F'[,=]' '/^rootfs:/{for(i=1;i<=NF;i++) if($i=="size") print $(i+1)}')
  echo "  Current size: ${CURRENT:-unknown}"
  echo "  Target size:  ${TARGET_SIZE}"

  if [[ "${CURRENT}" == "${TARGET_SIZE}" ]]; then
    echo "  SKIP: already at ${TARGET_SIZE}"
    continue
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    echo "  DRY-RUN: would run: pct resize ${CTID} rootfs ${TARGET_SIZE}"
    continue
  fi

  # Container must be stopped or running — resize works either way on most storage backends,
  # but the filesystem resize inside the container requires it to be running.
  pct resize "${CTID}" rootfs "${TARGET_SIZE}"
  echo "  Proxmox disk resized."

  # Resize the filesystem — must be done from the HOST, not inside the container.
  # Find the actual block device backing the rootfs.
  ROOTFS_CONF=$(pct config "${CTID}" | awk -F: '/^rootfs:/{print $2}' | xargs)
  STORAGE=$(echo "${ROOTFS_CONF}" | cut -d: -f1)
  VOLNAME=$(echo "${ROOTFS_CONF}" | cut -d: -f2 | cut -d, -f1)

  echo "  Storage: ${STORAGE}  Volume: ${VOLNAME}"

  # Resolve the block device path from the storage type
  STORAGE_TYPE=$(pvesm status -storage "${STORAGE}" 2>/dev/null | awk 'NR==2{print $2}')
  echo "  Storage type: ${STORAGE_TYPE}"

  case "${STORAGE_TYPE}" in
    lvmthin|lvm)
      # LVM: read vgname from /etc/pve/storage.cfg
      VG=$(awk "/^lvmthin: ${STORAGE}|^lvm: ${STORAGE}/{found=1} found && /vgname/{print \$2; exit}" /etc/pve/storage.cfg)
      BLOCK_DEV="/dev/${VG}/${VOLNAME}"
      ;;
    zfspool)
      # ZFS: pct resize already expanded the zvol; filesystem resize via xfs_growfs/resize2fs on the zvol
      ZPOOL=$(awk "/^zfspool: ${STORAGE}/{found=1} found && /pool/{print \$2; exit}" /etc/pve/storage.cfg)
      BLOCK_DEV="/dev/zvol/${ZPOOL}/${VOLNAME}"
      ;;
    dir)
      # Directory storage: image is a raw/qcow2 file — no direct block device; skip
      echo "  Directory storage detected — filesystem resizes automatically via e2fsck on next boot."
      BLOCK_DEV=""
      ;;
    *)
      echo "  WARNING: unknown storage type '${STORAGE_TYPE}', cannot auto-resize filesystem"
      BLOCK_DEV=""
      ;;
  esac

  if [[ -n "${BLOCK_DEV}" ]]; then
    echo "  Block device: ${BLOCK_DEV}"
    FS_TYPE=$(blkid -o value -s TYPE "${BLOCK_DEV}" 2>/dev/null || echo "unknown")
    echo "  Filesystem type: ${FS_TYPE}"
    case "${FS_TYPE}" in
      ext4|ext3|ext2)
        # e2fsck required before resize2fs on a live device
        e2fsck -f -y "${BLOCK_DEV}" 2>/dev/null || true
        resize2fs "${BLOCK_DEV}"
        ;;
      xfs)
        # XFS must be mounted; grow via the mountpoint inside the container
        pct exec "${CTID}" -- xfs_growfs /
        ;;
      btrfs)
        pct exec "${CTID}" -- btrfs filesystem resize max /
        ;;
      *)
        echo "  WARNING: filesystem '${FS_TYPE}' not handled — resize manually"
        ;;
    esac
  fi

  if [[ "${STATUS}" == "running" ]]; then
    NEW_SIZE=$(pct exec "${CTID}" -- df -h / | awk 'NR==2{print $2}')
    echo "  Filesystem size after resize: ${NEW_SIZE}"
  fi

  echo "  Done."
done

echo ""
echo "All containers processed."
