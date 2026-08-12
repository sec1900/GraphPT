#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared helpers for lightweight runtime status files.

All long-running scripts should write the same high-level status shape so the
orchestrating flow can poll one file and only continue when `status` becomes
`completed`.
"""

from __future__ import absolute_import, unicode_literals

import io
import json
import os
import time
from datetime import datetime


def _utc_now():
    return datetime.utcnow().isoformat() + "Z"


def _utc_from_timestamp(timestamp):
    return datetime.utcfromtimestamp(timestamp).isoformat() + "Z"


def write_runtime_status(
    status_file,
    tool,
    stage,
    status,
    targets,
    artifacts=None,
    started_at=None,
    progress=None,
    current_target=None,
    error=None,
    details=None,
):
    """Write a compact JSON status snapshot."""
    now = _utc_now()
    payload = {
        "tool": tool,
        "stage": stage,
        "status": status,
        "updated_at": now,
        "targets_total": len(targets or []),
        "targets": list(targets or []),
        "artifacts": artifacts or {},
    }

    if started_at is not None:
        payload["started_at"] = _utc_from_timestamp(started_at)
        payload["elapsed_seconds"] = round(time.time() - started_at, 2)

    if status in ("completed", "failed"):
        payload["ended_at"] = now

    if progress:
        payload["progress"] = progress
    elif current_target:
        payload["progress"] = {
            "current_target": current_target,
        }

    if error:
        payload["error"] = error

    if details:
        payload["details"] = details

    parent = os.path.dirname(os.path.abspath(status_file))
    if parent and not os.path.exists(parent):
        os.makedirs(parent)

    with io.open(status_file, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
