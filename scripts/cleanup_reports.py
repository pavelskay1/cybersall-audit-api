"""Очистка отчётов старше 7 дней."""
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

REPORTS_DIR = Path("/opt/audit-api/reports")
DAYS_TO_KEEP = 7
cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_TO_KEEP)

removed = 0
for f in REPORTS_DIR.iterdir():
    if f.is_file():
        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
        if mtime < cutoff:
            f.unlink()
            removed += 1

print(f"Cleanup: removed {removed} files older than {DAYS_TO_KEEP} days")
