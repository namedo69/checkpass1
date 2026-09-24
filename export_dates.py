"""Date values for XLSX exports (display formatting belongs to the cell)."""

from datetime import date, datetime
from typing import Any


def registration_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip().split(" ", 1)[0].split("T", 1)[0]
    for pattern in ("%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, pattern).date()
        except ValueError:
            pass
    return None
