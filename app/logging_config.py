import json
import logging
import sys
from datetime import UTC, datetime

_STANDARD_ATTRIBUTES = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, so logs can be searched and filtered by field."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        entry.update(
            {key: value for key, value in vars(record).items() if key not in _STANDARD_ATTRIBUTES}
        )
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: str) -> None:
    """Send all application logs to stdout as JSON lines (Render collects stdout)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
