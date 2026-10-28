"""Best-effort Telegram notifications for CryptoLab submissions."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


def notify_submission(student: dict, submitted_at: str) -> bool:
    """Send one submission notice to the configured instructor chat."""
    token = os.environ.get("TELEGRAM_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        logger.info("Telegram submission notifications are not configured")
        return False

    try:
        submitted = datetime.fromisoformat(submitted_at.replace("Z", "+00:00"))
        submitted = submitted.astimezone(timezone(timedelta(hours=3)))
        timestamp = submitted.strftime("%d.%m.%Y %H:%M MSK")
        text = (
            "✅ Сдана лабораторная работа №6 (CryptoLab)\n"
            f"Студент: {student['surname']} {student['given_name']}\n"
            f"Группа: {student['group']}\n"
            f"Время: {timestamp}"
        )
        payload = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
        request = Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            result = json.loads(response.read())
        if not result.get("ok"):
            logger.warning("Telegram rejected CryptoLab submission notification")
            return False
        return True
    except Exception as error:
        # Never log the exception text: urllib errors can contain the token URL.
        logger.warning("Telegram submission notification failed (%s)", type(error).__name__)
        return False
