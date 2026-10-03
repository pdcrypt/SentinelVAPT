"""Entry point: python -m app.worker"""

import logging
import os
import signal
import socket
import threading
from types import FrameType

from app.core.config import get_settings
from app.db.session import make_engine, make_session_factory
from app.worker.core import Worker


def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper())
    engine = make_engine(settings.database_url.get_secret_value())
    worker = Worker(
        make_session_factory(engine),
        worker_id=settings.worker_id or f"{socket.gethostname()}:{os.getpid()}",
        heartbeat_interval=settings.worker_heartbeat_seconds,
        stale_after=settings.worker_stale_after_seconds,
    )
    stop = threading.Event()

    def handle_signal(signum: int, _frame: FrameType | None) -> None:
        logging.getLogger(__name__).info("signal %s received; shutting down", signum)
        stop.set()
        worker.request_shutdown()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    try:
        worker.run_forever(stop, poll_interval=settings.worker_poll_seconds)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
