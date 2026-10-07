import multiprocessing
import os
import signal
import time

from .web import create_app
from .worker import run


def serve(folder):
    from waitress import serve as waitress_serve

    waitress_serve(
        create_app(folder),
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        threads=8,
        max_request_body_size=2_000_000,
        expose_tracebacks=False,
    )


def main():
    os.umask(0o077)
    folder = os.environ.get("DATA_DIR", "/data")
    # Initialize once before spawning to avoid racing secret/key creation.
    create_app(folder)
    children = [
        multiprocessing.Process(target=serve, args=(folder,)),
        multiprocessing.Process(target=run, args=(folder,)),
    ]
    for child in children:
        child.start()

    def stop(signum=None, frame=None):
        for child in children:
            if child.is_alive():
                child.terminate()
        for child in children:
            child.join(timeout=10)
            if child.is_alive():
                child.kill()

    def terminate(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    try:
        while all(child.is_alive() for child in children):
            time.sleep(1)
    finally:
        stop()
    raise SystemExit(1)


if __name__ == "__main__":
    main()
