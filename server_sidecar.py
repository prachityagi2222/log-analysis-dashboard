import os
import sys
import socket
import argparse
import asyncio
import traceback
import uvicorn
from app.main import app


def find_available_port(start_port=8080, max_attempts=50):
    """Return the first port the server can actually bind.

    Probing with ``connect_ex`` is unreliable on Windows: a port that nothing
    is listening on, but which sits in a reserved/excluded range or is blocked
    by a lingering socket, still fails the connect and therefore looks "free",
    yet binding it later fails. Binding is what the server ultimately does, so
    we replicate that here instead.
    """
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(
        f"No free port available in range {start_port}-{start_port + max_attempts - 1}."
    )


def main():
    parser = argparse.ArgumentParser(description="Log Analysis Dashboard Sidecar Backend")
    parser.add_argument("--port", type=int, default=None, help="Port to run the backend on")
    args = parser.parse_args()

    port = args.port or int(os.environ.get("PORT", 0)) or find_available_port(8080)

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)

    async def run():
        # Start uvicorn in the background, then wait until it has actually
        # bound the socket and completed startup before announcing readiness.
        # This closes the race where Tauri navigated to the port before the
        # server was listening.
        serve_task = asyncio.create_task(server.serve())
        while not server.started:
            if serve_task.done():
                # The server exited before becoming ready (e.g. bind error,
                # import failure). Re-raise so the top-level handler prints
                # the real cause to stderr.
                serve_task.result()
                raise RuntimeError(
                    "Backend server exited before it was ready "
                    "(no SERVER_READY emitted)."
                )
            await asyncio.sleep(0.05)
        print(f"SERVER_READY:http://127.0.0.1:{port}", flush=True)
        await serve_task

    try:
        asyncio.run(run())
    except Exception:
        # Surface the real failure (missing DLL, import error, bind error, ...)
        # on stderr so the Tauri parent captures it in its startup log file.
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
