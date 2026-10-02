import os
import sys
import socket
import argparse
import uvicorn
from app.main import app


def find_available_port(start_port=8080, max_attempts=50):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start_port


def main():
    parser = argparse.ArgumentParser(description="Log Analysis Dashboard Sidecar Backend")
    parser.add_argument("--port", type=int, default=None, help="Port to run the backend on")
    args = parser.parse_args()

    port = args.port or int(os.environ.get("PORT", 0)) or find_available_port(8080)

    # Print exact handshake token for Tauri sidecar reader
    print(f"SERVER_READY:http://127.0.0.1:{port}", flush=True)

    # Run Uvicorn directly
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=port,
        log_level="info",
        access_log=False
    )


if __name__ == "__main__":
    main()
