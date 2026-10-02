import os
import socket
import uvicorn


def find_available_port(start_port=8080, max_attempts=20):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start_port


if __name__ == "__main__":
    env_port = os.getenv("PORT")
    port = int(env_port) if env_port else find_available_port(8080)
    print("=" * 60)
    print(f"Log Analysis Dashboard launching at http://127.0.0.1:{port}")
    print("Local-First Security Intelligence • All data remains on your machine")
    print("=" * 60)
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, reload=False)
