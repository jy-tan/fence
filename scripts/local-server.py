#!/usr/bin/env python3
"""
Simple HTTP server for network benchmarking.

Runs on port 8765 and responds to all requests with a minimal JSON response.
Used by benchmark.sh to measure proxy overhead without internet variability.

Usage:
    python3 scripts/local-server.py
    # Server runs on http://127.0.0.1:8765/

    # In another terminal:
    curl http://127.0.0.1:8765/
"""

import http.server
import json
import socketserver
import sys

PORT = 8765


class BenchmarkHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler for benchmarking."""

    def do_GET(self):
        """Handle GET requests with minimal response."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {"status": "ok", "path": self.path}
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        """Handle POST requests with minimal response."""
        content_length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_length)  # Read and discard body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {"status": "ok", "method": "POST"}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        """Suppress request logging for cleaner benchmark output."""
        pass


def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), BenchmarkHandler) as httpd:
        print(f"Benchmark server running on http://127.0.0.1:{PORT}/", file=sys.stderr)
        print("Press Ctrl+C to stop", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...", file=sys.stderr)
            httpd.shutdown()


if __name__ == "__main__":
    main()
