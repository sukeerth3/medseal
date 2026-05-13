"""vsock transport between the enclave and parent EC2 host.

Nitro Enclaves do not have a network interface or persistent disk, so
vsock is the request path used by the gateway.

Message framing protocol:
  [4 bytes: message length (big-endian uint32)]
  [N bytes: JSON payload]
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# vsock constants
VSOCK_CID_ANY = 0xFFFFFFFF  # Accept connections from any CID
VMADDR_CID_PARENT = 3       # CID of the parent EC2 instance
DEFAULT_PORT = 5000
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB max message
HEADER_SIZE = 4               # 4-byte length prefix


class VsockServer:
    """
    vsock server running inside the Nitro Enclave.

    Listens for connections from the EC2 host and dispatches
    messages to a handler function. Each connection is handled
    in a separate thread.
    """

    def __init__(
        self,
        port: int = DEFAULT_PORT,
        handler: Optional[Callable[[str], str]] = None,
    ):
        self._port = port
        self._handler = handler
        self._running = False
        self._server_socket: Optional[socket.socket] = None

    def set_handler(self, handler: Callable[[str], str]) -> None:
        """Set the message handler (receives JSON string, returns JSON string)."""
        self._handler = handler

    def start(self) -> None:
        """Start listening for vsock connections."""
        if self._handler is None:
            raise RuntimeError("No handler set. Call set_handler() first.")

        self._server_socket = socket.socket(
            socket.AF_VSOCK, socket.SOCK_STREAM
        )
        self._server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_socket.bind((VSOCK_CID_ANY, self._port))
        self._server_socket.listen(5)
        self._running = True

        logger.info("vsock server listening on port %d", self._port)

        while self._running:
            try:
                self._server_socket.settimeout(1.0)
                try:
                    conn, addr = self._server_socket.accept()
                except socket.timeout:
                    continue

                logger.info("Connection from CID %s", addr)
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                )
                thread.start()

            except Exception as e:
                if self._running:
                    logger.error("Accept error: %s", e)

    def stop(self) -> None:
        """Stop the server."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        logger.info("vsock server stopped")

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a single connection from the host."""
        try:
            message = self._recv_message(conn)
            if message is None:
                return

            logger.debug("Received message (%d bytes)", len(message))

            response = self._handler(message)

            self._send_message(conn, response)
            logger.debug("Sent response (%d bytes)", len(response))

        except Exception as e:
            logger.error("Connection handler error: %s", e)
            try:
                error_response = json.dumps({
                    "status": "FAILED",
                    "error": str(e),
                })
                self._send_message(conn, error_response)
            except Exception:
                pass
        finally:
            conn.close()

    @staticmethod
    def _recv_message(conn: socket.socket) -> Optional[str]:
        """Receive a length-prefixed message."""
        header = _recv_exact(conn, HEADER_SIZE)
        if header is None:
            return None

        msg_len = struct.unpack(">I", header)[0]

        if msg_len > MAX_MESSAGE_SIZE:
            raise ValueError(
                f"Message too large: {msg_len} > {MAX_MESSAGE_SIZE}"
            )

        body = _recv_exact(conn, msg_len)
        if body is None:
            return None

        return body.decode("utf-8")

    @staticmethod
    def _send_message(conn: socket.socket, message: str) -> None:
        """Send a length-prefixed message."""
        data = message.encode("utf-8")
        header = struct.pack(">I", len(data))
        conn.sendall(header + data)


class VsockClient:
    """
    vsock client for the EC2 host side.

    Connects to the enclave and sends/receives length-prefixed
    JSON messages. Used by the Spring Boot gateway (via JNI or
    a Python sidecar process).
    """

    def __init__(self, enclave_cid: int, port: int = DEFAULT_PORT):
        self._cid = enclave_cid
        self._port = port

    def send(self, message: str, timeout: float = 30.0) -> str:
        """
        Send a message to the enclave and wait for a response.

        Args:
            message: JSON string to send
            timeout: Socket timeout in seconds

        Returns:
            JSON response string from the enclave
        """
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((self._cid, self._port))

            data = message.encode("utf-8")
            header = struct.pack(">I", len(data))
            sock.sendall(header + data)

            resp_header = _recv_exact(sock, HEADER_SIZE)
            if resp_header is None:
                raise ConnectionError("Enclave closed connection")

            resp_len = struct.unpack(">I", resp_header)[0]
            if resp_len > MAX_MESSAGE_SIZE:
                raise ValueError(f"Response too large: {resp_len}")

            resp_body = _recv_exact(sock, resp_len)
            if resp_body is None:
                raise ConnectionError("Incomplete response from enclave")

            return resp_body.decode("utf-8")

        finally:
            sock.close()


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes from a socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
