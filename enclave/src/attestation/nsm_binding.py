"""Minimal Nitro Secure Module binding.

This module talks directly to the NSM kernel driver via ``/dev/nsm``.
The wire protocol is CBOR encoded and mirrors the AWS
``aws-nitro-enclaves-nsm-api`` Rust request/response enums.
"""

from __future__ import annotations

import ctypes
import fcntl
import io
import os
from typing import Optional

import cbor2

NSM_DEVICE = "/dev/nsm"
NSM_IOCTL_MAGIC = 0x0A
NSM_IOCTL_NR = 0
NSM_REQUEST_MAX_SIZE = 0x1000
NSM_RESPONSE_MAX_SIZE = 0x3000

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_READ = 2
_IOC_WRITE = 1


class NsmError(RuntimeError):
    """Raised when the NSM driver returns an error response."""


class _Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class _NsmMessage(ctypes.Structure):
    _fields_ = [
        ("request", _Iovec),
        ("response", _Iovec),
    ]


NSM_IOCTL_REQUEST = (
    ((_IOC_READ | _IOC_WRITE) << _IOC_DIRSHIFT)
    | (ctypes.sizeof(_NsmMessage) << _IOC_SIZESHIFT)
    | (NSM_IOCTL_MAGIC << _IOC_TYPESHIFT)
    | (NSM_IOCTL_NR << _IOC_NRSHIFT)
)


class NsmClient:
    """Small context-managed client for the NSM driver."""

    def __init__(self, device_path: str = NSM_DEVICE):
        self._device_path = device_path

    def get_attestation_doc(
        self,
        public_key: Optional[bytes] = None,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        request = {
            "Attestation": {
                "user_data": user_data,
                "nonce": nonce,
                "public_key": public_key,
            }
        }
        response = self._process_request(request)
        if "Attestation" in response:
            document = response["Attestation"].get("document")
        elif b"Attestation" in response:
            document = response[b"Attestation"].get(b"document")
        else:
            error = response.get("Error") if isinstance(response, dict) else response
            raise NsmError(f"NSM attestation failed: {error!r}")

        if not isinstance(document, bytes):
            raise NsmError("NSM attestation response did not contain document bytes")
        return document

    def _process_request(self, request: dict) -> dict:
        encoded_request = cbor2.dumps(request)
        if len(encoded_request) > NSM_REQUEST_MAX_SIZE:
            raise NsmError("NSM request exceeds maximum size")

        request_buffer = ctypes.create_string_buffer(encoded_request)
        response_buffer = ctypes.create_string_buffer(NSM_RESPONSE_MAX_SIZE)
        message = _NsmMessage(
            request=_Iovec(
                ctypes.cast(request_buffer, ctypes.c_void_p),
                len(encoded_request),
            ),
            response=_Iovec(
                ctypes.cast(response_buffer, ctypes.c_void_p),
                NSM_RESPONSE_MAX_SIZE,
            ),
        )

        fd = os.open(self._device_path, os.O_RDWR)
        try:
            fcntl.ioctl(fd, NSM_IOCTL_REQUEST, message, True)
        except OSError as exc:
            raise NsmError(f"NSM ioctl failed: {exc}") from exc
        finally:
            os.close(fd)

        response_len = int(message.response.iov_len)
        if response_len <= 0 or response_len > NSM_RESPONSE_MAX_SIZE:
            response_len = NSM_RESPONSE_MAX_SIZE
        return _decode_first_cbor(response_buffer.raw[:response_len])


def extract_pcrs_from_attestation_document(document: bytes) -> dict[int, str]:
    """Extract PCR values from a COSE_Sign1-wrapped attestation document.

    Some NSM/kernel combinations return the document as a CBOR byte string
    containing the COSE_Sign1 bytes. Decode that wrapper before inspecting the
    COSE payload.
    """

    cose_sign1 = cbor2.loads(document)
    if isinstance(cose_sign1, bytes):
        cose_sign1 = cbor2.loads(cose_sign1)
    if isinstance(cose_sign1, cbor2.CBORTag):
        cose_sign1 = cose_sign1.value

    if isinstance(cose_sign1, dict):
        return _extract_pcrs_from_payload(cose_sign1)

    if not isinstance(cose_sign1, (list, tuple)) or len(cose_sign1) < 3:
        raise NsmError("Attestation document is not a COSE_Sign1 structure")

    payload = cose_sign1[2]
    if not isinstance(payload, bytes):
        raise NsmError("Attestation document COSE payload is not bytes")

    attestation_doc = cbor2.loads(payload)
    return _extract_pcrs_from_payload(attestation_doc)


def _extract_pcrs_from_payload(attestation_doc: dict) -> dict[int, str]:
    pcrs = attestation_doc.get("pcrs")
    if pcrs is None:
        pcrs = attestation_doc.get(b"pcrs")
    if not isinstance(pcrs, dict):
        raise NsmError("Attestation document did not contain a PCR map")

    extracted: dict[int, str] = {}
    for key, value in pcrs.items():
        if not isinstance(value, bytes):
            raise NsmError(f"PCR {key!r} value was not bytes")
        extracted[int(key)] = value.hex()
    return extracted


def _decode_first_cbor(raw: bytes) -> dict:
    decoder = cbor2.CBORDecoder(io.BytesIO(raw))
    decoded = decoder.decode()
    if not isinstance(decoded, dict):
        raise NsmError("NSM response was not a CBOR map")
    return decoded
