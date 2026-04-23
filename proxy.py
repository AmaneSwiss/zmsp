#!/usr/bin/env python3
"""
Zigbee Multi-Stick Broadcast Proxy

- Accepts exactly 1 Zigbee2MQTT TCP client
- Broadcasts each incoming packet to all configured SLZB sticks
- Uses the first valid response (checksum/ACK-NACK heuristic)
- Retries on timeout
- Supports reconnects, health checks, statistics, and passive learning
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import shutil
import ipaddress
import signal
import time
import yaml
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional


# -----------------------------
# Configuration models
# -----------------------------
@dataclasses.dataclass
class ProxyConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 6638

@dataclasses.dataclass
class StickConfig:
    name: str
    host: str
    port: int = 6638

@dataclasses.dataclass
class RetryConfig:
    max_attempts: int = 3
    delay_seconds: float = 2.0

@dataclasses.dataclass
class TimeoutConfig:
    response_timeout: float = 5.0

@dataclasses.dataclass
class LoggingConfig:
    level: str = "INFO"
    hex_dump: bool = False

@dataclasses.dataclass
class RoutingConfig:
    mode: str = "smart"  # smart | broadcast

@dataclasses.dataclass
class LearningConfig:
    ttl_seconds: int = 86400

@dataclasses.dataclass
class RuntimeConfig:
    proxy: ProxyConfig
    sticks: list[StickConfig]
    retry: RetryConfig
    timeout: TimeoutConfig
    logging: LoggingConfig
    routing: RoutingConfig
    learning: LearningConfig

@dataclasses.dataclass
class ValidationResult:
    valid: bool
    is_error: bool
    protocol: str
    reason: str = ""

@dataclasses.dataclass
class RequestContext:
    request_frame: bytes
    protocol_hint: str
    created_at: float
    future: asyncio.Future
    attempt: int
    target_stick_names: set[str] = dataclasses.field(default_factory=set)
    received_bytes_by_stick: Counter[str] = dataclasses.field(default_factory=Counter)
    received_frames_by_stick: Counter[str] = dataclasses.field(default_factory=Counter)
    invalid_reasons_by_stick: dict[str, list[str]] = dataclasses.field(default_factory=lambda: defaultdict(list))


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default

def load_config(path: Path) -> RuntimeConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    proxy_data = data.get("proxy", {})
    sticks_data = data.get("sticks", [])
    retry_data = data.get("retry", {})
    timeout_data = data.get("timeout", {})
    logging_data = data.get("logging", {})
    routing_data = data.get("routing", {})
    learning_data = data.get("learning", {})

    sticks = [
        StickConfig(
            name=item["name"],
            host=item["host"],
            port=int(item.get("port", 6638)),
        )
        for item in sticks_data
    ]

    if not sticks:
        raise ValueError("Mindestens ein Stick muss in config.yaml definiert sein.")

    routing_mode = str(routing_data.get("mode", "smart")).strip().lower()
    if routing_mode not in {"smart", "broadcast"}:
        logging.warning("Invalid routing.mode='%s' - fallback to 'smart'", routing_mode)
        routing_mode = "smart"

    learning_ttl = int(learning_data.get("ttl_seconds", 86400))
    if learning_ttl < 1:
        logging.warning("Invalid learning.ttl_seconds='%s' - fallback to 86400", learning_ttl)
        learning_ttl = 86400

    return RuntimeConfig(
        proxy=ProxyConfig(
            listen_host=str(proxy_data.get("listen_host", "0.0.0.0")),
            listen_port=int(proxy_data.get("listen_port", 6638)),
        ),
        sticks=sticks,
        retry=RetryConfig(
            max_attempts=int(retry_data.get("max_attempts", 3)),
            delay_seconds=float(retry_data.get("delay_seconds", 2)),
        ),
        timeout=TimeoutConfig(
            response_timeout=float(timeout_data.get("response_timeout", 5)),
        ),
        logging=LoggingConfig(
            level=str(logging_data.get("level", "INFO")),
            hex_dump=_as_bool(logging_data.get("hex_dump"), False),
        ),
        routing=RoutingConfig(
            mode=routing_mode,
        ),
        learning=LearningConfig(
            ttl_seconds=learning_ttl,
        ),
    )


# -----------------------------
# Protocol parsing / validation
# -----------------------------
class FrameParser:
    """Parser for ZNP (0xFE-based) and EZSP/ASH (0x7E-delimited)."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.protocol: str = "unknown"

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer.extend(data)

        if self.protocol == "unknown":
            self._detect_protocol()

        if self.protocol == "znp":
            return self._extract_znp_frames()
        if self.protocol == "ezsp":
            return self._extract_ezsp_frames()

        # Fallback: avoid large buffers for unknown streams
        if len(self.buffer) > 1024:
            frame = bytes(self.buffer)
            self.buffer.clear()
            return [frame]
        return []

    def _detect_protocol(self) -> None:
        if not self.buffer:
            return

        # ZNP typically starts with SOF 0xFE
        if self.buffer[0] == 0xFE:
            self.protocol = "znp"
            return

        # EZSP/ASH typically contains 0x7E as delimiter
        if 0x7E in self.buffer:
            self.protocol = "ezsp"
            return

        # Heuristic: if first byte is not FE, prefer EZSP
        if len(self.buffer) >= 4 and self.buffer[0] != 0xFE:
            self.protocol = "ezsp"

    def _extract_znp_frames(self) -> list[bytes]:
        frames: list[bytes] = []

        while self.buffer:
            if self.buffer[0] != 0xFE:
                sof_idx = self.buffer.find(0xFE)
                if sof_idx == -1:
                    self.buffer.clear()
                    break
                del self.buffer[:sof_idx]

            if len(self.buffer) < 5:
                break

            payload_len = self.buffer[1]
            total_len = 1 + 1 + 2 + payload_len + 1
            if len(self.buffer) < total_len:
                break

            frame = bytes(self.buffer[:total_len])
            del self.buffer[:total_len]
            frames.append(frame)

        return frames

    def _extract_ezsp_frames(self) -> list[bytes]:
        frames: list[bytes] = []

        while True:
            try:
                end_idx = self.buffer.index(0x7E)
            except ValueError:
                break

            raw_segment = bytes(self.buffer[: end_idx + 1])
            del self.buffer[: end_idx + 1]

            if raw_segment == b"\x7E":
                logging.debug("[ASH parser] Ignoring single end flag 0x7E without payload")
                continue

            start_idx = raw_segment.find(b"\x1A")
            if start_idx == -1:
                frame = raw_segment
                logging.debug(
                    "[ASH parser] Frame without start flag 0x1A accepted: %s",
                    " ".join(f"{b:02X}" for b in frame),
                )
            else:
                if start_idx > 0:
                    leading = raw_segment[:start_idx]
                    logging.debug(
                        "[ASH parser] Bytes before start flag 0x1A ignored: %s",
                        " ".join(f"{b:02X}" for b in leading),
                    )

                frame = raw_segment[start_idx:]
                logging.debug(
                    "[ASH parser] Extracted frame for validation/CRC: %s",
                    " ".join(f"{b:02X}" for b in frame),
                )

            frames.append(frame)

        return frames

def znp_fcs(frame: bytes) -> int:
    if len(frame) < 5:
        return 0
    fcs = 0
    for b in frame[1:-1]:
        fcs ^= b
    return fcs

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def ezsp_unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)

def validate_frame(frame: bytes, protocol_hint: str = "unknown") -> ValidationResult:
    if not frame:
        return ValidationResult(valid=False, is_error=True, protocol="unknown", reason="empty frame")

    protocol = protocol_hint
    if protocol == "unknown":
        protocol = "znp" if frame[:1] == b"\xFE" else ("ezsp" if frame.endswith(b"\x7E") else "unknown")

    if protocol == "znp":
        if len(frame) < 5 or frame[0] != 0xFE:
            return ValidationResult(False, True, "znp", "invalid znp length/sof")

        expected_len = 1 + 1 + 2 + frame[1] + 1
        if len(frame) != expected_len:
            return ValidationResult(False, True, "znp", "length mismatch")

        computed = znp_fcs(frame)
        recv = frame[-1]
        if computed != recv:
            return ValidationResult(False, True, "znp", "fcs mismatch")

        # Heuristic: treat SRSP with first data byte != 0 as error
        cmd0 = frame[2]
        is_srsp = (cmd0 & 0xE0) == 0x60
        if is_srsp and frame[1] > 0:
            status = frame[4]
            if status != 0x00:
                return ValidationResult(True, True, "znp", f"srsp status=0x{status:02X}")

        return ValidationResult(True, False, "znp", "ok")

    if protocol == "ezsp":
        if not frame.endswith(b"\x7E"):
            return ValidationResult(False, True, "ezsp", "missing end flag 0x7E")

        start_idx = frame.find(b"\x1A")
        if start_idx == -1:
            escaped_between_flags = frame[:-1]
        else:
            if start_idx > 0:
                logging.debug(
                    "[ASH crc] Ignoring bytes before start flag 0x1A: %s",
                    " ".join(f"{b:02X}" for b in frame[:start_idx]),
                )

            ash_frame = frame[start_idx:]
            escaped_between_flags = ash_frame[1:-1]
        decoded_between_flags = ezsp_unescape(escaped_between_flags)

        if len(decoded_between_flags) < 3:
            return ValidationResult(False, True, "ezsp", "decoded frame too short")

        body = decoded_between_flags[:-2]
        crc_byte_1 = decoded_between_flags[-2]
        crc_byte_2 = decoded_between_flags[-1]
        received_crc_le = crc_byte_1 | (crc_byte_2 << 8)
        received_crc_be = (crc_byte_1 << 8) | crc_byte_2

        computed_crc = crc16_ccitt_false(body)
        expected_crc_low = computed_crc & 0xFF
        expected_crc_high = (computed_crc >> 8) & 0xFF

        logging.debug(
            "[ASH crc] body=%s | expected(low/high)=%02X %02X | actual(bytes)=%02X %02X | interpreted_le=0x%04X interpreted_be=0x%04X",
            " ".join(f"{b:02X}" for b in body),
            expected_crc_low,
            expected_crc_high,
            crc_byte_1,
            crc_byte_2,
            received_crc_le,
            received_crc_be,
        )

        crc_ok = computed_crc in {received_crc_le, received_crc_be}
        if not crc_ok:
            return ValidationResult(
                False,
                True,
                "ezsp",
                (
                    "crc mismatch "
                    f"expected(low/high)={expected_crc_low:02X} {expected_crc_high:02X} "
                    f"actual(bytes)={crc_byte_1:02X} {crc_byte_2:02X}"
                ),
            )

        # ACK/NACK heuristic for ASH control byte
        ctrl = body[0]
        if 0xA0 <= ctrl <= 0xA7:
            return ValidationResult(True, True, "ezsp", "nack frame")

        return ValidationResult(True, False, "ezsp", "ok")

    return ValidationResult(True, False, "unknown", "no validator")


# -----------------------------
# Stick connection
# -----------------------------
class StickConnection:
    def __init__(self, config: StickConfig, proxy: "BroadcastProxy") -> None:
        self.config = config
        self.proxy = proxy
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.parser = FrameParser()
        self.online = False
        self._send_lock = asyncio.Lock()

    @property
    def name(self) -> str:
        return self.config.name

    async def run(self) -> None:
        while not self.proxy.stop_event.is_set():
            try:
                logging.info("[Stick:%s] Connecting to %s:%s", self.name, self.config.host, self.config.port)
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.host, self.config.port),
                    timeout=6,
                )
                self.online = True
                self.parser = FrameParser()
                logging.info("[Stick:%s] Online", self.name)
                logging.debug("[Stick:%s] _read_from_stick task active", self.name)
                await self._read_from_stick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logging.warning("[Stick:%s] Connection failed/disconnected: %s", self.name, exc)
            finally:
                await self._cleanup()

            if not self.proxy.stop_event.is_set():
                await asyncio.sleep(self.proxy.config.retry.delay_seconds)

    async def _read_from_stick(self) -> None:
        assert self.reader is not None
        while not self.proxy.stop_event.is_set():
            data = await self.reader.read(4096)
            if not data:
                raise ConnectionError("Socket durch Gegenstelle geschlossen")

            logging.debug("[Stick:%s] %s bytes received (raw socket read)", self.name, len(data))
            self.proxy._log_hex_dump(f"[RECV from Stick:{self.name}]", data)
            self.proxy._log_ash_frame(f"from Stick:{self.name}", data)

            frames = self.parser.feed(data)
            if not frames:
                logging.debug(
                    "[Stick:%s] No complete frame yet (parser_protocol=%s, buffered=%s)",
                    self.name,
                    self.parser.protocol,
                    len(self.parser.buffer),
                )
                continue

            logging.debug("[Stick:%s] %s frame(s) extracted", self.name, len(frames))
            for frame in frames:
                self.proxy.total_frames_from_stick[self.name] += 1
                self.proxy.total_bytes_from_stick[self.name] += len(frame)
                await self.proxy.handle_stick_frame(self, frame, self.parser.protocol)

    async def send(self, frame: bytes) -> bool:
        if not self.online or not self.writer:
            return False

        async with self._send_lock:
            try:
                self.proxy._log_hex_dump(f"[SEND to Stick:{self.name}]", frame)
                self.proxy._log_ash_frame(f"to Stick:{self.name}", frame)
                self.writer.write(frame)
                await self.writer.drain()
                return True
            except Exception as exc:
                logging.warning("[Stick:%s] Send error: %s", self.name, exc)
                await self._cleanup()
                return False

    async def _cleanup(self) -> None:
        self.online = False
        if self.writer:
            self.writer.close()
            with contextlib.suppress(Exception):
                await self.writer.wait_closed()
        self.reader = None
        self.writer = None


# -----------------------------
# Broadcast proxy
# -----------------------------
class BroadcastProxy:
    def __init__(self, config: RuntimeConfig, learning_path: Path) -> None:
        self.config = config
        self.stop_event = asyncio.Event()
        self.server: Optional[asyncio.base_events.Server] = None

        self.sticks = [StickConnection(cfg, self) for cfg in config.sticks]
        self.stick_tasks: list[asyncio.Task] = []

        self.client_reader: Optional[asyncio.StreamReader] = None
        self.client_writer: Optional[asyncio.StreamWriter] = None
        self.client_parser = FrameParser()
        self.client_write_lock = asyncio.Lock()

        self.request_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.active_request: Optional[RequestContext] = None

        self.response_stats: Counter[str] = Counter()
        self.timeout_count = 0
        self.retry_count = 0

        self.learning_path = learning_path
        self.learning_data = self._load_learning_data()
        self.learning_lock = asyncio.Lock()
        self._purge_expired_learning_entries()

        self._recent_forwarded: dict[str, float] = {}
        self.total_bytes_from_stick: Counter[str] = Counter()
        self.total_frames_from_stick: Counter[str] = Counter()

        self.primary_stick_name: Optional[str] = None

    def _load_learning_data(self) -> dict[str, dict[str, dict[str, float | int]]]:
        if not self.learning_path.exists():
            return {}
        try:
            raw = json.loads(self.learning_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                now = time.time()
                normalized: dict[str, dict[str, dict[str, float | int]]] = {}
                for signature, sticks in raw.items():
                    if not isinstance(sticks, dict):
                        continue

                    stick_bucket: dict[str, dict[str, float | int]] = {}
                    for stick_name, entry in sticks.items():
                        if not isinstance(entry, dict):
                            continue

                        count = int(entry.get("count", 0))
                        timestamp = float(entry.get("timestamp", now))

                        if count > 0:
                            stick_bucket[str(stick_name)] = {
                                "count": count,
                                "timestamp": timestamp,
                            }

                    if stick_bucket:
                        normalized[str(signature)] = stick_bucket

                return normalized
        except Exception as exc:
            logging.warning("Could not load learning file: %s", exc)
        return {}

    def _purge_expired_learning_entries(self) -> int:
        ttl_seconds = self.config.learning.ttl_seconds
        if ttl_seconds < 1:
            return 0

        cutoff = time.time() - ttl_seconds
        removed = 0
        signatures_to_remove: list[str] = []

        for signature, sticks in self.learning_data.items():
            stale_sticks = [
                stick_name
                for stick_name, entry in sticks.items()
                if float(entry.get("timestamp", 0)) < cutoff
            ]

            for stick_name in stale_sticks:
                sticks.pop(stick_name, None)
                removed += 1

            if not sticks:
                signatures_to_remove.append(signature)

        for signature in signatures_to_remove:
            self.learning_data.pop(signature, None)

        return removed

    async def _save_learning_data(self) -> None:
        async with self.learning_lock:
            removed = self._purge_expired_learning_entries()
            if removed:
                logging.info("Learning cleanup: %s expired entries removed", removed)
            self.learning_path.write_text(
                json.dumps(self.learning_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    async def start(self) -> None:
        for stick in self.sticks:
            task = asyncio.create_task(stick.run(), name=f"stick-{stick.name}")
            self.stick_tasks.append(task)

        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.config.proxy.listen_host,
            port=self.config.proxy.listen_port,
        )

        addr = ", ".join(str(sock.getsockname()) for sock in self.server.sockets or [])
        logging.info("Proxy listening on %s", addr)
        logging.info(
            "Debug options | hex_dump=%s routing_mode=%s learning_ttl_seconds=%s",
            self.config.logging.hex_dump,
            self.config.routing.mode,
            self.config.learning.ttl_seconds,
        )

        worker = asyncio.create_task(self._request_worker(), name="request-worker")
        health = asyncio.create_task(self._health_check_loop(), name="health-check")

        async with self.server:
            await self.stop_event.wait()

        # Graceful shutdown
        worker.cancel()
        health.cancel()
        for t in self.stick_tasks:
            t.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await worker
        with contextlib.suppress(asyncio.CancelledError):
            await health
        for t in self.stick_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t

        await self._close_client()
        await self._save_learning_data()
        logging.info("Proxy shut down cleanly")

    async def shutdown(self) -> None:
        self.stop_event.set()
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()

    @staticmethod
    def _is_localhost_peer(peer_ip: str) -> bool:
        try:
            return ipaddress.ip_address(peer_ip).is_loopback
        except ValueError:
            return False

    async def _close_writer(self, writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    def _format_hex_dump(self, data: bytes, limit: int = 64) -> str:
        if not data:
            return "<empty>"
        trimmed = data[:limit]
        hex_bytes = " ".join(f"{b:02X}" for b in trimmed)
        if len(data) > limit:
            return f"{hex_bytes} ... (+{len(data) - limit} bytes)"
        return hex_bytes

    def _log_hex_dump(self, prefix: str, data: bytes) -> None:
        if not self.config.logging.hex_dump:
            return
        logging.debug("%s %s", prefix, self._format_hex_dump(data))

    @staticmethod
    def _detect_ash_frame_type(frame: bytes) -> str:
        if not frame:
            return "EMPTY"

        decoded_payload: bytes

        if frame.endswith(b"\x7E"):
            start_idx = frame.find(b"\x1A")
            if start_idx != -1 and start_idx + 2 <= len(frame):
                escaped_between_flags = frame[start_idx + 1 : -1]
                decoded_payload = ezsp_unescape(escaped_between_flags)
            else:
                payload = frame[:-1]
                decoded_payload = ezsp_unescape(payload)
        else:
            decoded_payload = ezsp_unescape(frame)

        if not decoded_payload:
            return "UNKNOWN"

        ctrl = decoded_payload[0]
        if ctrl == 0xC0:
            return "RST"
        if ctrl == 0xC1:
            return "RSTACK"
        if ctrl == 0xC2:
            return "ERROR"
        if 0x80 <= ctrl <= 0x87:
            return "ACK"
        if 0xA0 <= ctrl <= 0xA7:
            return "NAK"
        if 0x00 <= ctrl <= 0x7F:
            return "DATA"
        return "UNKNOWN"

    def _log_ash_frame(self, origin: str, frame: bytes) -> None:
        frame_type = self._detect_ash_frame_type(frame)
        if frame_type != "UNKNOWN":
            logging.debug("[ASH %s] type=%s len=%s", origin, frame_type, len(frame))

    def _is_expected_ash_response(self, request_frame: bytes, response_frame: bytes) -> tuple[bool, str]:
        request_type = self._detect_ash_frame_type(request_frame)
        response_type = self._detect_ash_frame_type(response_frame)

        if request_type == "RST" and response_type != "RSTACK":
            return False, f"unexpected response for RST: got {response_type}, expected RSTACK"

        if request_type == "RST" and response_type == "RSTACK":
            logging.debug("[ASH validation] RSTACK recognized as a valid response to RST")

        return True, "ok"

    def _resolve_primary_stick(self) -> Optional[StickConnection]:
        if not self.primary_stick_name:
            return None
        for stick in self.sticks:
            if stick.name == self.primary_stick_name:
                return stick
        return None

    def _set_primary_stick(self, stick_name: str, reason: str) -> None:
        if self.primary_stick_name == stick_name:
            return
        old = self.primary_stick_name
        self.primary_stick_name = stick_name
        if old is None:
            logging.info("Routing primary_stick set: %s (%s)", stick_name, reason)
        else:
            logging.warning(
                "Routing Failover: primary_stick %s -> %s (%s)",
                old,
                stick_name,
                reason,
            )

    def _clear_primary_stick(self, reason: str) -> None:
        if self.primary_stick_name is not None:
            logging.info("Routing primary_stick reset (%s): %s", reason, self.primary_stick_name)
        self.primary_stick_name = None

    def _select_request_targets(self, frame: bytes, online_sticks: list[StickConnection]) -> list[StickConnection]:
        mode = self.config.routing.mode
        frame_type = self._detect_ash_frame_type(frame)

        if mode == "broadcast":
            return list(online_sticks)

        # smart mode
        primary = self._resolve_primary_stick()
        if primary is not None and primary.online:
            return [primary]

        # During handshake (RST), and while no primary exists: broadcast
        if frame_type == "RST":
            return list(online_sticks)

        # Fallback: do not block without a primary, use first online stick
        fallback = online_sticks[0]
        self._set_primary_stick(fallback.name, "smart-mode fallback without handshake")
        return [fallback]

    def _promote_failover_primary(self, tried_sticks: list[StickConnection], online_sticks: list[StickConnection]) -> None:
        mode = self.config.routing.mode
        if mode == "broadcast":
            return

        current = self._resolve_primary_stick()
        current_name = current.name if current else None
        candidate_names = [s.name for s in online_sticks if s.name != current_name]
        if not candidate_names:
            return

        # Prefer switching to a stick that was not targeted in the previous attempt.
        tried_names = {s.name for s in tried_sticks}
        for name in candidate_names:
            if name not in tried_names:
                self._set_primary_stick(name, "failover after timeout/error")
                return

        self._set_primary_stick(candidate_names[0], "failover rotate")

    def _log_request_timeout_details(self, active: RequestContext, online_sticks: list[StickConnection]) -> None:
        bytes_by_stick = {
            stick.name: int(active.received_bytes_by_stick.get(stick.name, 0))
            for stick in online_sticks
        }
        frames_by_stick = {
            stick.name: int(active.received_frames_by_stick.get(stick.name, 0))
            for stick in online_sticks
        }
        any_data = any(v > 0 for v in bytes_by_stick.values())

        logging.warning(
            "Timeout Attempt %s | any_data=%s | bytes=%s | frames=%s",
            active.attempt,
            any_data,
            bytes_by_stick,
            frames_by_stick,
        )

        for stick_name, reasons in active.invalid_reasons_by_stick.items():
            if reasons:
                logging.debug(
                    "Timeout Attempt %s | invalid reasons from %s: %s",
                    active.attempt,
                    stick_name,
                    reasons,
                )

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = str(peer[0]) if isinstance(peer, tuple) and len(peer) > 0 else ""

        if self._is_localhost_peer(peer_ip):
            logging.debug(
                "Localhost connection detected (health check) from %s - not registering as Z2M peer",
                peer,
            )
            await self._close_writer(writer)
            logging.debug("Health-check connection closed cleanly: %s", peer)
            return

        if self.client_writer is not None and self.client_writer is not writer:
            logging.warning("Additional Z2M client %s rejected (only 1 allowed)", peer)
            await self._close_writer(writer)
            return

        logging.info("Z2M client connected: %s", peer)
        self.client_reader = reader
        self.client_writer = writer
        self.client_parser = FrameParser()
        if self.config.routing.mode == "smart":
            self._clear_primary_stick("new Z2M client")

        try:
            while not self.stop_event.is_set():
                data = await reader.read(4096)
                if not data:
                    break

                logging.debug("[Z2M->Proxy] %s bytes received", len(data))
                self._log_hex_dump("[RECV from Z2M]", data)
                self._log_ash_frame("from Z2M", data)

                frames = self.client_parser.feed(data)
                if not frames:
                    logging.debug(
                        "[Z2M->Proxy] No complete frame yet (parser_protocol=%s, buffered=%s)",
                        self.client_parser.protocol,
                        len(self.client_parser.buffer),
                    )
                    continue

                logging.debug("[Z2M->Proxy] %s Frame(s) in Request-Queue", len(frames))
                for frame in frames:
                    self._log_hex_dump("[QUEUE from Z2M]", frame)
                    self._log_ash_frame("frame from Z2M", frame)
                    await self.request_queue.put(frame)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
                logging.warning("Client error from %s: %s", peer, exc)
        finally:
            if self.client_writer is writer:
                logging.info("Z2M client disconnected: %s", peer)
                await self._close_client()
            else:
                await self._close_writer(writer)

    async def _close_client(self) -> None:
        if self.client_writer:
            self.client_writer.close()
            with contextlib.suppress(Exception):
                await self.client_writer.wait_closed()
        self.client_reader = None
        self.client_writer = None
        self.active_request = None
        if self.config.routing.mode == "smart":
            self._clear_primary_stick("Z2M client disconnected")

    async def _request_worker(self) -> None:
        while not self.stop_event.is_set():
            frame = await self.request_queue.get()
            try:
                await self._process_request(frame, self.client_parser.protocol)
            finally:
                self.request_queue.task_done()

    async def _process_request(self, frame: bytes, protocol_hint: str) -> None:
        if not self.client_writer:
            logging.debug("No client connected, request dropped")
            return

        max_attempts = self.config.retry.max_attempts
        delay = self.config.retry.delay_seconds
        timeout = self.config.timeout.response_timeout
        ash_frame_type = self._detect_ash_frame_type(frame)
        expects_response = ash_frame_type not in {"ACK", "NAK"}

        for attempt in range(1, max_attempts + 1):
            online_sticks = [s for s in self.sticks if s.online]
            if not online_sticks:
                logging.warning("No sticks online (attempt %s/%s)", attempt, max_attempts)
                self.retry_count += 1
                await asyncio.sleep(delay)
                continue

            target_sticks = self._select_request_targets(frame, online_sticks)
            if not target_sticks:
                logging.warning("No target sticks found for request (attempt %s/%s)", attempt, max_attempts)
                self.retry_count += 1
                await asyncio.sleep(delay)
                continue

            fut = asyncio.get_running_loop().create_future()
            self.active_request = RequestContext(
                request_frame=frame,
                protocol_hint=protocol_hint,
                created_at=time.time(),
                future=fut,
                attempt=attempt,
                target_stick_names={s.name for s in target_sticks},
            )

            route_mode = self.config.routing.mode
            target_names = [s.name for s in target_sticks]
            logging.debug(
                "Routing Attempt %s/%s | mode=%s | targets=%s",
                attempt,
                max_attempts,
                route_mode,
                target_names,
            )

            send_results = await asyncio.gather(
                *(stick.send(frame) for stick in target_sticks),
                return_exceptions=True,
            )
            ok_sends = sum(1 for r in send_results if r is True)
            failed_sends = [
                f"{target_sticks[idx].name}:{repr(res)}"
                for idx, res in enumerate(send_results)
                if res is not True
            ]
            logging.debug(
                "Routing attempt %s/%s result | ok=%s/%s failed=%s",
                attempt,
                max_attempts,
                ok_sends,
                len(target_sticks),
                failed_sends,
            )
            if ok_sends == 0:
                logging.warning("Routing failed: no target stick could send")
                self.retry_count += 1
                if attempt < max_attempts:
                    await asyncio.sleep(delay)
                continue

            if not expects_response:
                logging.debug(
                    "Forwarded frame without response expectation (type=%s, attempt=%s/%s)",
                    ash_frame_type,
                    attempt,
                    max_attempts,
                )
                self.active_request = None
                return

            try:
                response = await asyncio.wait_for(fut, timeout=timeout)
                active_ctx = self.active_request
                await self._send_to_client(response)
                if active_ctx is not None:
                    logging.debug(
                        "Attempt %s successful | bytes=%s frames=%s",
                        active_ctx.attempt,
                        dict(active_ctx.received_bytes_by_stick),
                        dict(active_ctx.received_frames_by_stick),
                    )
                self.active_request = None
                return
            except asyncio.TimeoutError:
                self.timeout_count += 1
                self.retry_count += 1
                active_ctx = self.active_request
                if active_ctx is not None:
                    self._log_request_timeout_details(active_ctx, online_sticks)
                logging.warning("Timeout on attempt %s/%s", attempt, max_attempts)
                self.active_request = None
                self._promote_failover_primary(target_sticks, online_sticks)
                if attempt < max_attempts:
                    await asyncio.sleep(delay)
            except Exception as exc:
                logging.error("Request processing failed: %s", exc)
                self.active_request = None
                self._promote_failover_primary(target_sticks, online_sticks)
                if attempt < max_attempts:
                    await asyncio.sleep(delay)

        logging.error("Request failed after %s attempts without a valid response", max_attempts)

    async def handle_stick_frame(self, stick: StickConnection, frame: bytes, protocol_hint: str) -> None:
        self._log_hex_dump(f"[RECV from Stick:{stick.name}]", frame)
        self._log_ash_frame(f"frame from Stick:{stick.name}", frame)

        result = validate_frame(frame, protocol_hint)
        active = self.active_request

        if active is not None and not active.future.done():
            if active.target_stick_names and stick.name not in active.target_stick_names:
                logging.debug(
                    "[%s] Response dropped outside active routing targets: targets=%s",
                    stick.name,
                    sorted(active.target_stick_names),
                )
                return

            active.received_bytes_by_stick[stick.name] += len(frame)
            active.received_frames_by_stick[stick.name] += 1
            logging.debug(
                "[%s] Response received for active request: bytes=%s total_bytes=%s total_frames=%s",
                stick.name,
                len(frame),
                active.received_bytes_by_stick[stick.name],
                active.received_frames_by_stick[stick.name],
            )

            if not result.valid:
                active.invalid_reasons_by_stick[stick.name].append(
                    f"invalid:{result.reason} len={len(frame)}"
                )
                logging.debug("[%s] Invalid frame dropped for active request: %s", stick.name, result.reason)
                return

            if result.is_error:
                active.invalid_reasons_by_stick[stick.name].append(
                    f"error:{result.reason} len={len(frame)}"
                )
                logging.debug("[%s] Error frame dropped for active request: %s", stick.name, result.reason)
                return

            if result.protocol == "ezsp":
                expected, expected_reason = self._is_expected_ash_response(active.request_frame, frame)
                if not expected:
                    active.invalid_reasons_by_stick[stick.name].append(
                        f"invalid:{expected_reason} len={len(frame)}"
                    )
                    logging.debug("[%s] ASH response dropped: %s", stick.name, expected_reason)
                    return

            request_type = self._detect_ash_frame_type(active.request_frame)
            response_type = self._detect_ash_frame_type(frame)
            if self.config.routing.mode == "smart" and request_type == "RST" and response_type == "RSTACK":
                self._set_primary_stick(stick.name, "ASH handshake response")

            # First valid response wins
            active.future.set_result(frame)
            self.response_stats[stick.name] += 1
            await self._learn(active.request_frame, stick.name)
            logging.debug("[%s] Valid response selected", stick.name)
            return

        if not result.valid:
            logging.debug("[%s] Invalid frame dropped (no active request): %s", stick.name, result.reason)
            return

        # Asynchronous event: forward deduplicated frame to Z2M
        if result.is_error:
            logging.debug("[%s] Asynchronous error frame dropped: %s", stick.name, result.reason)
            return

        if self.config.routing.mode == "smart" and self.primary_stick_name:
            if stick.name != self.primary_stick_name:
                logging.debug(
                    "[%s] Asynchronous event from non-primary dropped (primary=%s)",
                    stick.name,
                    self.primary_stick_name,
                )
                return

        dedupe_key = hashlib.sha1(frame).hexdigest()
        now = time.time()
        old_ts = self._recent_forwarded.get(dedupe_key)
        if old_ts and (now - old_ts) < 0.25:
            logging.debug("[%s] Dedupe active, asynchronous duplicate dropped", stick.name)
            return

        self._recent_forwarded[dedupe_key] = now
        if len(self._recent_forwarded) > 2000:
            # Simple cleanup heuristic
            cutoff = now - 10
            self._recent_forwarded = {
                k: v for k, v in self._recent_forwarded.items() if v >= cutoff
            }

        logging.debug("[%s] Unsolicited stick message detected, forwarding to Z2M", stick.name)
        await self._send_to_client(frame)
        logging.debug("[%s] Asynchronous event forwarded to Z2M", stick.name)

    async def _send_to_client(self, frame: bytes) -> None:
        if not self.client_writer:
            return

        async with self.client_write_lock:
            try:
                self._log_hex_dump("[SEND to Z2M]", frame)
                self._log_ash_frame("to Z2M", frame)
                self.client_writer.write(frame)
                await self.client_writer.drain()
            except Exception as exc:
                logging.warning("Sending to Z2M failed: %s", exc)
                await self._close_client()

    async def _learn(self, request_frame: bytes, stick_name: str) -> None:
        signature = self._packet_signature(request_frame)
        async with self.learning_lock:
            self._purge_expired_learning_entries()
            bucket = self.learning_data.setdefault(signature, {})
            entry = bucket.setdefault(stick_name, {"count": 0, "timestamp": time.time()})
            entry["count"] = int(entry.get("count", 0)) + 1
            entry["timestamp"] = time.time()

    @staticmethod
    def _packet_signature(frame: bytes) -> str:
        head = frame[:8].hex()
        digest = hashlib.sha1(frame).hexdigest()[:10]
        return f"{head}:{digest}"

    async def _health_check_loop(self) -> None:
        while not self.stop_event.is_set():
            online = [s.name for s in self.sticks if s.online]
            offline = [s.name for s in self.sticks if not s.online]

            logging.debug(
                "HealthCheck | mode=%s primary=%s online=%s offline=%s stats=%s retries=%s timeouts=%s total_rx_bytes=%s total_rx_frames=%s",
                self.config.routing.mode,
                self.primary_stick_name,
                online,
                offline,
                dict(self.response_stats),
                self.retry_count,
                self.timeout_count,
                dict(self.total_bytes_from_stick),
                dict(self.total_frames_from_stick),
            )

            await asyncio.sleep(30)


# -----------------------------
# Entry point
# -----------------------------
def configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
    )

async def amain(config_path: Path) -> None:
    config = load_config(config_path)
    configure_logging(config.logging.level)

    learning_path = config_path.parent / "learning_state.json"
    proxy = BroadcastProxy(config, learning_path)

    loop = asyncio.get_running_loop()
    stop_called = asyncio.Event()

    def _request_stop() -> None:
        if not stop_called.is_set():
            stop_called.set()
            asyncio.create_task(proxy.shutdown())

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _request_stop)

    await proxy.start()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zigbee Multi-Stick Broadcast Proxy")
    parser.add_argument(
        "-d",
        "--data",
        default="/data",
        help="Path to data directory (default: /data)",
    )

    return parser.parse_args()

def main() -> None:
    args = parse_args()
    data_path = Path(args.data).expanduser().resolve()
    config_path = data_path / "config.yaml"
    learning_path = data_path / "learning_state.json"

    if not config_path.exists():
        logging.warning("Copy new config.yaml into: %s", data_path)
        shutil.copy2("/app/data/config.yaml", config_path)

    if not learning_path.exists():
        with open(learning_path, "w") as f:  
            json.dump({}, f)

    try:
        asyncio.run(amain(config_path))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
