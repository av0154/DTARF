# ingestion/log_collector.py
"""
Data Ingestion Layer - Log Collector
Collects logs from multiple sources: Nginx/OS logs, application logs, auth logs.
Normalizes them into a unified event format for the analytics engine.
"""

import os
import re
import time
import json
import threading
from datetime import datetime
from collections import deque


class LogEvent:
    """Unified log event format."""

    def __init__(self, source, raw_line, timestamp=None, src_ip=None,
                 method=None, path=None, status_code=None, message=None):
        self.id = f"{source}-{time.time_ns()}"
        self.source = source
        self.raw_line = raw_line
        self.timestamp = timestamp or datetime.now().isoformat()
        self.src_ip = src_ip
        self.method = method
        self.path = path
        self.status_code = status_code
        self.message = message
        self.ingested_at = datetime.now().isoformat()

    def to_dict(self):
        return {
            "id": self.id,
            "source": self.source,
            "raw_line": self.raw_line,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "message": self.message,
            "ingested_at": self.ingested_at
        }


# --- Log Parsers ---

# Nginx combined log format
NGINX_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\d+)'
)

# Syslog format
SYSLOG_RE = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)'
)

# Auth log format
AUTH_RE = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)'
)

# Flask/Python access log format
FLASK_RE = re.compile(
    r'(?P<timestamp>[\d-]+\s+[\d:,]+)\s+-\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)"\s+'
    r'(?P<status>\d+)'
)


def parse_nginx_line(line):
    m = NGINX_RE.search(line)
    if m:
        return LogEvent(
            source="nginx",
            raw_line=line,
            timestamp=m.group("timestamp"),
            src_ip=m.group("ip"),
            method=m.group("method"),
            path=m.group("path"),
            status_code=int(m.group("status"))
        )
    return None


def parse_syslog_line(line):
    m = SYSLOG_RE.search(line)
    if m:
        return LogEvent(
            source="syslog",
            raw_line=line,
            timestamp=m.group("timestamp"),
            message=m.group("message")
        )
    return None


def parse_auth_line(line):
    m = AUTH_RE.search(line)
    if m:
        msg = m.group("message")
        # Extract IP from auth messages
        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
        return LogEvent(
            source="auth",
            raw_line=line,
            timestamp=m.group("timestamp"),
            src_ip=ip_match.group(1) if ip_match else None,
            message=msg
        )
    return None


def parse_flask_line(line):
    m = FLASK_RE.search(line)
    if m:
        return LogEvent(
            source="flask",
            raw_line=line,
            timestamp=m.group("timestamp"),
            src_ip=m.group("ip"),
            method=m.group("method"),
            path=m.group("path"),
            status_code=int(m.group("status"))
        )
    return None


PARSERS = {
    "combined": parse_nginx_line,
    "syslog": parse_syslog_line,
    "auth": parse_auth_line,
    "flask": parse_flask_line,
}


class LogCollector:
    """
    Continuously monitors and collects log files.
    Parses raw log lines into unified LogEvent objects and
    pushes them to the event queue for the analytics engine.
    """

    def __init__(self, config, event_queue):
        self.sources = config.get("sources", [])
        self.poll_interval = config.get("poll_interval_sec", 2)
        self.event_queue = event_queue
        self._offsets = {}  # Track read position per file
        self._stop_event = threading.Event()
        self._thread = None
        self._stats = {"total_events": 0, "errors": 0}

    def start(self):
        """Start log collection in background thread."""
        self._thread = threading.Thread(target=self._collection_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def get_stats(self):
        return dict(self._stats)

    def _collection_loop(self):
        while not self._stop_event.is_set():
            for source in self.sources:
                try:
                    self._read_source(source)
                except Exception as e:
                    self._stats["errors"] += 1
            time.sleep(self.poll_interval)

    def _read_source(self, source):
        path = source.get("path", "")
        fmt = source.get("format", "combined")
        name = source.get("name", path)

        if not os.path.exists(path):
            return

        parser = PARSERS.get(fmt, parse_nginx_line)
        offset = self._offsets.get(path, 0)

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = parser(line)
                if event:
                    self.event_queue.append(event)
                    self._stats["total_events"] += 1
            self._offsets[path] = f.tell()
