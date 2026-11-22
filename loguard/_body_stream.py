"""Bounded observation of synchronous request streams used by Django."""

from __future__ import annotations


class ObservedBodyStream:
    """Forward reads unchanged, retaining at most max_bytes for telemetry.

    The middleware releases its capture after the application returns. It does
    not close or drain the application-owned stream during cleanup.
    """

    def __init__(self, stream, max_bytes: int, expected: int | None = None):
        self._stream = stream
        self._max_bytes = max_bytes
        self._expected = expected
        self._raw = bytearray()
        self._seen = 0
        self._recording = True
        self.complete = expected == 0
        self.too_large = False
        self.unavailable = False
        try:
            position = stream.tell()
            self.unavailable = isinstance(position, int) and position != 0
        except Exception:
            pass
        self.failed = False

    def _observe(self, data, *, all_read=False, eof=False):
        if not self._recording:
            return
        try:
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise TypeError("Expected a binary request stream")
            self._seen += len(data)
            self.complete = (
                self.complete
                or all_read
                or eof
                or (self._expected is not None and self._seen == self._expected)
            )
            if not self.too_large and not self.unavailable:
                if len(self._raw) + len(data) > self._max_bytes:
                    self.too_large = True
                    self._raw.clear()
                else:
                    self._raw.extend(data)
        except Exception:
            # Only instrumentation errors are suppressed. Underlying read
            # exceptions propagate unchanged from _read().
            self.failed = True
            self._raw.clear()

    def _read(self, method, *args):
        try:
            return method(*args)
        except Exception:
            self.failed = True
            self._raw.clear()
            raise

    def read(self, size=-1):
        data = self._read(self._stream.read, size)
        self._observe(
            data, all_read=size is None or size < 0, eof=data == b"" and size != 0
        )
        return data

    def readline(self, size=-1):
        data = self._read(self._stream.readline, size)
        self._observe(data, eof=data == b"" and size != 0)
        return data

    def readlines(self, hint=-1):
        lines = self._read(self._stream.readlines, hint)
        for line in lines:
            self._observe(line)
        if self._recording and (hint is None or hint <= 0 or not lines):
            self.complete = True
        return lines

    def readinto(self, buffer):
        count = self._read(self._stream.readinto, buffer)
        if count is not None:
            try:
                self._observe(
                    memoryview(buffer).cast("B")[:count],
                    eof=count == 0 and len(buffer) > 0,
                )
            except Exception:
                self.failed = True
                self._raw.clear()
        return count

    def seek(self, *args):
        result = self._stream.seek(*args)
        self.unavailable = True
        self.complete = False
        self._raw.clear()
        return result

    def close(self):
        return self._stream.close()

    def release(self):
        self._recording = False
        self._raw.clear()

    def captured(self) -> bytes:
        return bytes(self._raw)

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def __enter__(self):
        self._stream.__enter__()
        return self

    def __exit__(self, *args):
        return self._stream.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self._stream, name)
