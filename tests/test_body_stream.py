"""Stream observation must not alter application reads or exceed its memory budget."""

from io import BytesIO

import pytest

from loguard._body_stream import ObservedBodyStream


def test_chunked_reads_are_forwarded_and_bounded():
    original = BytesIO(b"123456789")
    stream = ObservedBodyStream(original, max_bytes=4, expected=9)
    assert stream.read(3) == b"123"
    assert stream.captured() == b"123"
    assert stream.read(6) == b"456789"
    assert stream.too_large and stream.complete
    assert stream.captured() == b""
    assert not original.closed


def test_unknown_length_requires_eof_or_read_all():
    stream = ObservedBodyStream(BytesIO(b"1234"), 32)
    assert stream.read(2) == b"12"
    assert not stream.complete
    assert stream.read() == b"34"
    assert stream.complete
    assert stream.captured() == b"1234"


def test_zero_length_read_does_not_mark_complete():
    stream = ObservedBodyStream(BytesIO(b"1234"), 32)
    assert stream.read(0) == b""
    assert not stream.complete


def test_readinto_observes_only_actual_bytes():
    stream = ObservedBodyStream(BytesIO(b"abc"), 32)
    buffer = bytearray(b"?????")
    assert stream.readinto(buffer) == 3
    assert buffer == b"abc??"
    assert stream.captured() == b"abc"
    assert not stream.complete
    assert stream.readinto(buffer) == 0
    assert stream.complete


def test_iteration_and_readlines_are_preserved():
    raw = b"one\ntwo\nthree"
    stream = ObservedBodyStream(BytesIO(raw), 32)
    assert next(stream) == b"one\n"
    assert stream.readlines() == [b"two\n", b"three"]
    assert stream.captured() == raw
    assert stream.complete


def test_successful_seek_invalidates_capture():
    stream = ObservedBodyStream(BytesIO(b"abc"), 32)
    assert stream.read(2) == b"ab"
    assert stream.seek(0) == 0
    assert stream.read() == b"abc"
    assert stream.unavailable
    assert stream.captured() == b""


def test_release_does_not_close_or_observe_later_reads():
    original = BytesIO(b"abcdef")
    stream = ObservedBodyStream(original, 32)
    assert stream.read(2) == b"ab"
    stream.release()
    assert stream.read() == b"cdef"
    assert stream.captured() == b""
    assert not original.closed
    stream.close()
    assert original.closed


def test_original_read_exception_is_preserved():
    error = OSError("application read failure")

    class Broken:
        def read(self, size):
            raise error

    stream = ObservedBodyStream(Broken(), 32)
    with pytest.raises(OSError) as exc:
        stream.read()
    assert exc.value is error
    assert stream.failed
