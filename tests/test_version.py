"""Package/runtime version and outgoing identification must agree."""

from importlib.metadata import version

from loguard import __version__
from loguard._signing import sign
from loguard.monitor import _Monitor


def test_version_matches_installed_distribution_and_transport():
    assert __version__ == version("loguard")
    expected = f"loguard-python-sdk/{__version__}"
    assert sign("test-only-key", b"{}")[1]["User-Agent"] == expected
    assert _Monitor()._headers["User-Agent"] == expected
