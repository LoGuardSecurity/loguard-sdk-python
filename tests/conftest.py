# Standalone command-line programs require explicit credentials and may contact
# a live service. They must never execute as pytest collection side effects.
collect_ignore_glob = ["*_e2e.py"]


def pytest_configure(config):
    try:
        from django.conf import settings
    except ImportError:
        return
    if not settings.configured:
        settings.configure(DEFAULT_CHARSET="utf-8", SECRET_KEY="test-only-key")
