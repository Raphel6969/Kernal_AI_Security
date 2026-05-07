"""
conftest.py — pytest configuration for large_test_set.

Resets all backend singletons before each test so state from one test
does not bleed into the next. Run from the project root:

    pytest large_test_set/ -v
"""

import sys
import os
import pytest

# Make the project root importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture(autouse=True)
def reset_singletons():
    """
    Reset every module-level singleton before each test.
    This prevents state leaking between tests (e.g. event store counts,
    cached pipeline instances, ML scorer).
    """
    import backend.detection.rule_engine as re_mod
    import backend.detection.ml_scorer as ml_mod
    import backend.detection.pipeline as pipe_mod
    import backend.events.event_store as es_mod
    import backend.kernel.execve_hook as hook_mod
    import backend.kernel.rce_monitor as rce_mod

    re_mod._rule_engine = None
    ml_mod._ml_scorer = None
    pipe_mod._detection_pipeline = None
    es_mod._event_store = None
    hook_mod._hook_manager = None
    rce_mod._rce_monitor = None

    yield  # run the test

    # teardown: reset again after test
    re_mod._rule_engine = None
    ml_mod._ml_scorer = None
    pipe_mod._detection_pipeline = None
    es_mod._event_store = None
    hook_mod._hook_manager = None
    rce_mod._rce_monitor = None
