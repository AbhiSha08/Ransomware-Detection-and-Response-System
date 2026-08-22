"""
tests/test_config.py
====================
Unit tests for backend.core.config settings loader and validation rules.
"""

import pytest
from pydantic import ValidationError

from backend.core.config import (
    Settings,
    DetectorWeights,
    ResponseMode,
    settings,
)


def test_config_singleton_loaded() -> None:
    """Verify settings singleton is properly instantiated."""
    assert settings.app.name == "Ransomware Detection and Response System"
    assert settings.app.version == "1.0.0"
    assert settings.threat_scoring.window_seconds == 60


def test_detector_weights_sum_validation() -> None:
    """Detector weights must sum to 1.0; invalid sum raises ValidationError."""
    valid_weights = DetectorWeights(
        file_rename=0.30,
        entropy=0.25,
        process_chain=0.20,
        shadow_copy=0.15,
        network_beacon=0.10,
    )
    assert valid_weights.file_rename == 0.30

    with pytest.raises(ValidationError):
        DetectorWeights(
            file_rename=0.50,
            entropy=0.50,
            process_chain=0.50,
            shadow_copy=0.15,
            network_beacon=0.10,
        )


def test_response_mode_active_guard() -> None:
    """Setting mode='active' without active_mode_authorized=True must raise ValidationError."""
    with pytest.raises(ValidationError):
        ResponseMode(mode="active", active_mode_authorized=False)

    valid_active = ResponseMode(mode="active", active_mode_authorized=True)
    assert valid_active.mode == "active"


def test_watch_paths_resolution() -> None:
    """Verify watch paths helper returns Path objects."""
    paths = settings.get_watch_paths()
    assert isinstance(paths, list)
    assert len(paths) >= 1
