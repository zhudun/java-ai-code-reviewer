from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "vulnerable-shop"


@pytest.fixture
def example_root() -> Path:
    return EXAMPLE
