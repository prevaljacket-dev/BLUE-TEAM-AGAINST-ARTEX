import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SAMPLE = ROOT.parent / "samples" / "access_demo.log"


@pytest.fixture
def cfg(tmp_path):
    from artex_soar.config import load_config
    c = load_config(str(ROOT / "config" / "soar.yml"))
    c["_base_dir"] = str(tmp_path)
    c["database"] = ":memory:"
    c["inventory"] = {"hosts": ["web01"]}
    return c


@pytest.fixture
def engine(cfg):
    from artex_soar.engine import Engine
    from artex_soar.store import Store
    return Engine(cfg, Store(":memory:"))


@pytest.fixture
def sample_lines():
    with open(SAMPLE) as f:
        return f.readlines()
