#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from github_automation.jit_pilot import validation_main  # noqa: E402

raise SystemExit(validation_main())
