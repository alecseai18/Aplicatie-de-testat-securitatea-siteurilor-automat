from __future__ import annotations

import dataclasses
from typing import List, Tuple


@dataclasses.dataclass
class Finding:
    name: str
    status: str
    severity: str
    evidence: str
    url: str
    request: str = ""
    recommendation: str = ""


@dataclasses.dataclass
class Form:
    action: str
    method: str
    inputs: List[Tuple[str, str]]
    source: str
