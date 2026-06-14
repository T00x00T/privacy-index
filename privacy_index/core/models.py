from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    OK = "ok"
    INFO = "info"
    WARN = "warn"
    BAD = "bad"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    category: str
    key: str
    title: str
    status: Severity
    points: int = 0
    max_points: int = 0
    privacy: int = 0
    anonymity: int = 0
    hardening: int = 0
    evidence: str = ""
    recommendation: str = ""
    confidence: str = "medium"                     

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ScanContext:
    os_id: str = "unknown"
    os_like: str = ""
    distro_pretty_name: str = "unknown"
    package_manager: str = "unknown"
    facts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def fact(self, key: str, value: Any) -> None:
        self.facts[key] = value
