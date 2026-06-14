from __future__ import annotations

from dataclasses import dataclass, asdict
from .models import Finding, Severity


@dataclass
class ScoreBundle:
    privacy: int
    anonymity: int
    hardening: int
    global_score: int
    confidence: str

    def to_dict(self) -> dict:
        return asdict(self)


def clamp20(x: int) -> int:
    return max(0, min(20, x))


def confidence_from_findings(findings: list[Finding]) -> str:
    if not findings:
        return "low"
    low = sum(1 for f in findings if f.confidence == "low" or f.status == Severity.UNKNOWN)
    ratio = low / len(findings)
    if ratio > 0.35:
        return "low"
    if ratio > 0.15:
        return "medium"
    return "high"


def compute_scores(findings: list[Finding]) -> ScoreBundle:
    privacy = sum(f.privacy for f in findings)
    anonymity = sum(f.anonymity for f in findings)
    hardening = sum(f.hardening for f in findings)

                                                                        
    privacy = clamp20(privacy)
    anonymity = clamp20(anonymity)
    hardening = clamp20(hardening)

                                                                                     
    global_score = round((privacy * 0.50) + (anonymity * 0.25) + (hardening * 0.25))
    return ScoreBundle(
        privacy=privacy,
        anonymity=anonymity,
        hardening=hardening,
        global_score=clamp20(global_score),
        confidence=confidence_from_findings(findings),
    )
