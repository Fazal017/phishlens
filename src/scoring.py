"""Scoring engine: weighted findings -> 0-100 risk score + risk band.

Every finding carries a stable rule id, a severity, a weight, a plain
English explanation and a remediation step. The score is the sum of
weights, capped at 100. No single low-severity signal can push a URL
into High on its own; High/Critical requires several signals or one
critical one (IP host, punycode, lookalike brand, display-name spoof).
"""

from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    rule_id: str
    severity: str  # info | low | medium | high | critical
    weight: int
    title: str
    explanation: str
    remediation: str

    def to_dict(self):
        return asdict(self)


@dataclass
class AnalysisResult:
    target: str
    kind: str  # "url" | "email"
    score: int = 0
    findings: list = field(default_factory=list)

    @property
    def risk(self):
        if self.score >= 80:
            return "Critical"
        if self.score >= 60:
            return "High"
        if self.score >= 30:
            return "Medium"
        return "Low"

    @property
    def verdict(self):
        if self.score >= 60:
            return "Likely phishing — do not visit / do not trust"
        if self.score >= 30:
            return "Suspicious — verify through an official channel first"
        return "Looks legitimate on these heuristics — still stay alert"

    def add(self, rule_id, severity, weight, title, explanation, remediation):
        self.findings.append(Finding(rule_id, severity, weight, title,
                                     explanation, remediation))

    def finalize(self):
        self.score = min(100, sum(f.weight for f in self.findings))
        # Highest severity first, then heaviest weight — the most
        # decision-relevant findings read first in every output format.
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda f: (order.get(f.severity, 5), -f.weight))
        return self

    def to_dict(self):
        return {
            "target": self.target,
            "kind": self.kind,
            "score": self.score,
            "risk": self.risk,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
        }
