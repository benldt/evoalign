from dataclasses import dataclass
from enum import Enum
from typing import Optional


class InvariantResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class InvariantCheck:
    """Result of an invariant check."""
    name: str
    result: InvariantResult
    message: str
    details: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "result": self.result.value,
            "message": self.message,
            "details": self.details,
        }


class InvariantChecker:
    """Base class for invariant checkers."""

    def __init__(self, repo_root):
        self.repo_root = repo_root

    def check(self) -> InvariantCheck:
        raise NotImplementedError
