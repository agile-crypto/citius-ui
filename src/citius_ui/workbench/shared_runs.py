"""Runbook progress that every signed-in browser sees.

A runbook step runs in the browser of the identity it is for, so a hand-off
(the Producer signs, the Consumer verifies) spans browsers. This store keeps,
for the whole UI process, each runbook's step results and the bundles steps
keep, so every browser draws the same diagram and goal card, and a consumer
step finds the bundle another browser kept, in the same runbook or an earlier
one (``Runbook.after``).

It holds no tokens: each browser still calls as its own identity. A step's
full request and response are shown only to the identity that ran it; other
browsers see its status, its band in the diagram, and the values its
runbook's proofs name. Memory only; Reset clears one runbook.
"""

from __future__ import annotations

import itertools
import threading
from collections.abc import Mapping
from dataclasses import dataclass

from citius_ui.showcases.replay import StepResult


@dataclass(frozen=True, slots=True)
class SharedStep:
    """A step's last result, and the identity (session subject) that ran it."""

    result: StepResult
    subject: str


class SharedRuns:
    """Each runbook's results and the bundles its steps kept, with a version that changes on every update."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # One counter for every runbook, so a version is never reused, not even after a Reset.
        self._counter = itertools.count(1)
        self._steps: dict[str, dict[int, SharedStep]] = {}
        self._last: dict[str, int] = {}
        self._version: dict[str, int] = {}
        self._bundles: dict[str, str] = {}
        self._bundle_from: dict[str, str] = {}

    def version(self, runbook: str) -> int:
        """Changes whenever the runbook's results do; 0 before anything ran."""
        with self._lock:
            return self._version.get(runbook, 0)

    def results(self, runbook: str) -> dict[int, StepResult]:
        with self._lock:
            return {index: step.result for index, step in self._steps.get(runbook, {}).items()}

    def ran_by(self, runbook: str, index: int) -> str | None:
        with self._lock:
            step = self._steps.get(runbook, {}).get(index)
            return step.subject if step is not None else None

    def last(self, runbook: str) -> StepResult | None:
        """The step that ran most recently, in any browser."""
        with self._lock:
            index = self._last.get(runbook)
            step = self._steps.get(runbook, {}).get(index) if index is not None else None
            return step.result if step is not None else None

    def bundles(self) -> dict[str, str]:
        """Every kept bundle by name, from any runbook (a copy)."""
        with self._lock:
            return dict(self._bundles)

    def record(self, runbook: str, result: StepResult, subject: str, kept: Mapping[str, str]) -> int:
        """Store a step's result and the bundles it kept; return the runbook's new version."""
        with self._lock:
            self._steps.setdefault(runbook, {})[result.index] = SharedStep(result, subject)
            self._last[runbook] = result.index
            for name, bundle in kept.items():
                self._bundles[name] = bundle
                self._bundle_from[name] = runbook
            version = self._version[runbook] = next(self._counter)
            return version

    def reset(self, runbook: str) -> int:
        """Forget the runbook's results and the bundles its steps kept; return its new version."""
        with self._lock:
            self._steps.pop(runbook, None)
            self._last.pop(runbook, None)
            for name in [name for name, source in self._bundle_from.items() if source == runbook]:
                del self._bundles[name]
                del self._bundle_from[name]
            version = self._version[runbook] = next(self._counter)
            return version
