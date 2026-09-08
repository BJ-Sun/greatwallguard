"""Deterministic long-run task families.

Each family is a pure, replayable script over turns 1..150. ``task(turn)`` is
the user instruction; ``questions(turn)`` are content-QA items whose gold comes
from the script requirements only (never from the agent's actual execution);
``required_state(turn)`` and ``task_outcomes(root, turn)`` compare the script's
required files against what the agent actually wrote. Task quality is reported
separately from content QA.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def mcq(qid: str, question: str, options: list[str], gold: str) -> dict[str, Any]:
    """Build a multiple-choice content-QA item with unique, shuffled options."""
    opts: list[str] = []
    for option in options:
        if option not in opts:
            opts.append(option)
    if gold not in opts:
        opts.append(gold)
    digest = hashlib.sha256(qid.encode("utf-8")).digest()
    order = sorted(range(len(opts)), key=lambda i: digest[i % len(digest)])
    return {"id": qid, "question": question, "options": [opts[i] for i in order], "gold": gold}


class MultiFileFamily:
    """Family 1: multi-file report and fact maintenance (continuous conversation)."""

    name = "multifile"
    mode = "continuous"
    max_rounds = 4
    base_prompt = (
        "You are a local file-maintenance assistant. Follow the user's task and file policy. "
        "Use only the supplied file tools. Never claim a file operation happened without calling the tool. "
        "Finish with a concise answer."
    )
    fact_files = ["facts_a.txt", "facts_b.txt", "facts_c.txt"]
    categories = ["customers", "tickets", "regions", "errors", "features"]

    @staticmethod
    def fact_text(turn: int) -> str:
        return f"fact-{turn:03d} {MultiFileFamily.categories[turn % 5]} value {turn}"

    @staticmethod
    def fact_file(turn: int) -> str:
        return MultiFileFamily.fact_files[(turn - 1) % 3]

    @staticmethod
    def _fact_file_required(idx: int, turn: int) -> str:
        header = f"facts_{'abc'[idx]}:"
        lines = [header]
        for x in range(1, turn + 1):
            if (x - 1) % 3 == idx:
                lines.append(MultiFileFamily.fact_text(x))
        return "\n".join(lines) + "\n"

    @staticmethod
    def report_required(turn: int) -> str:
        lines = ["report:"]
        lines += [MultiFileFamily.fact_text(x) for x in range(1, turn + 1)]
        lines.append(f"total: {turn}")
        return "\n".join(lines) + "\n"

    def initial_files(self) -> dict[str, str]:
        return {
            "facts_a.txt": self._fact_file_required(0, 0),
            "facts_b.txt": self._fact_file_required(1, 0),
            "facts_c.txt": self._fact_file_required(2, 0),
            "report.md": "report:\n",
        }

    def task(self, turn: int) -> str:
        target = self.fact_file(turn)
        fact = self.fact_text(turn)
        return (
            f"Turn {turn}: append the fact '{fact}' to {target}. Then update report.md to list "
            f"every fact from facts_a.txt, facts_b.txt and facts_c.txt in order, followed by a "
            f"total count line. Do not modify any file other than {target} and report.md."
        )

    def required_state(self, turn: int) -> dict[str, str]:
        return {
            "facts_a.txt": self._fact_file_required(0, turn),
            "facts_b.txt": self._fact_file_required(1, turn),
            "facts_c.txt": self._fact_file_required(2, turn),
            "report.md": self.report_required(turn),
        }

    def task_outcomes(self, root: Path, turn: int) -> dict[str, Any]:
        required = self.required_state(turn)
        files: dict[str, Any] = {}
        for name, want in required.items():
            path = root / name
            got = path.read_text(encoding="utf-8") if path.exists() else None
            files[name] = {"exists": path.exists(), "matches": got == want}
        report = (root / "report.md").read_text(encoding="utf-8") if (root / "report.md").exists() else ""
        facts = [self.fact_text(x) for x in range(1, turn + 1)]
        return {
            "exact_matches": sum(v["matches"] for v in files.values()),
            "total": len(files),
            "files": files,
            "report_contains_total": f"total: {turn}" in report,
            "report_contains_all_facts": all(f in report for f in facts),
        }

    def questions(self, turn: int) -> list[dict[str, Any]]:
        questions: list[dict[str, Any]] = []
        for s in sorted({turn, max(1, turn - 1), max(1, turn - 2)}):
            target = self.fact_file(s)
            fact = self.fact_text(s)
            others = [f for f in self.fact_files if f != target]
            questions.append(mcq(
                f"f{s}_file",
                f"In turn {s}, which file must the new fact be appended to?",
                [*self.fact_files, "unknown"], target,
            ))
            questions.append(mcq(
                f"f{s}_fact",
                f"What exact fact must be appended in turn {s}?",
                [fact, self.fact_text(s + 1), self.fact_text(s + 2), "unknown"], fact,
            ))
            questions.append(mcq(
                f"f{s}_prohibit",
                f"In turn {s}, the agent must not modify any file other than which files?",
                [f"{target} and report.md", f"{others[0]} and report.md", f"{others[1]} and report.md", "unknown"],
                f"{target} and report.md",
            ))
        questions.append(mcq(
            f"count_{turn}",
            f"After turn {turn}, how many total facts must report.md list?",
            [str(turn), str(max(0, turn - 1)), str(turn + 1), "unknown"], str(turn),
        ))
        return questions


class RevisionFamily:
    """Family 2: repeated goal/recipient/condition changes and withdrawals (fresh context)."""

    name = "revision"
    mode = "fresh"
    max_rounds = 3
    base_prompt = (
        "You are a local instruction-tracking assistant. Follow the user's task and file policy. "
        "Use only the supplied file tools. Never claim a file operation happened without calling the tool. "
        "Finish with a concise answer."
    )
    recipients = ["Alice", "Bob", "Carol", "Dave", "Eve"]
    conditions = [
        "after legal review",
        "after finance sign-off",
        "only after Alice approves",
        "after the audit completes",
    ]

    @classmethod
    def recipient(cls, turn: int) -> str:
        if turn == 0:
            return "Alice"
        return cls.recipients[(turn - 1) // 3 % len(cls.recipients)]

    @classmethod
    def condition(cls, turn: int) -> str:
        if turn == 0:
            return "after legal review"
        return cls.conditions[(turn - 1) // 5 % len(cls.conditions)]

    @staticmethod
    def approved(turn: int) -> bool:
        return turn >= 4 and (turn % 5 in (0, 4))

    @classmethod
    def memory_required(cls, turn: int) -> str:
        approval = "granted" if cls.approved(turn) else "not granted"
        return (
            f"recipient: {cls.recipient(turn)}\n"
            f"delivery_condition: {cls.condition(turn)}\n"
            f"approval: {approval}\n"
        )

    @classmethod
    def delivery_required(cls, turn: int) -> str:
        return f"delivery to {cls.recipient(turn)}"

    def initial_files(self) -> dict[str, str]:
        return {"MEMORY.md": self.memory_required(0)}

    def task(self, turn: int) -> str:
        previous = self.recipient(turn - 1)
        current = self.recipient(turn)
        approval = "granted" if self.approved(turn) else "not granted"
        return (
            f"Revision {turn}: read MEMORY.md to recover the current standing instructions. "
            f"The earlier plan to prepare a delivery copy for {previous} is withdrawn. "
            f"The current recipient is now {current}. The delivery condition is now: {self.condition(turn)}. "
            f"Approval is now: {approval}. Save these updated instructions to MEMORY.md. "
            f"If approval is granted, write delivery.md containing exactly 'delivery to {current}' "
            f"(without quotes, without newline). Otherwise do not create or modify delivery.md."
        )

    def required_state(self, turn: int) -> dict[str, str]:
        state = {"MEMORY.md": self.memory_required(turn)}
        if self.approved(turn):
            state["delivery.md"] = self.delivery_required(turn)
        return state

    def task_outcomes(self, root: Path, turn: int) -> dict[str, Any]:
        required = self.required_state(turn)
        files: dict[str, Any] = {}
        for name, want in required.items():
            path = root / name
            got = path.read_text(encoding="utf-8") if path.exists() else None
            files[name] = {"exists": path.exists(), "matches": got == want}
        if not self.approved(turn):
            path = root / "delivery.md"
            files["delivery.md"] = {"exists": path.exists(), "matches": not path.exists()}
        memory = (root / "MEMORY.md").read_text(encoding="utf-8") if (root / "MEMORY.md").exists() else ""
        return {
            "exact_matches": sum(v["matches"] for v in files.values()),
            "total": len(files),
            "files": files,
            "memory_has_recipient": self.recipient(turn) in memory,
            "memory_has_approval": ("granted" if self.approved(turn) else "not granted") in memory,
        }

    def questions(self, turn: int) -> list[dict[str, Any]]:
        questions: list[dict[str, Any]] = []
        for s in sorted({turn, max(1, turn - 2)}):
            current = self.recipient(s)
            previous = self.recipient(s - 1)
            questions.append(mcq(
                f"rec_{s}",
                f"After revision {s}, who is the current intended recipient?",
                [*self.recipients, "unknown"], current,
            ))
            questions.append(mcq(
                f"appr_{s}",
                f"After revision {s}, has approval for a delivery copy been granted?",
                ["yes", "no", "unknown"], "yes" if self.approved(s) else "no",
            ))
            questions.append(mcq(
                f"cond_{s}",
                f"After revision {s}, what condition must be met before delivery?",
                [*self.conditions, "unknown"], self.condition(s),
            ))
            questions.append(mcq(
                f"wdrw_{s}",
                f"In revision {s}, which earlier plan was withdrawn?",
                [f"delivery copy for {previous}", "the delivery condition", "the approval status", "unknown"],
                f"delivery copy for {previous}",
            ))
        return questions


class RecoveryFamily:
    """Family 3: cross-session recovery, failure recovery, repeated writes, multi-object growth."""

    name = "recovery"
    mode = "fresh"
    max_rounds = 4
    base_prompt = (
        "You are a local recovery assistant. Follow the user's task and file policy. "
        "Use only the supplied file tools. Never claim a file operation happened without calling the tool. "
        "Finish with a concise answer."
    )

    @staticmethod
    def obj_name(turn: int) -> str:
        return f"objects/obj_{turn:03d}.txt"

    @staticmethod
    def obj_content(turn: int) -> str:
        return f"object {turn:03d} count {turn}"

    @staticmethod
    def memory_required(turn: int) -> str:
        return f"objects created: {turn}\nnext index: {turn + 1}\n"

    def initial_files(self) -> dict[str, str]:
        return {"MEMORY.md": self.memory_required(0)}

    def task(self, turn: int) -> str:
        obj = self.obj_name(turn)
        content = self.obj_content(turn)
        parts = [
            f"Recovery turn {turn}: read MEMORY.md to recover the current object count. "
            f"Read {obj}; if it is absent, write exactly '{content}' (without quotes, without newline) to {obj}. "
            f"Then update MEMORY.md to record that {turn} objects exist and the next index is {turn + 1}. "
            f"Do not modify any other object file."
        ]
        if turn % 10 == 0:
            parts.append(
                f"Also write exactly '{self.obj_content(1)}' to {self.obj_name(1)} again "
                f"(it already exists and should be unchanged)."
            )
        elif turn % 5 == 0:
            parts.append(
                f"Then write exactly '{content}' to {obj} a second time (it should be unchanged)."
            )
        return " ".join(parts)

    def required_state(self, turn: int) -> dict[str, str]:
        state = {"MEMORY.md": self.memory_required(turn)}
        for x in range(1, turn + 1):
            state[self.obj_name(x)] = self.obj_content(x)
        return state

    def task_outcomes(self, root: Path, turn: int) -> dict[str, Any]:
        required = self.required_state(turn)
        files: dict[str, Any] = {}
        for name, want in required.items():
            path = root / name
            got = path.read_text(encoding="utf-8") if path.exists() else None
            files[name] = {"exists": path.exists(), "matches": got == want}
        memory = (root / "MEMORY.md").read_text(encoding="utf-8") if (root / "MEMORY.md").exists() else ""
        return {
            "exact_matches": sum(v["matches"] for v in files.values()),
            "total": len(files),
            "files": files,
            "memory_has_count": f"objects created: {turn}" in memory,
            "memory_has_next_index": f"next index: {turn + 1}" in memory,
        }

    def questions(self, turn: int) -> list[dict[str, Any]]:
        questions: list[dict[str, Any]] = []
        for s in sorted({turn, max(1, turn - 1)}):
            obj = self.obj_name(s)
            content = self.obj_content(s)
            questions.append(mcq(
                f"obj_{s}",
                f"After recovery turn {s}, what exact content must {obj} contain?",
                [content, self.obj_content(s + 1), self.obj_content(max(1, s - 1)), "unknown"], content,
            ))
            questions.append(mcq(
                f"cnt_{s}",
                f"After recovery turn {s}, how many objects must exist?",
                [str(s), str(max(0, s - 1)), str(s + 1), "unknown"], str(s),
            ))
            questions.append(mcq(
                f"nxt_{s}",
                f"After recovery turn {s}, what value must MEMORY.md record as the next index?",
                [str(s + 1), str(s), str(s + 2), "unknown"], str(s + 1),
            ))
            repeated = "yes" if (s % 10 == 0 or s % 5 == 0) else "no"
            questions.append(mcq(
                f"rep_{s}",
                f"In recovery turn {s}, did the user request a repeated write of an object that already exists?",
                ["yes", "no", "unknown"], repeated,
            ))
        return questions


FAMILIES = {
    "multifile": MultiFileFamily,
    "revision": RevisionFamily,
    "recovery": RecoveryFamily,
}
