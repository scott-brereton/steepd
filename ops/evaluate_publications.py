"""Deliberate, operator-run trial of the publication classifier.

Never imported by the application and never run by the test suite: it is the only thing
here that spends money and the only thing that reads real newsletters. Two modes.

    smoke     One synthetic issue against the exact production provider restrictions.
              Proves the endpoint is reachable under zero-retention routing, that the
              output contract holds, and what the answer actually cost. No real mail.

    evaluate  A held-out trial over a private fixture directory. Issues are replayed in
              delivery order so each decision sees only the catalogue the earlier ones
              established -- the same thing that happens in production, and the only way
              a duplicate-publication rate means anything.

Fixtures and reports stay out of the repository. Point --fixtures at a directory of
JSON files: {"publication": "Stratechery", "title": ..., "byline": ..., "source_url":
..., "text": ...}. `publication` is the expected answer and is never sent; leave it blank for a negative
example that should come back unknown.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from steepd.publication_ai import (  # noqa: E402
    Deadline,
    IssueInput,
    OpenRouterClassifier,
    PublicationChoice,
)
from steepd.publications import MAX_ISSUE_TEXT_BYTES, bound_text, host_of, redact  # noqa: E402

# The plan's pilot gate: no wrong held-out assignments, and at least this share of
# clearly branded issues actually organized.
COVERAGE_GATE = 0.95

SMOKE_ISSUE = IssueInput(
    title="The Weekly Ledger - Issue 42",
    byline="Dana Okonkwo",
    language="en",
    text=(
        "THE WEEKLY LEDGER\n"
        "Issue 42 - a synthetic newsletter written for a compatibility check.\n\n"
        "This week we look at nothing in particular, because no real newsletter was used "
        "to produce this message. The Weekly Ledger is published every Tuesday.\n\n"
        "You are receiving The Weekly Ledger because you subscribed at weeklyledger.example."
    ),
    source_host="weeklyledger.example",
)


@dataclass
class Outcome:
    expected: str
    decision: str
    resolved: str
    prompt_tokens: int | None
    completion_tokens: int | None
    reasoning_tokens: int | None
    cost: str | None
    duration_ms: int


def _client(args: argparse.Namespace) -> OpenRouterClassifier:
    key = os.environ.get("LLMKEY", "").strip()
    if not key:
        raise SystemExit("LLMKEY is not set. Export the inference key before running this.")
    return OpenRouterClassifier(
        api_key=key,
        model=args.model,
        providers=tuple(p for p in (args.providers or "").split(",") if p),
        max_input_price=args.max_input_price,
        max_output_price=args.max_output_price,
        structured_outputs=not args.json_object,
        reasoning=args.reasoning,
    )


def smoke(args: argparse.Namespace) -> int:
    client = _client(args)
    started = time.monotonic()
    result = client.classify(SMOKE_ISSUE, (), deadline=Deadline(60))
    usage = result.usage
    print(f"model            {usage.model or args.model}")
    print(f"provider         {usage.provider or 'unreported'}")
    print(f"request id       {usage.request_id or 'unreported'}")
    print(f"decision         {result.classification.decision}")
    print(f"name             {result.classification.name}")
    print(f"prompt tokens    {usage.prompt_tokens}")
    print(f"output tokens    {usage.completion_tokens} (reasoning {usage.reasoning_tokens})")
    print(f"cost             {usage.cost}")
    print(f"round trip       {int((time.monotonic() - started) * 1000)} ms")
    if result.classification.decision != "new":
        print("\nNOTE: with no publications supplied, a correct answer is 'new'.")
    return 0


def _load(directory: Path) -> list[dict]:
    issues = [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]
    if not issues:
        raise SystemExit(f"No fixtures in {directory}")
    return issues


def evaluate(args: argparse.Namespace) -> int:
    client = _client(args)
    issues = _load(Path(args.fixtures))
    # Request-local ids only, exactly as the worker builds them: the trial must exercise
    # the same mapping the product uses, not a friendlier one.
    names: dict[str, str] = {}
    outcomes: list[Outcome] = []

    for index, issue in enumerate(issues, start=1):
        choices = tuple(
            PublicationChoice(request_id=key, name=name) for key, name in sorted(names.items())
        )
        text, abridged = bound_text(redact(issue["text"]), max_bytes=args.max_bytes)
        prepared = IssueInput(
            title=redact(issue.get("title", "")),
            byline=redact(issue.get("byline", "")),
            language=issue.get("language", ""),
            text=text,
            source_host=host_of(issue.get("source_url", "")),
            abridged=abridged,
        )
        result = client.classify(prepared, choices, deadline=Deadline(60))
        answer = result.classification
        if answer.decision == "existing":
            resolved = names.get(answer.request_id or "", "?")
        elif answer.decision == "new":
            resolved = answer.name or "?"
            names[f"p{len(names) + 1}"] = resolved
        else:
            resolved = "(unknown)"
        outcomes.append(
            Outcome(
                expected=issue["publication"],
                decision=answer.decision,
                resolved=resolved,
                prompt_tokens=result.usage.prompt_tokens,
                completion_tokens=result.usage.completion_tokens,
                reasoning_tokens=result.usage.reasoning_tokens,
                cost=result.usage.cost,
                duration_ms=result.usage.duration_ms,
            )
        )
        print(f"[{index}/{len(issues)}] {issue['publication']!r} -> {answer.decision} {resolved!r}")

    return _report(outcomes, Path(args.report) if args.report else None)


def _report(outcomes: list[Outcome], report_path: Path | None) -> int:
    total = len(outcomes)
    unknown = sum(1 for o in outcomes if o.decision == "unknown")
    # A negative example answered with a publication is wrong; answered unknown, right.
    wrong = [o for o in outcomes if o.decision != "unknown" and o.resolved != o.expected]
    expected_names = {o.expected for o in outcomes if o.expected}
    created = Counter(o.resolved for o in outcomes if o.decision == "new")
    duplicates = sum(count - 1 for count in created.values() if count > 1)
    prompt_tokens = [o.prompt_tokens for o in outcomes if o.prompt_tokens is not None]

    # A fixture whose expected publication is blank is a negative example -- a personal
    # message that *should* come back unknown. Counting those in the denominator marked a
    # perfectly correct run down for getting them right.
    branded = [o for o in outcomes if o.expected]
    organized = sum(1 for o in branded if o.decision != "unknown" and o.resolved == o.expected)
    coverage = organized / len(branded) if branded else 0.0
    print(f"\nissues                {total} across {len(expected_names)} publications")
    print(f"wrong assignments     {len(wrong)}")
    print(f"unknown answers       {unknown}")
    print(f"correctly organized   {organized}/{len(branded)} branded ({coverage:.1%})")
    print(f"negative examples     {total - len(branded)}")
    print(f"publications created  {len(created)} (duplicates {duplicates})")
    if prompt_tokens:
        ordered = sorted(prompt_tokens)
        print(
            f"prompt tokens         min {ordered[0]} median {ordered[len(ordered) // 2]} max {ordered[-1]}"
        )
    print(f"median latency        {sorted(o.duration_ms for o in outcomes)[total // 2]} ms")
    for outcome in wrong:
        print(f"  WRONG expected {outcome.expected!r} got {outcome.resolved!r}")

    if report_path is not None:
        report_path.write_text(json.dumps([vars(o) for o in outcomes], indent=2))
        print(f"\nwrote {report_path}")
    # The pilot gate from the plan, both halves of it. Counting only wrong assignments
    # let a run that answered "unknown" to every single issue exit successfully, which is
    # a classifier that never works passing a test for whether it works.
    passed = not wrong and coverage >= COVERAGE_GATE
    print(f"\ngate                  {'PASS' if passed else 'FAIL'} "
          f"(needs 0 wrong and >= {COVERAGE_GATE:.0%} organized)")
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("smoke", "evaluate"))
    parser.add_argument("--model", default=os.environ.get("LLMMODEL", ""), required=not os.environ.get("LLMMODEL"))
    parser.add_argument("--providers", default="", help="comma-separated provider order")
    parser.add_argument("--fixtures", help="directory of private fixture JSON files")
    parser.add_argument("--report", help="where to write the per-issue JSON report")
    parser.add_argument("--max-bytes", type=int, default=MAX_ISSUE_TEXT_BYTES)
    parser.add_argument("--max-input-price", type=float, default=0.10)
    parser.add_argument("--max-output-price", type=float, default=0.40)
    parser.add_argument("--reasoning", default=os.environ.get("NEWSLETTER_AI_REASONING", "exclude"))
    parser.add_argument("--json-object", action="store_true", help="use JSON-object mode instead of a schema")
    args = parser.parse_args()
    if args.mode == "evaluate" and not args.fixtures:
        raise SystemExit("evaluate needs --fixtures")
    return smoke(args) if args.mode == "smoke" else evaluate(args)


if __name__ == "__main__":
    raise SystemExit(main())
