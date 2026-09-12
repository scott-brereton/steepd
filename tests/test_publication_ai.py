from __future__ import annotations

import json

import httpx
import pytest

from steepd.publication_ai import (
    MAX_RESPONSE_BYTES,
    ClassifierError,
    Deadline,
    IssueInput,
    OpenRouterClassifier,
    PublicationChoice,
    validate_answer,
)

CHOICES = (
    PublicationChoice(request_id="p1", name="Stratechery"),
    PublicationChoice(request_id="p2", name="Dense Discovery"),
)
ISSUE = IssueInput(title="Issue 1", byline="Ben", language="en", text="Body")


def _answer(**fields):
    return {"decision": None, "publication_id": None, "publication_name": None} | fields


def _reply(answer, *, finish_reason="stop", status=200, extra=None):
    document = {
        "id": "req-1",
        "model": "test/model",
        "provider": "TestProvider",
        "choices": [{"finish_reason": finish_reason, "message": {"content": json.dumps(answer)}}],
        "usage": {"prompt_tokens": 1200, "completion_tokens": 30, "cost": "0.00012"},
    } | (extra or {})
    return httpx.Response(status, json=document)


def _client(handler, **kwargs):
    return OpenRouterClassifier(
        api_key="sk-or-test", model="test/model", transport=httpx.MockTransport(handler), **kwargs
    )


# -- the output contract ----------------------------------------------------


def test_an_existing_choice_must_be_one_we_offered():
    assert validate_answer(_answer(decision="existing", publication_id="p1"), CHOICES).request_id == "p1"

    with pytest.raises(ClassifierError) as invented:
        validate_answer(_answer(decision="existing", publication_id="p9"), CHOICES)
    assert invented.value.code == "unknown_publication_id"


@pytest.mark.parametrize(
    "answer",
    [
        {"decision": "maybe", "publication_id": None, "publication_name": None},
        # Cross-field rules: a chosen id may not also carry a name.
        _answer(decision="existing", publication_id="p1", publication_name="Stratechery"),
        _answer(decision="new"),
        _answer(decision="unknown", publication_name="Stratechery"),
        _answer(decision="new", publication_name=123),
        # An answer shaped differently from the one asked for is not understood.
        {"decision": "unknown", "publication_id": None},
        {**_answer(decision="unknown"), "extra": 1},
        "not an object",
    ],
)
def test_an_answer_outside_the_contract_is_refused(answer):
    with pytest.raises(ClassifierError):
        validate_answer(answer, CHOICES)


@pytest.mark.parametrize("name", ["", "x" * 121, "https://example.com", "www.example.com", "<b>Bold</b>", "a\x00b"])
def test_a_name_that_is_not_a_plain_label_is_refused(name):
    with pytest.raises(ClassifierError):
        validate_answer(_answer(decision="new", publication_name=name), CHOICES)


# -- the client -------------------------------------------------------------


def test_a_successful_call_carries_the_provider_restrictions_and_reports_usage():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        seen["auth"] = request.headers["authorization"]
        return _reply(_answer(decision="existing", publication_id="p1"))

    result = _client(handler, providers=["DeepInfra"], max_input_price=0.1).classify(
        ISSUE, CHOICES, deadline=Deadline(30)
    )

    assert result.classification.request_id == "p1"
    assert seen["provider"]["data_collection"] == "deny"
    assert seen["provider"]["zdr"] is True
    assert seen["provider"]["require_parameters"] is True
    assert seen["provider"]["allow_fallbacks"] is False
    assert seen["provider"]["max_price"] == {"prompt": 0.1}
    assert seen["reasoning"] == {"exclude": True}, "the least thinking the endpoint will do"
    assert seen["auth"].startswith("Bearer ")
    assert (result.usage.prompt_tokens, result.usage.cost) == (1200, "0.00012")


def test_the_prompt_carries_the_issue_and_choices_but_no_real_identifiers():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return _reply(_answer(decision="unknown"))

    _client(handler).classify(ISSUE, CHOICES, deadline=Deadline(30))

    payload = json.loads(seen["messages"][1]["content"])
    assert [choice["id"] for choice in payload["publications"]] == ["p1", "p2"]
    assert payload["issue"]["text"] == "Body"


@pytest.mark.parametrize(
    ("status", "code", "paused", "retryable"),
    [
        (429, "rate_limited", False, True),
        (401, "auth_rejected", True, False),
        (402, "credit_exhausted", True, False),
        (503, "provider_unavailable", False, True),
        (400, "request_rejected", False, False),
    ],
)
def test_each_http_failure_maps_to_one_sanitized_code(status, code, paused, retryable):
    client = _client(lambda request: httpx.Response(status, json={"error": {"message": "provider detail"}}))

    with pytest.raises(ClassifierError) as failure:
        client.classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert (failure.value.code, failure.value.paused, failure.value.retryable) == (code, paused, retryable)


@pytest.mark.parametrize(
    ("reply", "code"),
    [
        (_reply(_answer(decision="unknown"), finish_reason="length"), "truncated"),
        (httpx.Response(200, json={"choices": [{"message": {"refusal": "no"}}]}), "refused"),
        (httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]}), "invalid_json"),
        (httpx.Response(200, json={"choices": [{"message": {"content": ""}}]}), "empty_answer"),
        (httpx.Response(200, content=b"<html>gateway</html>"), "invalid_response"),
    ],
)
def test_an_unusable_answer_fails_without_a_second_model_repairing_it(reply, code):
    with pytest.raises(ClassifierError) as failure:
        _client(lambda request: reply).classify(ISSUE, CHOICES, deadline=Deadline(30))
    assert failure.value.code == code


def test_a_timeout_is_retryable_rather_than_terminal():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(ClassifierError) as failure:
        _client(handler).classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert (failure.value.code, failure.value.retryable) == ("timeout", True)


def test_an_oversized_response_body_is_refused_rather_than_buffered():
    oversized = httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1024))

    with pytest.raises(ClassifierError) as failure:
        _client(lambda request: oversized).classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert failure.value.code == "response_too_large"


def test_an_exhausted_time_budget_stops_the_attempt_before_it_is_sent():
    called = False

    def handler(request):
        nonlocal called
        called = True
        return _reply(_answer(decision="unknown"))

    with pytest.raises(ClassifierError) as failure:
        _client(handler).classify(ISSUE, CHOICES, deadline=Deadline(-1))

    assert failure.value.code == "time_budget_exhausted"
    assert called is False


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("off", {"enabled": False}), ("exclude", {"exclude": True}), ("minimal", {"effort": "minimal"})],
)
def test_the_reasoning_setting_reaches_the_request(mode, expected):
    """Reasoning is billed output, and some endpoints refuse to have it switched off, so
    how much of it to pay for is a setting confirmed per endpoint rather than a guess."""
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return _reply(_answer(decision="unknown"))

    _client(handler, reasoning=mode).classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert seen["reasoning"] == expected


def test_an_unknown_reasoning_mode_is_refused_at_construction():
    with pytest.raises(ValueError):
        _client(lambda request: _reply(_answer(decision="unknown")), reasoning="maximum")


@pytest.mark.parametrize(
    ("status", "code", "paused", "retryable"),
    [(401, "auth_rejected", True, False), (503, "provider_unavailable", False, True)],
)
def test_a_huge_error_body_cannot_disguise_what_the_failure_was(status, code, paused, retryable):
    """What a failure *is* comes from the status line, and the body is never read.

    Reading it first meant an oversized rejected-key response became "response too large",
    which is neither a pause nor a retry -- so the worker kept spending against a key that
    had already been refused.
    """
    huge = httpx.Response(status, content=b"x" * (MAX_RESPONSE_BYTES * 3))

    with pytest.raises(ClassifierError) as failure:
        _client(lambda request: huge).classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert (failure.value.code, failure.value.paused, failure.value.retryable) == (code, paused, retryable)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("3600", 3600.0),
        ("0", 0.0),
        # Reported as asked. Neither clamped nor discarded: the caller declines to retry
        # at all rather than shortening a week into something more convenient.
        ("604800", 604800.0),
        # "nan" and "inf" parse as floats and sail through every comparison, then fail
        # much later inside a timedelta with the item stuck mid-flight.
        ("nan", None),
        ("inf", None),
        # A date already in the past is no wait, not a negative one.
        ("Wed, 21 Oct 2020 07:28:00 GMT", 0.0),
        ("-5", 0.0),
        ("junk", None),
        (None, None),
    ],
)
def test_retry_after_is_honoured_in_either_form_and_never_silently_reduced(header, expected):
    headers = {"Retry-After": header} if header is not None else {}
    client = _client(lambda request: httpx.Response(429, json={}, headers=headers))

    with pytest.raises(ClassifierError) as failure:
        client.classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert failure.value.retry_after == expected


def test_a_future_dated_retry_after_is_converted_to_a_delay():
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    when = format_datetime(datetime.now(UTC) + timedelta(minutes=30))
    client = _client(lambda request: httpx.Response(429, json={}, headers={"Retry-After": when}))

    with pytest.raises(ClassifierError) as failure:
        client.classify(ISSUE, CHOICES, deadline=Deadline(30))

    assert 1700 <= failure.value.retry_after <= 1800
