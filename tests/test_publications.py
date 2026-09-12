from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from steepd.config import Settings
from steepd.db import Database
from steepd.epubgen import build_epub
from steepd.newsletter import NewsletterResource
from steepd.publication_ai import OpenRouterClassifier
from steepd.publications import (
    DOCUMENT_MEMBER,
    MAX_CHOICES,
    NewsletterDocumentError,
    Organizer,
    bound_text,
    prepare_issue,
    read_stored_document,
    redact,
    visible_text,
)
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


@pytest.fixture
def world(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        public_base_url="http://localhost:8000",
        newsletter_ai_enabled=True,
        newsletter_ai_key="sk-or-test",
        newsletter_ai_model="test/model",
        newsletter_ai_daily_limit=5,
    )
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    return settings, database, storage


def _store_issue(database, storage, scope, *, title="Weekly issue", body="<p>Something to read.</p>", images=()):
    payload = build_epub(
        title=title, author="Ben Thompson", language="en", identifier="urn:test", body_html=body, resources=images
    )
    return storage.store_bytes(
        scope, payload, filename=f"{title}.epub", kind="article", source="newsletter",
        title=title, author="Ben Thompson", source_url="https://stratechery.com/2026/issue",
    ).item


def _enable(database, scope):
    database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=None, now=NOW.isoformat()
    )


def _organizer(world, handler, **overrides):
    settings, database, storage = world
    settings = replace(settings, **overrides) if overrides else settings
    classifier = OpenRouterClassifier(
        api_key="sk-or-test", model="test/model", transport=httpx.MockTransport(handler)
    )
    return Organizer(database, storage, settings, classifier, clock=lambda: NOW)


def _run(organizer, at):
    """One pass with the clock fixed at `at`, so claim, dispatch and commit agree on the time."""
    organizer.clock = lambda: at
    return organizer.run_once()



def _publication(database, scope, publication_id, name, *, now):
    """A publication row without an issue, the way an owner's earlier correction left one.

    Inserted directly: production creates publications only alongside an assignment, and
    these tests want the bare record to exercise everything downstream of that.
    """
    with database._connect() as connection:
        connection.execute(
            """
            INSERT INTO publications (
                tenant_id, id, name, original_name, identification_note, merged_into_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, '', NULL, ?, ?)
            """,
            (scope.tenant_id, publication_id, name, name, now, now),
        )

def _reply(**fields):
    answer = {
        "decision": None, "publication_id": None, "publication_name": None
    } | fields
    return httpx.Response(
        200,
        json={
            "id": "req", "model": "test/model", "provider": "Test",
            "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(answer)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10},
        },
    )


# -- reading the stored newsletter ------------------------------------------


def test_the_generated_newsletter_is_read_from_its_known_member(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope, body="<p>Hello from the masthead.</p>")

    document = read_stored_document(storage.path_for(item), max_bytes=1_000_000)

    assert "Hello from the masthead." in document
    with zipfile.ZipFile(storage.path_for(item)) as archive:
        assert DOCUMENT_MEMBER in archive.namelist()


def test_an_issue_with_inline_images_still_reads_from_the_same_member(world):
    """Images add archive members, so the reader must not assume a fixed member count."""
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    images = (NewsletterResource(location="images/1.png", content_type="image/png", content=b"\x89PNG\r\n\x1a\n"),)
    item = _store_issue(database, storage, scope, body='<p>Text</p><img src="images/1.png">', images=images)

    assert "Text" in read_stored_document(storage.path_for(item), max_bytes=1_000_000)


def test_a_missing_or_corrupt_document_is_a_recoverable_failure_not_a_crash(tmp_path):
    empty = tmp_path / "empty.epub"
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip")
    with pytest.raises(NewsletterDocumentError) as missing:
        read_stored_document(empty, max_bytes=1_000)
    assert missing.value.code == "document_missing"

    corrupt = tmp_path / "corrupt.epub"
    corrupt.write_bytes(b"not a zip at all")
    with pytest.raises(NewsletterDocumentError) as unreadable:
        read_stored_document(corrupt, max_bytes=1_000)
    assert unreadable.value.code == "document_unreadable"


def test_the_document_read_is_bounded_even_when_the_header_understates_it(tmp_path):
    path = tmp_path / "big.epub"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(DOCUMENT_MEMBER, "x" * 5_000)

    with pytest.raises(NewsletterDocumentError) as failure:
        read_stored_document(path, max_bytes=1_000)

    assert failure.value.code == "document_too_large"


def test_visible_text_keeps_the_masthead_the_footer_and_paragraph_boundaries():
    text = visible_text(
        "<html><head><title>t</title></head><body>"
        '<div style="display:none">Preheader nobody reads</div>'
        "<p>THE PRAGMATIC ENGINEER</p><p>Body paragraph.</p>"
        "<script>ignored()</script>"
        "<p>You are receiving this because you subscribed.</p>"
        "</body></html>"
    )

    assert text.splitlines() == [
        "THE PRAGMATIC ENGINEER",
        "Body paragraph.",
        "You are receiving this because you subscribed.",
    ]
    assert "Preheader" not in text and "ignored" not in text


def test_redaction_keeps_the_article_and_drops_addresses_paths_and_secrets():
    redacted = redact(
        "Read https://stratechery.com/2026/09/the-issue?utm_source=x#top -- "
        "reply to ada@example.com. Key sk-or-v1-abcdefghijklmnopqrstuvwxyz012345."
    )

    assert "stratechery.com" in redacted, "the host is the part that says who published it"
    assert "the-issue" not in redacted and "utm_source" not in redacted
    assert "ada@example.com" not in redacted and "[address]" in redacted
    assert "sk-or-v1-abcdefghijklmnopqrstuvwxyz012345" not in redacted


def test_an_oversized_issue_keeps_its_opening_and_ending_and_says_it_was_abridged():
    text, abridged = bound_text("START" + ("filler " * 5_000) + "END", max_bytes=200)

    assert abridged is True
    assert text.startswith("START") and text.endswith("END")
    assert "[...]" in text, "the omission is disclosed, not silent"


def test_a_short_issue_is_sent_whole(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope, body="<p>Short and complete.</p>")
    document = read_stored_document(storage.path_for(item), max_bytes=1_000_000)

    issue = prepare_issue(item, document)

    assert issue.abridged is False and "Short and complete." in issue.text
    assert issue.source_host == "stratechery.com"


# -- the worker -------------------------------------------------------------


def test_an_imported_newsletter_is_discovered_by_absence_and_organized(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _store_issue(database, storage, scope)
    _enable(database, scope)
    organizer = _organizer(world, lambda request: _reply(decision="new", publication_name="Stratechery"))

    assert _run(organizer, NOW) is True

    summaries = database.list_publication_summaries(scope)
    assert [(s.publication.name, s.issue_count) for s in summaries] == [("Stratechery", 1)]
    assert _run(organizer, NOW) is False, "there is no work left to find"


def test_nothing_is_attempted_while_the_setting_is_off(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _store_issue(database, storage, scope)

    def handler(request):
        raise AssertionError("a disabled account must not reach the network")

    assert _run(_organizer(world, handler), NOW) is False


def test_re_enabling_picks_up_the_deliveries_that_arrived_while_it_was_off(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _enable(database, scope)
    revision = database.newsletter_preferences(scope).settings_revision
    database.set_newsletter_organization(
        scope, enabled=False, consent_version=1, settings_revision=revision, now=NOW.isoformat()
    )
    _store_issue(database, storage, scope)
    organizer = _organizer(world, lambda request: _reply(decision="new", publication_name="Stratechery"))
    assert _run(organizer, NOW) is False

    revision = database.newsletter_preferences(scope).settings_revision
    database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=revision, now=NOW.isoformat()
    )

    assert _run(organizer, NOW) is True


def test_books_and_saved_pages_never_become_work(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    payload = build_epub(title="A page", author="", language="en", identifier="u", body_html="<p>x</p>")
    storage.store_bytes(scope, payload, filename="p.epub", kind="article", source="url", title="A page")
    _enable(database, scope)

    def handler(request):
        raise AssertionError("only newsletters are classified")

    assert _run(_organizer(world, handler), NOW) is False


def test_tenants_take_turns_rather_than_one_backlog_starving_another(world):
    settings, database, storage = world
    scopes = []
    for name in ("ada", "bob"):
        tenant = database.create_tenant(email=f"{name}@example.com", inbox_local=name)
        scope = TenantScope(tenant.id)
        for index in range(2):
            _store_issue(database, storage, scope, title=f"{name} issue {index}")
        _enable(database, scope)
        scopes.append(scope)
    organizer = _organizer(world, lambda request: _reply(decision="unknown"))

    served = []
    for index in range(4):
        _run(organizer, NOW + timedelta(seconds=index))
        served.append(
            [database.organization_progress(scope, retention_cutoff=None).outstanding for scope in scopes]
        )

    assert served[0] != served[1], "the second pass must serve the other account"
    assert served[-1] == [0, 0]


def test_an_unknown_answer_is_a_result_not_a_failure(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    calls = []

    def handler(request):
        calls.append(1)
        return _reply(decision="unknown")

    organizer = _organizer(world, handler)
    _run(organizer, NOW)

    assert database.organization_row(scope, item.id)["state"] == "unrecognized"
    assert _run(organizer, NOW) is False, "an unknown answer is not retried automatically"
    assert len(calls) == 1


def test_a_transient_failure_retries_once_and_then_gives_up(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503, json={"error": "unavailable"})

    organizer = _organizer(world, handler)
    _run(organizer, NOW)
    assert database.organization_row(scope, item.id)["state"] == "retry"

    _run(organizer, NOW + timedelta(minutes=5))
    row = database.organization_row(scope, item.id)

    assert (row["state"], row["attempts"], row["error_code"]) == ("failed", 2, "provider_unavailable")
    assert len(calls) == 2, "two inference attempts per cycle, never a third"


def test_a_rejected_key_pauses_the_worker_instead_of_burning_the_allowance(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    for index in range(3):
        _store_issue(database, storage, scope, title=f"Issue {index}")
    _enable(database, scope)
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(401, json={"error": "bad key"})

    organizer = _organizer(world, handler)
    _run(organizer, NOW)
    _run(organizer, NOW)

    assert organizer.status.paused_code == "auth_rejected"
    assert len(calls) == 1, "one rejection stops dispatch; it is not rediscovered per item"
    assert database.organization_progress(scope, retention_cutoff=None).outstanding == 3


def test_the_daily_allowance_stops_dispatch_and_leaves_the_work_waiting(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    for index in range(3):
        _store_issue(database, storage, scope, title=f"Issue {index}")
    _enable(database, scope)
    organizer = _organizer(world, lambda request: _reply(decision="unknown"), newsletter_ai_daily_limit=2)

    for index in range(3):
        _run(organizer, NOW + timedelta(seconds=index))

    assert database.newsletter_preferences(scope).attempts_today == 2
    assert database.organization_progress(scope, retention_cutoff=None).waiting == 1

    _run(organizer, NOW + timedelta(days=1))
    assert database.newsletter_preferences(scope).attempts_today == 1, "the allowance resets on the next UTC day"


def test_a_manual_correction_made_during_the_request_survives_the_answer(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    _publication(database, scope, "chosen", "Dense Discovery", now=NOW.isoformat())

    def handler(request):
        # The owner corrects the item while the request is in flight.
        database.assign_publication_manually(scope, item.id, publication_id="chosen", now=NOW.isoformat())
        return _reply(decision="new", publication_name="Stratechery")

    _run(_organizer(world, handler), NOW)

    assert database.organization_row(scope, item.id)["publication_id"] == "chosen"
    assert database.canonical_publications(scope) == [
        p for p in database.canonical_publications(scope) if p.id == "chosen"
    ], "a refused answer leaves no publication behind"


def test_turning_the_setting_off_during_the_request_discards_the_answer(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)

    def handler(request):
        revision = database.newsletter_preferences(scope).settings_revision
        database.set_newsletter_organization(
            scope, enabled=False, consent_version=1, settings_revision=revision, now=NOW.isoformat()
        )
        return _reply(decision="new", publication_name="Stratechery")

    _run(_organizer(world, handler), NOW)

    assert database.canonical_publications(scope) == []
    assert database.organization_row(scope, item.id)["publication_id"] is None


def test_an_unreadable_file_fails_the_item_without_spending_an_attempt(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    storage.path_for(item).write_bytes(b"corrupted on disk")

    def handler(request):
        raise AssertionError("nothing should be sent for an unreadable file")

    _run(_organizer(world, handler), NOW)

    row = database.organization_row(scope, item.id)
    assert (row["state"], row["error_code"]) == ("failed", "document_unreadable")
    assert database.newsletter_preferences(scope).attempts_today == 0


def test_a_second_issue_joins_the_publication_the_first_one_established(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _store_issue(database, storage, scope, title="Issue 1")
    _enable(database, scope)
    seen_choices = []

    def handler(request):
        payload = json.loads(json.loads(request.content)["messages"][1]["content"])
        seen_choices.append([choice["name"] for choice in payload["publications"]])
        if not payload["publications"]:
            return _reply(decision="new", publication_name="Stratechery")
        return _reply(decision="existing", publication_id=payload["publications"][0]["id"])

    organizer = _organizer(world, handler)
    _run(organizer, NOW)
    _store_issue(database, storage, scope, title="Issue 2")
    _run(organizer, NOW + timedelta(minutes=1))

    assert seen_choices == [[], ["Stratechery"]]
    assert [s.issue_count for s in database.list_publication_summaries(scope)] == [2]


def test_a_paid_only_deployment_leaves_free_accounts_alone(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _store_issue(database, storage, scope)
    _enable(database, scope)

    def handler(request):
        raise AssertionError("a free account is out of scope for this deployment")

    organizer = _organizer(world, handler, newsletter_ai_plans=("paid",))
    assert _run(organizer, NOW) is False

    database.set_tenant_plan(tenant.id, "paid")
    organizer.classifier = OpenRouterClassifier(
        api_key="k", model="m", transport=httpx.MockTransport(lambda r: _reply(decision="unknown"))
    )
    assert _run(organizer, NOW) is True


def test_an_expired_item_is_not_organized_even_if_the_sweep_has_not_run(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _store_issue(database, storage, scope)
    _enable(database, scope)

    def handler(request):
        raise AssertionError("an expired item is not eligible work")

    # Free retention is seven days; this pass runs a month after the issue arrived.
    assert _run(_organizer(world, handler), NOW + timedelta(days=30)) is False


def test_no_inference_client_means_reading_continues_untouched(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)

    organizer = Organizer(database, storage, settings, None)

    assert _run(organizer, NOW) is False
    assert database.get_item(scope, item.id) is not None
    assert database.organization_row(scope, item.id) is None


# -- regressions from review ------------------------------------------------


def test_a_slow_request_whose_lease_expires_cannot_commit_its_answer(world):
    """Time really passes across the request, so the lease check has something to catch."""
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    clock = {"now": NOW}

    def handler(request):
        # Time passes while the request is out, which is the whole point: the lease was
        # 120 seconds and this took ten minutes.
        clock["now"] = NOW + timedelta(minutes=10)
        return _reply(decision="new", publication_name="Stratechery")

    organizer = Organizer(
        database, storage, settings,
        OpenRouterClassifier(api_key="k", model="m", transport=httpx.MockTransport(handler)),
        clock=lambda: clock["now"],
    )
    organizer.run_once()

    assert database.canonical_publications(scope) == [], "an expired lease must refuse a late answer"
    assert database.organization_row(scope, item.id)["publication_id"] is None


def test_preparation_that_runs_long_does_not_pay_for_a_request_it_never_sends(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    def handler(request):
        raise AssertionError("the budget was gone before this was worth sending")

    organizer = Organizer(
        database, storage, settings,
        OpenRouterClassifier(api_key="k", model="m", transport=httpx.MockTransport(handler)),
        budget_seconds=0,
    )
    _run(organizer, NOW)

    assert database.newsletter_preferences(scope).attempts_today == 0, "no allowance spent"
    row = database.organization_row(scope, item.id)
    assert (row["state"], row["attempts"]) == ("failed", 0), "and no inference attempt either"


def test_a_rate_limit_is_retried_when_the_provider_said_to_and_not_before(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)

    def handler(request):
        return httpx.Response(429, json={"error": "slow down"}, headers={"Retry-After": "3600"})

    _run(_organizer(world, handler), NOW)

    row = database.organization_row(scope, item.id)
    assert row["state"] == "retry"
    # An hour, as asked -- not thirty seconds of our own jitter over the top of it.
    assert row["not_before"] >= (NOW + timedelta(minutes=59)).isoformat()


def test_publication_names_notes_and_examples_are_redacted_like_the_issue(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    first = _store_issue(database, storage, scope, title="Reply to ada@example.com about it")
    _store_issue(database, storage, scope, title="Second issue")
    now = NOW.isoformat()
    database.create_and_assign_for_owner(
        scope, first.id, publication_id="p1", name="Alpha", now=now
    )
    database.edit_publication(
        scope, "p1", name="Alpha", identification_note="Write to editor@alpha.example", now=now
    )
    _enable(database, scope)
    seen = {}

    def handler(request):
        seen.update(json.loads(json.loads(request.content)["messages"][1]["content"]))
        return _reply(decision="unknown")

    _run(_organizer(world, handler), NOW)

    payload = json.dumps(seen["publications"])
    assert "ada@example.com" not in payload and "editor@alpha.example" not in payload
    assert "[address]" in payload
    assert "Alpha" in payload, "the identifying part of the context still has to survive"


def test_more_publications_than_one_request_can_carry_is_reported_not_truncated(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    now = NOW.isoformat()
    for index in range(MAX_CHOICES + 1):
        _publication(database, scope, f"p{index}", f"Publication {index:03d}", now=now)
    _enable(database, scope)

    def handler(request):
        raise AssertionError("classifying against an incomplete list invites duplicates")

    _run(_organizer(world, handler), NOW)

    row = database.organization_row(scope, item.id)
    assert (row["state"], row["error_code"]) == ("failed", "too_many_publications")


def test_production_reads_the_real_clock_rather_than_remembering_the_claim(world, monkeypatch):
    """No injected clock -- the path an actual deployment takes.

    The first attempt at this pinned the clock on every pass, so production still compared
    the lease against the moment the claim was taken and the check could never fail. A
    zero-second lease cannot catch that either: dispatch is refused before anything is
    sent, so the commit guard is never reached. The lease stays real, the module's own
    clock is advanced while the request is out, and the request must actually have gone.
    """
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)
    state = {"now": NOW}

    class Advancing(datetime):
        @classmethod
        def now(cls, tz=None):
            return state["now"]

    monkeypatch.setattr("steepd.publications.datetime", Advancing)
    sent = []

    def handler(request):
        sent.append(1)
        state["now"] = NOW + timedelta(minutes=10)
        return _reply(decision="new", publication_name="Stratechery")

    organizer = _organizer(world, handler)
    organizer.clock = None

    organizer.run_once()

    assert sent == [1], "the request went out under a live lease"
    assert database.canonical_publications(scope) == [], "and the late answer was refused"
    assert database.organization_row(scope, item.id)["publication_id"] is None


def test_a_malformed_retry_after_does_not_wedge_the_item(world):
    """"nan" parses as a float and survives every comparison, then fails inside a
    timedelta with the row left running and its attempt already spent."""
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)

    def handler(request):
        return httpx.Response(429, json={}, headers={"Retry-After": "nan"})

    _run(_organizer(world, handler), NOW)

    row = database.organization_row(scope, item.id)
    assert row["state"] == "retry", "falls back to jitter rather than raising"
    assert row["not_before"] is not None


def test_a_wait_longer_than_we_will_hold_a_claim_is_given_up_not_shortened(world):
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    item = _store_issue(database, storage, scope)
    _enable(database, scope)

    def handler(request):
        return httpx.Response(429, json={}, headers={"Retry-After": "604800"})

    _run(_organizer(world, handler), NOW)

    row = database.organization_row(scope, item.id)
    assert row["state"] == "failed", "a week is honoured by not retrying, not by retrying sooner"
    assert row["error_code"] == "rate_limited"


def test_an_issue_that_expires_during_the_request_is_not_filed(world):
    """The retention cutoff moves with the clock, or the answer lands in a publication the
    sweep is about to empty."""
    settings, database, storage = world
    tenant = database.create_tenant(email="a@example.com", inbox_local="a")
    scope = TenantScope(tenant.id)
    _store_issue(database, storage, scope)
    _enable(database, scope)
    clock = {"now": NOW}

    def handler(request):
        # Free retention is seven days; this request spans a fortnight.
        clock["now"] = NOW + timedelta(days=14)
        return _reply(decision="new", publication_name="Stratechery")

    Organizer(
        database, storage, settings,
        OpenRouterClassifier(api_key="k", model="m", transport=httpx.MockTransport(handler)),
        clock=lambda: clock["now"],
    ).run_once()

    assert database.canonical_publications(scope) == []
