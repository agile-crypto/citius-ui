from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest

from citius_ui.actions.model import Availability, ResultStatus, RpcAction, RpcResult
from citius_ui.actions.registry import ActionRegistry
from citius_ui.showcases.model import Evidence, ExpectedOutcome, Runbook, RunbookStep, StepState
from citius_ui.showcases.replay import StepResult, evidence, form_values, judge, replay, run_step
from citius_ui.showcases.runbooks import (
    DEEP_DIVES,
    R3_POLICY,
    R4_AGILITY,
    R7_DUTIES,
    RUNBOOKS,
    RUNBOOKS_BY_KEY,
    SHOWCASE,
    SHOWCASE_GOVERN,
    SHOWCASE_MOVE,
    SHOWCASE_TRANSFORM,
    is_runnable,
    look_up,
    render_markdown,
)
from citius_ui.workbench.actions import registry_overview
from citius_ui.workbench.forms import FORMS_BY_METHOD, build_request


def _resolver_from_overview() -> Callable[[str, str], Availability]:
    overview = registry_overview()
    lookup = {(s, m): a for s, methods in overview.items() for m, a in methods}

    def resolve(service: str, method: str) -> Availability:
        return lookup.get((service, method), Availability.UNKNOWN)

    return resolve


def _all_steps() -> list[tuple[Runbook, int, RunbookStep]]:
    return [(rb, i, step) for rb in RUNBOOKS for i, step in enumerate(rb.steps, start=1)]


def test_the_showcase_then_the_eight_deep_dives_with_unique_keys() -> None:
    assert [rb.title for rb in SHOWCASE] == [
        "1 · Choose",
        "2 · Use",
        "3 · Govern",
        "4 · Transform",
        "5 · Move",
        "6 · Know",
    ]
    assert [rb.title.split(" ·")[0] for rb in DEEP_DIVES] == [f"R{n}" for n in range(1, 9)]
    assert RUNBOOKS == (*SHOWCASE, *DEEP_DIVES)
    assert len({rb.key for rb in RUNBOOKS}) == len(RUNBOOKS)


def test_every_runbook_is_runnable_now() -> None:
    resolve = _resolver_from_overview()
    for runbook in RUNBOOKS:
        assert is_runnable(runbook, resolve), runbook.key


@pytest.mark.parametrize(("runbook", "index", "step"), _all_steps(), ids=lambda v: getattr(v, "key", str(v)))
def test_every_step_prefills_a_valid_form_request(runbook: Runbook, index: int, step: RunbookStep) -> None:
    assert step.request is not None, f"{runbook.key} step {index} has no prefilled request"
    spec = FORMS_BY_METHOD[(step.service, step.method)]
    # The form turns the values into the request the action gets.
    build_request(spec, form_values(step))


def test_names_stay_inside_the_demo_identities_patterns() -> None:
    for runbook, index, step in _all_steps():
        request = step.request or {}
        for field in ("name", "key_name", "policy"):
            if field in request:
                assert str(request[field]).startswith("demo-"), f"{runbook.key} step {index}: {field}"


def _kept_before(runbook: Runbook) -> set[str]:
    """Bundles the runbooks this one continues from keep, directly or through theirs."""
    kept: set[str] = set()
    for key in runbook.after:
        earlier = RUNBOOKS_BY_KEY[key]
        kept |= _kept_before(earlier) | {step.bundle for step in earlier.steps if step.copy_bundle}
    return kept


def test_consumer_steps_paste_a_bundle_an_earlier_step_copies() -> None:
    for runbook in RUNBOOKS:
        copied = _kept_before(runbook)
        for index, step in enumerate(runbook.steps, start=1):
            if step.copy_bundle:
                assert step.bundle, f"{runbook.key} step {index} copies a bundle without naming it"
                copied.add(step.bundle)
            elif step.bundle:
                assert step.bundle in copied, f"{runbook.key} step {index} pastes {step.bundle} before it exists"


def test_bundle_names_are_unique_across_runbooks() -> None:
    # Bundles are shared between runbooks, so one name must not mean two things.
    owner: dict[str, str] = {}
    for runbook in RUNBOOKS:
        for step in runbook.steps:
            if step.copy_bundle:
                assert owner.setdefault(step.bundle, runbook.key) == runbook.key, step.bundle


def test_a_runbook_continues_only_from_earlier_showcase_runbooks() -> None:
    order = [rb.key for rb in RUNBOOKS]
    for runbook in RUNBOOKS:
        for key in runbook.after:
            assert order.index(key) < order.index(runbook.key), (runbook.key, key)
    assert all(not rb.after for rb in DEEP_DIVES)


def test_every_expected_refusal_says_why() -> None:
    for runbook, index, step in _all_steps():
        if step.expected is not ExpectedOutcome.SUCCESS:
            assert step.hint, f"{runbook.key} step {index} expects {step.expected.value} without a hint"


def test_every_runbook_has_a_goal_whose_proofs_name_its_steps() -> None:
    for runbook in RUNBOOKS:
        goal = runbook.goal
        assert goal is not None, runbook.key
        assert goal.claim and goal.before and goal.after, runbook.key
        # A deep dive makes two or three points; a showcase part lists every claim it proves.
        most = 6 if runbook in SHOWCASE else 3
        assert 2 <= len(goal.proofs) <= most, runbook.key
        for proof in goal.proofs:
            assert proof.steps, f"{runbook.key}: {proof.text!r} names no step"
            assert set(proof.steps) <= set(range(1, len(runbook.steps) + 1)), f"{runbook.key}: {proof.text!r}"
            # The values shown come from steps the proof names.
            assert {item.step for item in proof.shows} <= set(proof.steps), f"{runbook.key}: {proof.text!r}"


def test_every_showcase_claim_shows_the_values_that_prove_it() -> None:
    for runbook in SHOWCASE:
        assert runbook.goal is not None
        for proof in runbook.goal.proofs:
            assert proof.shows, f"{runbook.key}: {proof.text!r} shows no value"


def test_the_showcase_tells_one_keys_story() -> None:
    named = [
        (rb.key, step.method)
        for rb in SHOWCASE
        for step in rb.steps
        if "demo-signing-key" in ((step.request or {}).get("name"), (step.request or {}).get("key_name"))
    ]
    assert named[0] == ("choose", "CreateKey")
    assert {key for key, _ in named} == {"choose", "use", "transform", "move", "know"}
    assert ("transform", "TransformKey") in named and ("move", "MigrateKey") in named
    # Govern stands alone: its own policy and keys.
    assert SHOWCASE_GOVERN.after == ()
    for step in SHOWCASE_GOVERN.steps:
        request = step.request or {}
        assert "demo-signing" not in str(request.get("name", "")) + str(request.get("key_name", ""))


def test_evidence_reads_requests_responses_and_statuses() -> None:
    step = SHOWCASE_MOVE.steps[3]
    results = {
        1: StepResult(
            1,
            SHOWCASE_MOVE.steps[0],
            "OK",
            StepState.PASSED,
            request={"policy_document": json.dumps({"provider_requirements": {"fips_140_certified": True}})},
        ),
        3: StepResult(3, SHOWCASE_MOVE.steps[2], "FAILED_PRECONDITION", StepState.PASSED),
        4: StepResult(
            4,
            step,
            "OK",
            StepState.PASSED,
            request={"name": "demo-signing-key", "target_provider_id": "openssl"},
            response={"migration": {"target": {"instance_id": "openssl-fips"}}},
        ),
    }
    policy = Evidence(1, "request.policy_document.provider_requirements.fips_140_certified")
    assert evidence(policy, results) is True
    assert evidence(Evidence(3, "status"), results) == "FAILED_PRECONDITION"
    assert evidence(Evidence(4, "request"), results) == ["name", "target_provider_id"]
    assert evidence(Evidence(4, "migration.target.instance_id"), results) == "openssl-fips"
    assert evidence(Evidence(2, "status"), results) is None  # not run


def test_goal_proofs_point_at_the_steps_that_show_them() -> None:
    def step(runbook: Runbook, number: int) -> RunbookStep:
        return runbook.steps[number - 1]

    # A refusal proof names the refused step.
    for runbook in (R3_POLICY, R7_DUTIES):
        assert runbook.goal is not None
        for proof in runbook.goal.proofs:
            if "blocked" in proof.text or "cannot" in proof.text or "denied" in proof.text:
                assert any(step(runbook, n).expected is not ExpectedOutcome.SUCCESS for n in proof.steps)
    # R4's "old signature still verifies" is the sign, then the verify of that bundle.
    assert R4_AGILITY.goal is not None
    sign, verify = (step(R4_AGILITY, n) for n in R4_AGILITY.goal.proofs[1].steps)
    assert (sign.method, verify.method, verify.bundle) == ("Sign", "Verify", sign.bundle)


def test_form_values_pastes_the_named_bundle_and_rejects_unknown_fields() -> None:
    consumer = next(s for s in R4_AGILITY.steps if s.method == "Verify")
    spec = FORMS_BY_METHOD[(consumer.service, consumer.method)]
    values = dict(zip((f.key for f in spec.fields), form_values(consumer, {consumer.bundle: '{"x": 1}'}), strict=True))
    assert values["bundle"] == '{"x": 1}'
    assert values["key_name"] == consumer.request["key_name"]  # type: ignore[index]

    bad = RunbookStep("CISO", "t", "KeyManagementService", "ReadKey", ExpectedOutcome.SUCCESS, "", request={"nope": 1})
    with pytest.raises(ValueError, match="no field"):
        form_values(bad)


def test_look_up_follows_dotted_paths() -> None:
    response = {"migration": {"target": {"instance_id": "openssl"}}, "valid": False}
    assert look_up(response, "migration.target.instance_id") == "openssl"
    assert look_up(response, "valid") is False
    assert look_up(response, "migration.nope") is None


def test_look_up_reads_json_strings_and_every_item_of_a_list() -> None:
    request = {"policy_document": json.dumps({"allowed_templates": ["a", "b"]}), "note": "not json"}
    assert look_up(request, "policy_document.allowed_templates") == ["a", "b"]
    assert look_up(request, "note.x") is None
    timeline = {"timeline": [{"version": 1, "provider": "software"}, {"version": 2, "provider": "openssl-fips"}]}
    assert look_up(timeline, "timeline.*.provider") == ["software", "openssl-fips"]
    assert look_up(timeline, "timeline.0") is None


def test_render_markdown_shows_hints_bundles_and_what_to_look_for() -> None:
    resolve = _resolver_from_overview()
    text = render_markdown(R7_DUTIES, resolve)
    assert "runnable now" in text
    assert "PERMISSION_DENIED (method)" in text
    assert "PERMISSION_DENIED (resource)" in text
    assert "Copy the response bundle as **r7-sig**" in text
    assert "Paste the **r7-sig** bundle" in text
    assert "_Why:_ The producer lacks citius:crypto:verify." in text
    assert "never tokens" in text
    r3 = render_markdown(R3_POLICY, resolve)
    assert 'Look for `key_metadata.template_id` = `"ml-dsa-87"`' in r3


def test_runbook_marked_pending_when_action_unavailable() -> None:
    def resolve(service: str, method: str) -> Availability:
        return Availability.UNIMPLEMENTED

    assert not is_runnable(R3_POLICY, resolve)
    assert "pending server RPCs" in render_markdown(R3_POLICY, resolve)


class _Artifact:
    def __init__(self, bundle: dict[str, Any]) -> None:
        self._bundle = bundle

    def bundle(self) -> dict[str, Any]:
        return self._bundle


def _fake_registry(responses: dict[str, RpcResult], seen: list[tuple[str, dict[str, Any]]]) -> ActionRegistry:
    registry = ActionRegistry()
    for service, method in {(s.service, s.method) for s in R4_AGILITY.steps}:

        async def invoke(request: dict[str, Any], _method: str = method) -> RpcResult:
            seen.append((_method, request))
            return responses.get(_method, RpcResult(status=ResultStatus.OK))

        registry.register(
            RpcAction(
                service=service,
                method=method,
                permission="",
                availability=Availability.AVAILABLE,
                invoke=invoke,
                extract_artifacts=lambda request, _result: [
                    _Artifact({"key_name": request["key_name"], "signature": "c2ln"})
                ],
            )
        )
    return registry


def test_replay_passes_bundles_along_and_checks_what_to_look_for() -> None:
    seen: list[tuple[str, dict[str, Any]]] = []
    responses = {
        "CreateKey": RpcResult(
            status=ResultStatus.OK, response={"key_metadata": {"template_id": "ecdsa-p256-sha256-der"}}
        ),
        # The transform response lacks the version the step looks for.
        "TransformKey": RpcResult(status=ResultStatus.OK, response={"key_metadata": {"template_id": "ml-dsa-65"}}),
        "Verify": RpcResult(status=ResultStatus.OK, response={"valid": True}),
    }
    results = asyncio.run(replay(R4_AGILITY, _fake_registry(responses, seen)))
    verify_requests = [request for method, request in seen if method == "Verify"]
    assert json.loads(verify_requests[0]["bundle"]) == {"key_name": "demo-r4-key", "signature": "c2ln"}
    failed = [(r.index, r.detail) for r in results if not r.passed]
    assert failed[0][0] == 4 and "key_metadata.version" in failed[0][1]


def test_replay_skips_identity_denials_without_the_demo_identities() -> None:
    registry = ActionRegistry()
    for service, method in R7_DUTIES.required_actions():

        async def invoke(request: dict[str, Any]) -> RpcResult:
            return RpcResult(status=ResultStatus.OK, response={"valid": True})

        registry.register(
            RpcAction(
                service=service,
                method=method,
                permission="",
                availability=Availability.AVAILABLE,
                invoke=invoke,
                extract_artifacts=lambda request, _result: [_Artifact({"key_name": request["key_name"]})],
            )
        )
    results = asyncio.run(replay(R7_DUTIES, registry))
    skipped = {r.index for r in results if r.skipped}
    assert skipped == {
        i for i, s in enumerate(R7_DUTIES.steps, 1) if s.expected.value in ("method_denied", "resource_denied")
    }
    assert all(r.passed for r in results)


def test_replay_reports_a_step_the_forms_refuse_and_goes_on() -> None:
    import dataclasses

    timeline = next(s for s in R4_AGILITY.steps if s.method == "ReadKey")
    bad = dataclasses.replace(timeline, request={"name": "demo-r4-key", "version": "two"})
    runbook = dataclasses.replace(R4_AGILITY, steps=(bad, timeline))
    results = asyncio.run(replay(runbook, _fake_registry({}, [])))
    assert [r.passed for r in results] == [False, True]
    assert results[0].detail.startswith("form refused")


def test_replay_takes_bundles_an_earlier_runbook_kept() -> None:
    seen: list[tuple[str, dict[str, Any]]] = []
    registry = _fake_registry({"Verify": RpcResult(status=ResultStatus.OK, response={"valid": True})}, seen)
    # Transform verifies Use's invoice-v1: alone it has no such bundle.
    alone = asyncio.run(replay(SHOWCASE_TRANSFORM, registry))
    assert "no invoice-v1 bundle yet" in alone[2].detail
    bundles = {"invoice-v1": json.dumps({"key_name": "demo-signing-key", "signature": "djE="})}
    after_use = asyncio.run(replay(SHOWCASE_TRANSFORM, registry, bundles=bundles))
    assert after_use[2].state is StepState.PASSED
    assert json.loads(after_use[2].request["bundle"])["signature"] == "djE="
    assert "invoice-v2" in bundles  # kept for Move


def test_judge_tells_a_wrong_status_from_a_different_value() -> None:
    create = R4_AGILITY.steps[1]
    assert create.look_for == {"key_metadata.template_id": "ecdsa-p256-sha256-der"}
    ok = {"key_metadata": {"template_id": "ecdsa-p256-sha256-der"}}
    assert judge(create, "OK", ok) == (StepState.PASSED, "")
    state, detail = judge(create, "OK", {"key_metadata": {"template_id": "ml-dsa-44"}})
    assert state is StepState.DIFFERS and "ml-dsa-44" in detail
    assert judge(create, "NOT_FOUND", {})[0] is StepState.FAILED
    # An expected refusal passes on its code alone.
    refused = R3_POLICY.steps[4]
    assert refused.expected is ExpectedOutcome.POLICY_REJECTED
    assert judge(refused, "PERMISSION_DENIED", {})[0] is StepState.PASSED


def test_run_step_goes_through_the_given_invoke_and_keeps_the_bundle() -> None:
    seen: list[str] = []
    registry = _fake_registry({}, [])

    async def invoke(action: RpcAction, payload: dict[str, Any]) -> RpcResult:
        seen.append(action.method)
        return RpcResult(status=ResultStatus.OK, response={"valid": True})

    bundles: dict[str, str] = {}
    sign, verify = R4_AGILITY.steps[2], R4_AGILITY.steps[4]
    first = asyncio.run(run_step(3, sign, registry, bundles, invoke=invoke))
    assert first.state is StepState.PASSED and set(bundles) == {"r4-ecdsa"}
    second = asyncio.run(run_step(5, verify, registry, bundles, invoke=invoke))
    assert (second.index, second.state) == (5, StepState.PASSED)
    assert seen == ["Sign", "Verify"]


def test_run_step_refuses_a_consumer_step_before_its_bundle_exists() -> None:
    async def invoke(action: RpcAction, payload: dict[str, Any]) -> RpcResult:
        raise AssertionError("no call without the bundle")

    verify = R4_AGILITY.steps[4]
    result = asyncio.run(run_step(5, verify, _fake_registry({}, []), {}, invoke=invoke))
    assert (result.status, result.state) == ("", StepState.FAILED)
    assert "no r4-ecdsa bundle yet" in result.detail
