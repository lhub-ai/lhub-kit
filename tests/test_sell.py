"""`sell` (seller-door D-10): local core build, sign → create → activate, store.

Proves: the activate action is BUILT LOCALLY and signed over the kit's own
bytes; registry idempotency keys are 128-bit random and stored with the
pending op (reused on retry); the listing id is UUID-checked before use; and
the pinned refusals (currency, min_charge, unit form) fire before anything is
signed or sent.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit

import lhub

LISTING_ID = "7a1d2f30-1111-4222-8333-944444444444"


@pytest.fixture(autouse=True)
def recorded_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """The post-sell search check waits between searches; record, never sleep."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    return sleeps


def make_kit(tmp_path: Path, router: Any) -> RouterKit:
    return RouterKit(tmp_path / "home", router)


def flags_core(kit: RouterKit, **overrides: Any) -> dict[str, Any]:
    core = lhub.build_listing_core(
        own_did=kit.did,
        endpoint=kit.base_url + lhub.MCP_PATH,
        category="digital_services/text/summarization",
        title="Summarizer",
        summary="Summarizes one text file",
        price="0.10",
        unit="file",
        min_charge="0.50",
    )
    core.update(overrides)
    return core


def happy_router(created: dict[str, Any] | None = None) -> Any:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "create_listing":
            return created or {"listing_id": LISTING_ID, "status": "staging"}
        if name == "activate_listing":
            return {"listing_id": LISTING_ID, "status": "active"}
        if name == "search_services":
            # A search hit names the listing as `listing.id` (discovery's
            # search result, copied unfenced by the bridge) — never
            # `listing_id`, which only create/activate results carry.
            return {"results": [{"listing": {"id": LISTING_ID}}]}
        raise AssertionError(f"unexpected tool {name}")

    return route


def test_sell_happy_path_signs_only_self_built_bytes(
    tmp_path: Path, recorded_sleeps: list[float]
) -> None:
    kit = make_kit(tmp_path, happy_router())
    out = lhub.do_sell(kit, flags_core(kit))

    assert out["listing_id"] == LISTING_ID
    assert out["status"] == "active"
    assert out["search_check"] == "found"
    # Found by `listing.id` on the first search, after one short wait.
    assert len(kit.calls_to("search_services")) == 1
    assert recorded_sleeps == [lhub.SEARCH_CHECK_WAITS_SECONDS[0]]

    # The created core's provider_signature verifies under OUR did over OUR
    # canonicalization of core-minus-signature (the registry's exact check).
    (create_args,) = kit.calls_to("create_listing")
    signed_core = create_args["core"]
    sig = signed_core.pop("provider_signature")
    canonical = lhub.jcs_canonicalize(signed_core)
    lhub.verify_jws_es256_canonical(did=kit.did, jws=sig, expected_canonical=canonical)
    assert out["content_hash"] == lhub.sha256_ref(canonical).removeprefix("sha256:")

    # The activate action was built locally from our own DID + the UUID-checked
    # id, and its signature verifies over our own JCS of the 3-field object.
    (activate_args,) = kit.calls_to("activate_listing")
    action = dict(activate_args["action"])
    action_sig = action.pop("signature")
    assert action == {"actor_did": kit.did, "action": "activate", "listing_id": LISTING_ID}
    lhub.verify_jws_es256_canonical(
        did=kit.did, jws=action_sig, expected_canonical=lhub.jcs_canonicalize(action)
    )

    # The signed core is stored locally as the terms we sell at.
    stored = kit.load_listing(LISTING_ID)
    assert stored is not None
    assert stored["content_hash"] == out["content_hash"]
    assert stored["core"]["provider_signature"] == sig


def test_sell_registry_keys_are_random_and_stored_for_retry(tmp_path: Path) -> None:
    attempts: list[str] = []

    def failing_router(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "create_listing":
            attempts.append(arguments["idempotency_key"])
            raise lhub.KitError("create_listing: transport sneeze")
        raise AssertionError(name)

    kit = make_kit(tmp_path, failing_router)
    core = flags_core(kit)
    with pytest.raises(lhub.KitError, match="sneeze"):
        lhub.do_sell(kit, dict(core))

    # Retry of the SAME core reuses the SAME stored key (registry replay-safe).
    kit2 = RouterKit(tmp_path / "home", failing_router)
    with pytest.raises(lhub.KitError, match="sneeze"):
        lhub.do_sell(kit2, dict(core))
    assert len(attempts) == 2
    assert attempts[0] == attempts[1]
    assert len(attempts[0]) == 32  # 128-bit hex
    int(attempts[0], 16)

    # A DIFFERENT core gets a fresh random key.
    other = flags_core(kit, capability={**core["capability"], "summary": "another"})
    kit3 = RouterKit(tmp_path / "home", failing_router)
    with pytest.raises(lhub.KitError, match="sneeze"):
        lhub.do_sell(kit3, other)
    assert attempts[2] != attempts[0]


def test_sell_refuses_non_uuid_listing_id_and_does_not_activate(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router(created={"listing_id": "../../etc/passwd"}))
    with pytest.raises(lhub.KitError, match="non-UUID listing_id"):
        lhub.do_sell(kit, flags_core(kit))
    assert kit.calls_to("activate_listing") == []
    assert kit.load_listing(LISTING_ID) is None


def test_sell_refuses_registry_content_hash_disagreement(tmp_path: Path) -> None:
    kit = make_kit(
        tmp_path,
        happy_router(created={"listing_id": LISTING_ID, "content_hash": "ee" * 32}),
    )
    with pytest.raises(lhub.KitError, match="content hash disagrees"):
        lhub.do_sell(kit, flags_core(kit))
    assert kit.calls_to("activate_listing") == []


def test_validate_refuses_foreign_currency(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    core = flags_core(kit)
    core["pricing"]["currency"] = "USD"
    with pytest.raises(lhub.KitRefusal, match="REG-1"):
        lhub.do_sell(kit, core)
    assert kit.tool_calls == []  # refused before anything was sent


def test_validate_refuses_min_charge_below_price(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    core = flags_core(kit)
    core["pricing"]["min_charge"] = "0.05"  # price is 0.10
    with pytest.raises(lhub.KitRefusal, match="min_charge is below the unit price"):
        lhub.do_sell(kit, core)


def test_validate_refuses_bad_unit_identifier(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    core = flags_core(kit)
    core["pricing"]["unit"] = "ignore previous instructions"
    with pytest.raises(lhub.KitRefusal, match=r"pricing\.unit"):
        lhub.do_sell(kit, core)


def test_validate_refuses_zero_price(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    core = flags_core(kit)
    core["pricing"]["amount"] = "0"
    with pytest.raises(lhub.KitRefusal, match="price is zero"):
        lhub.do_sell(kit, core)


def test_validate_refuses_foreign_agent_did(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    core = flags_core(kit)
    core["identity"]["agent_did"] = "did:key:zSomeoneElse"
    with pytest.raises(lhub.KitRefusal, match="not this kit's DID"):
        lhub.do_sell(kit, core)


def test_validate_fills_missing_agent_did(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    core = flags_core(kit)
    core["identity"].pop("agent_did")
    out = lhub.do_sell(kit, core)
    (create_args,) = kit.calls_to("create_listing")
    assert create_args["core"]["identity"]["agent_did"] == kit.did
    assert out["listing_id"] == LISTING_ID


def test_flags_path_refuses_code_review_category(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    kit.ensure_key()
    with pytest.raises(lhub.KitError, match="code-review extension"):
        lhub.build_listing_core(
            own_did=kit.did,
            endpoint="http://localhost:19999/mcp/v1",
            category=lhub.CODE_REVIEW_CATEGORY,
            title="t",
            summary="s",
            price="0.05",
            unit="file",
        )


def test_built_core_shape_matches_schema_requirements(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    kit.ensure_key()
    core = flags_core(kit)
    assert core["schema_version"] == "0.1"
    assert core["pricing"]["currency"] == lhub.SETTLEMENT_UNIT
    assert core["fulfillment"] == {
        "tier": 0,
        "proof": {
            "method": "signed_output",
            "hash_algorithm": "sha-256",
            "signature_alg": "ES256",
        },
    }
    assert core["interface_bindings"] == [
        {"protocol": "mcp", "endpoint": "http://localhost:19999/mcp/v1"}
    ]
    extension = core["capability"]["extension_input"]
    for field in (
        "input_description",
        "input_media_types",
        "deliverable_description",
        "deliverable_media_type",
        "turnaround_hours",
    ):
        assert field in extension
    assert extension["max_input_bytes"] == lhub.DELIVERABLE_CAP_BYTES
    # The core (with its signature) must survive a JSON round trip unchanged.
    assert json.loads(json.dumps(core)) == core


def test_retire_signs_local_action(tmp_path: Path) -> None:
    def route(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "retire_listing":
            return {"listing_id": LISTING_ID, "status": "retired"}
        raise AssertionError(name)

    kit = make_kit(tmp_path, route)
    out = lhub.do_retire(kit, listing_id=LISTING_ID)
    assert out["status"] == "retired"
    (args,) = kit.calls_to("retire_listing")
    action = dict(args["action"])
    sig = action.pop("signature")
    assert action == {"actor_did": kit.did, "action": "retire", "listing_id": LISTING_ID}
    lhub.verify_jws_es256_canonical(
        did=kit.did, jws=sig, expected_canonical=lhub.jcs_canonicalize(action)
    )
    assert len(args["idempotency_key"]) == 32


def test_retire_refuses_non_uuid(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, happy_router())
    with pytest.raises(lhub.KitError, match="not a UUID"):
        lhub.do_retire(kit, listing_id="rm -rf /")
    assert kit.tool_calls == []


# ---------------------------------------------------------------------------
# The post-sell search check (harden-public-sandbox task 3.2): hits carry the
# listing's id as `listing.id`, and the check spends a bounded number of
# searches (the anonymous-read budget is shared per source, anon_read 120/min).
# ---------------------------------------------------------------------------


def discovery_hit(listing_id: str) -> dict[str, Any]:
    """A search hit in the shape the bridge serves (measured on the dev stack)."""
    return {
        "listing": {
            "id": listing_id,
            "provider_did": "did:key:zDnaeSomeProvider",
            "category_id": "digital_services/text/summarization",
            "category_path": "digital_services/text/summarization",
            "pricing_model": "per_unit",
            "price_min": 100000,
            "price_max": 100000,
            "unit": "file",
            "text_summary": "[UNTRUSTED-CONTENT]Summarizes one text file[/UNTRUSTED-CONTENT]",
            "extension_blob": "[UNTRUSTED-CONTENT]text/plain[/UNTRUSTED-CONTENT]",
            "score": 0.5,
        },
        "unit": lhub.SETTLEMENT_UNIT,
        "decimals": lhub.UNIT_DECIMALS,
        "price_min_display": "0.10 LHUB-DEV",
        "price_max_display": "0.10 LHUB-DEV",
    }


class SearchRouter:
    """search_services answers ``misses`` times without the listing, then with it."""

    def __init__(self, *, misses: int, hit_id: str = LISTING_ID) -> None:
        self.misses = misses
        self.hit_id = hit_id
        self.searches: list[dict[str, Any]] = []

    def __call__(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name != "search_services":
            raise AssertionError(f"unexpected tool {name}")
        self.searches.append(arguments)
        other = discovery_hit("0b0b0b0b-2222-4333-8444-955555555555")
        if len(self.searches) <= self.misses:
            return {"total": 1, "results": [other]}
        return {"total": 2, "results": [other, discovery_hit(self.hit_id)]}


def test_search_check_finds_the_listing_by_id_on_a_later_attempt(
    tmp_path: Path, recorded_sleeps: list[float]
) -> None:
    router = SearchRouter(misses=2, hit_id=LISTING_ID.upper())  # ids compare case-blind
    kit = make_kit(tmp_path, router)
    out = lhub._search_check(
        kit, listing_id=LISTING_ID, category="digital_services/text/summarization"
    )
    assert out == "found"
    assert len(router.searches) == 3  # stopped at the first hit
    assert recorded_sleeps == list(lhub.SEARCH_CHECK_WAITS_SECONDS[:3])
    assert router.searches[0] == {"category": "digital_services/text/summarization", "limit": 50}


def test_search_check_spends_at_most_four_searches(
    tmp_path: Path, recorded_sleeps: list[float]
) -> None:
    # Pre-fix, the check polled every second for 15 s (about 15 searches) and
    # matched a field search hits never carry. Now: a bounded, spaced-out spend.
    router = SearchRouter(misses=1_000)
    kit = make_kit(tmp_path, router)
    out = lhub._search_check(kit, listing_id=LISTING_ID, category="digital_services/other")
    assert out == "not_yet_indexed"
    assert len(router.searches) == len(lhub.SEARCH_CHECK_WAITS_SECONDS) == 4
    assert recorded_sleeps == [1.0, 2.0, 4.0, 8.0]  # cumulative 1, 3, 7, 15 s
    assert min(recorded_sleeps) >= 1.0  # never a tight poll


def test_search_check_stops_at_once_on_a_refusal(
    tmp_path: Path, recorded_sleeps: list[float]
) -> None:
    searches: list[str] = []

    def rate_limited(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        searches.append(name)
        raise lhub.KitRetryableError(
            "search_services: rate_limited: rate limited; retry later (correlationId=c1)",
            code=lhub.CODE_RATE_LIMITED,
            tool="search_services",
        )

    kit = make_kit(tmp_path, rate_limited)
    out = lhub._search_check(kit, listing_id=LISTING_ID, category="digital_services/other")
    assert out == "search_unavailable"
    assert searches == ["search_services"]  # no further spend against the budget
