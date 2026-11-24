"""Strict acceptance tests for the token exchange exercise.

The tests in this file are part of the contract and must not be modified.
"""

import pytest

from exchange.swap import (
    audience_ok,
    chain_ok,
    narrow_scopes,
    parse_token,
    subject_ok,
    swap,
    swap_batch,
    validate_policy,
)

NOW = 1_000_000


def _token(**overrides):
    token = {
        "subject": "user:alice",
        "audience": "svc:orders",
        "scopes": ["orders:read", "orders:write"],
        "chain": ["user:alice"],
        "expires_at": NOW + 500,
        "jti": "source-token",
        "single_use": False,
    }
    token.update(overrides)
    return token


def _request(**overrides):
    request = {
        "subject": "user:alice",
        "audience": "svc:orders",
        "scopes": ["orders:read"],
    }
    request.update(overrides)
    return request


def _policy(**overrides):
    policy = {
        "allow_scope_escalation": False,
        "max_chain_depth": 4,
        "max_ttl": 60,
        "require_single_use": True,
        "now": NOW,
    }
    policy.update(overrides)
    return policy


def _stable(exchanged):
    return {key: value for key, value in exchanged.items() if key not in {"jti", "issued_at"}}


def test_01_subject_prefix_lookalike_rejected():
    token = _token(subject="agent:bot", chain=["user:alice", "agent:bot"])

    assert subject_ok(token, "user:alice") is True
    assert subject_ok(token, "agent:bot") is True
    assert subject_ok(token, "user:alice-admin") is False
    assert subject_ok(token, "agent:bot.evil") is False

    with pytest.raises(ValueError):
        swap(_token(), _request(subject="user:alice-admin"), _policy())


def test_02_audience_must_match_exactly():
    token = _token(audience="api.example.com")
    assert audience_ok(token, "api.example.com") is True
    assert audience_ok(token, "evil.api.example.com") is False
    assert audience_ok(token, "api.example.com.evil") is False

    multi = _token(audience=["a.example.com", "b.example.com"])
    assert audience_ok(multi, "b.example.com") is True
    assert audience_ok(multi, "x.b.example.com") is False


def test_03_scopes_cannot_expand():
    original = ["orders:read", "orders:write"]

    assert narrow_scopes(original, ["orders:read"]) == ["orders:read"]
    assert narrow_scopes(original, ["orders:read", "orders:read"]) == ["orders:read"]
    with pytest.raises(ValueError):
        narrow_scopes(original, ["orders:read", "admin:all"])


def test_04_omitted_scopes_do_not_inherit():
    request = _request()
    request.pop("scopes")

    result = swap(_token(), request, _policy())
    assert result["scopes"] == []
    assert narrow_scopes(["orders:read", "orders:write"], []) == []


def test_05_duplicate_subjects_in_chain_rejected():
    assert chain_ok(["user:alice", "agent:bot"], 4) is True
    assert chain_ok(["user:alice", "user:alice"], 4) is False
    assert chain_ok(["user:alice", "agent:bot", "user:alice"], 4) is False

    source = _token(chain=["user:alice", "agent:bot"])
    request = _request(
        subject="agent:bot",
        chain=["user:alice", "agent:bot", "user:alice"],
    )
    with pytest.raises(ValueError):
        swap(source, request, _policy())


def test_06_chain_depth_limit_is_enforced():
    assert chain_ok(["user:alice"], 2) is True
    assert chain_ok(["user:alice", "agent:bot"], 2) is False
    assert chain_ok(["user:alice", "agent:bot", "svc:worker"], 3) is False

    source = _token(chain=["user:alice", "agent:bot"])
    request = _request(subject="agent:bot", chain=["user:alice", "agent:bot"])
    with pytest.raises(ValueError):
        swap(source, request, _policy(max_chain_depth=2))


def test_07_exchange_token_is_single_use():
    source = _token()
    result = swap(source, _request(), _policy())

    assert result["single_use"] is True
    assert result["jti"] != source["jti"]
    assert result["expires_at"] <= NOW + 60


def test_08_exchange_ttl_is_capped():
    source = _token(expires_at=NOW + 10_000)
    result = swap(source, _request(), _policy(max_ttl=60))

    assert result["expires_at"] == NOW + 60
    assert result["ttl"] == 60
    assert result["expires_at"] < source["expires_at"]


def test_09_policy_validation_rejects_unsafe_policy():
    assert validate_policy(_policy()) == []

    scope_issues = validate_policy(_policy(allow_scope_escalation=True))
    assert scope_issues
    assert any("scope" in issue.lower() or "权限" in issue for issue in scope_issues)

    no_limit = _policy()
    no_limit.pop("max_chain_depth")
    chain_issues = validate_policy(no_limit)
    assert chain_issues
    assert any("chain" in issue.lower() or "代理" in issue for issue in chain_issues)

    single_use_issues = validate_policy(_policy(require_single_use=False))
    assert single_use_issues
    assert any("single" in issue.lower() or "单次" in issue for issue in single_use_issues)

    with pytest.raises(ValueError):
        swap(_token(), _request(), _policy(allow_scope_escalation=True))


def test_10_batch_does_not_reuse_audience():
    items = [
        {
            "token": _token(audience=["svc:one", "svc:two"], jti="batch-1"),
            "request": _request(audience="svc:one"),
        },
        {
            "token": _token(audience=["svc:one", "svc:two"], jti="batch-2"),
            "request": _request(audience="svc:two"),
        },
    ]

    batch = swap_batch(items, _policy())
    assert [result["audience"] for result in batch["results"]] == [
        ["svc:one"],
        ["svc:two"],
    ]


def test_11_valid_exchange_narrows_scopes():
    source = _token(
        scopes=["orders:read", "orders:write"],
        chain=["user:alice"],
        expires_at=NOW + 10_000,
    )
    parsed = parse_token(source)
    assert parsed["subject"] == "user:alice"
    assert parsed["audience"] == ["svc:orders"]
    assert parsed["scopes"] == ["orders:read", "orders:write"]
    assert parsed["chain"] == ["user:alice"]

    result = swap(source, _request(scopes=["orders:read"]), _policy())
    assert result["subject"] == "user:alice"
    assert result["audience"] == ["svc:orders"]
    assert result["scopes"] == ["orders:read"]
    assert set(result["scopes"]) <= set(source["scopes"])
    assert result["chain"] == ["user:alice"]
    assert result["single_use"] is True
    assert result["expires_at"] <= NOW + 60
    assert result["expires_at"] <= source["expires_at"]


def test_12_audience_mismatch_is_rejected():
    with pytest.raises(ValueError):
        swap(_token(), _request(audience="evil.svc:orders"), _policy())


def test_13_scope_escalation_is_rejected():
    with pytest.raises(ValueError):
        swap(
            _token(scopes=["orders:read"]),
            _request(scopes=["orders:read", "admin:all"]),
            _policy(),
        )


def test_14_second_redemption_is_rejected():
    policy = _policy()
    issued = swap(_token(), _request(), policy)
    assert issued["single_use"] is True

    redeemed = swap(issued, _request(scopes=["orders:read"]), policy)
    assert redeemed["single_use"] is True

    with pytest.raises(ValueError):
        swap(issued, _request(scopes=["orders:read"]), policy)


def test_15_batch_matches_individual_exchange():
    items = [
        {
            "token": _token(
                scopes=["orders:read", "orders:write"],
                jti="batch-order",
            ),
            "request": _request(audience="svc:orders", scopes=["orders:read"]),
        },
        {
            "token": _token(
                audience="svc:billing",
                scopes=["billing:read", "billing:write"],
                jti="batch-billing",
            ),
            "request": _request(audience="svc:billing", scopes=["billing:read"]),
        },
    ]

    batch = swap_batch(items, _policy())
    solo_order = swap(items[0]["token"], items[0]["request"], _policy())
    solo_billing = swap(items[1]["token"], items[1]["request"], _policy())

    assert batch["results"][0]["audience"] == ["svc:orders"]
    assert batch["results"][1]["audience"] == ["svc:billing"]
    assert _stable(batch["results"][0]) == _stable(solo_order)
    assert _stable(batch["results"][1]) == _stable(solo_billing)