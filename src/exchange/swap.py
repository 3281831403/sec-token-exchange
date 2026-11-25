"""Token exchange contract.

The module deliberately contains only the eight public functions that make up
the exercise.  Every function is a failing stub; the task is to implement the
security semantics described in README.md without editing the tests.
"""

import time
import uuid


# ---------------------------------------------------------------------------
# Parsing / normalisation
# ---------------------------------------------------------------------------

_REQUIRED_TOKEN_FIELDS = (
    "subject",
    "audience",
    "scopes",
    "chain",
    "expires_at",
    "jti",
)


def _is_plain_int(value) -> bool:
    """``bool`` is an ``int`` subclass but is not a valid timestamp/depth."""

    return isinstance(value, int) and not isinstance(value, bool)


def _dedupe_strings(values, field: str) -> list:
    """Validate a list of strings and de-duplicate preserving first order."""

    if not isinstance(values, list):
        raise ValueError(f"{field} must be a list of strings")
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"{field} entries must be strings")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _normalize_audience(audience) -> list:
    if isinstance(audience, str):
        values = [audience]
    elif isinstance(audience, list):
        values = audience
    else:
        raise ValueError("audience must be a string or a list of strings")

    result = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value:
            raise ValueError("audience entries must be non-empty strings")
        if value not in seen:
            seen.add(value)
            result.append(value)

    # An audience-less token must never be accepted.
    if not result:
        raise ValueError("audience must not be empty")
    return result


def parse_token(token) -> dict:
    """Parse a token mapping into the canonical exchange representation.

    The canonical result is::

        {
            "subject": str,
            "audience": list[str],
            "scopes": list[str],
            "chain": list[str],
            "expires_at": int,
            "jti": str,
            "single_use": bool,
        }

    A string audience is normalised to a one-element list.  Audience and scope
    lists are de-duplicated while preserving first-seen order.  Invalid or
    missing required fields raise ValueError.  The caller's mapping must not be
    mutated.
    """

    if not isinstance(token, dict):
        raise ValueError("token must be a mapping")

    for field in _REQUIRED_TOKEN_FIELDS:
        if field not in token:
            raise ValueError(f"missing required token field: {field}")

    subject = token["subject"]
    if not isinstance(subject, str) or not subject:
        raise ValueError("subject must be a non-empty string")

    jti = token["jti"]
    if not isinstance(jti, str) or not jti:
        raise ValueError("jti must be a non-empty string")

    expires_at = token["expires_at"]
    if not _is_plain_int(expires_at):
        raise ValueError("expires_at must be an integer Unix timestamp")

    # Audience/scopes are de-duplicated; the chain is only type-checked and
    # copied because duplicate chain entries have to survive for chain_ok().
    audience = _normalize_audience(token["audience"])
    scopes = _dedupe_strings(token["scopes"], "scopes")

    raw_chain = token["chain"]
    if not isinstance(raw_chain, list):
        raise ValueError("chain must be a list of strings")
    chain = []
    for entry in raw_chain:
        if not isinstance(entry, str):
            raise ValueError("chain entries must be strings")
        chain.append(entry)

    single_use = token.get("single_use", False)
    if not isinstance(single_use, bool):
        raise ValueError("single_use must be a boolean")

    # Brand-new containers: the caller's mapping is never mutated.
    return {
        "subject": subject,
        "audience": audience,
        "scopes": scopes,
        "chain": chain,
        "expires_at": expires_at,
        "jti": jti,
        "single_use": single_use,
    }


# ---------------------------------------------------------------------------
# Defect 1: subject comparison must be exact, never prefix-based.
# ---------------------------------------------------------------------------

def subject_ok(token, subject) -> bool:
    """Return True only for an exact subject or exact delegated-party match.

    The candidate is valid when it exactly equals the token subject or exactly
    equals one entry in the token chain.  Prefix matches never count.  Invalid
    tokens or subjects return False rather than raising.
    """

    if not isinstance(subject, str) or not subject:
        return False
    try:
        parsed = parse_token(token)
    except (ValueError, TypeError):
        return False

    # Exact equality on both sides -- no startswith() / prefix matching.
    if subject == parsed["subject"]:
        return True
    return any(subject == entry for entry in parsed["chain"])


# ---------------------------------------------------------------------------
# Defect 2: audience comparison must be exact, never suffix/subdomain-based.
# ---------------------------------------------------------------------------

def audience_ok(token, audience) -> bool:
    """Return True only when audience exactly matches a token audience.

    Token audiences are exact strings, normalised by parse_token to a list.  A
    requested audience must equal one entry; suffix and subdomain matches are
    not acceptable.  Invalid tokens or audiences return False.
    """

    if not isinstance(audience, str) or not audience:
        return False
    try:
        parsed = parse_token(token)
    except (ValueError, TypeError):
        return False

    # Exact list membership -- no endswith() / suffix / subdomain logic.
    return audience in parsed["audience"]


# ---------------------------------------------------------------------------
# Defects 3 & 4: scopes may only narrow; omitted scopes mean zero privileges.
# ---------------------------------------------------------------------------

def narrow_scopes(original, requested) -> list:
    """Return the requested scopes after enforcing least privilege.

    ``requested`` must be a subset of ``original``.  The result preserves the
    requested order and removes duplicates.  An omitted, None, or empty request
    narrows to an empty list; it never inherits the original scopes.  Any scope
    outside ``original`` raises ValueError.  This function never returns a
    union or silently drops an unauthorised scope.
    """

    # Defect 4: omitted / None request narrows to [] -- never inherits all.
    if requested is None:
        return []

    if isinstance(requested, str) or not isinstance(requested, list):
        raise ValueError("requested scopes must be a list of strings or None")

    if not isinstance(original, list):
        raise ValueError("original scopes must be a list of strings")

    allowed = set()
    for scope in original:
        if not isinstance(scope, str):
            raise ValueError("original scopes must be strings")
        allowed.add(scope)

    result = []
    seen = set()
    for scope in requested:
        if not isinstance(scope, str):
            raise ValueError("requested scopes must be strings")

        # Defect 3: anything outside the original set is an escalation and is
        # rejected loudly -- no union, no silent intersection/drop.
        if scope not in allowed:
            raise ValueError(f"requested scope is not held by source token: {scope!r}")

        if scope not in seen:
            seen.add(scope)
            result.append(scope)

    return result


# ---------------------------------------------------------------------------
# Defects 5 & 6: chain subjects must be unique and length is strictly bounded.
# ---------------------------------------------------------------------------

def chain_ok(chain, max_depth) -> bool:
    """Validate delegation-chain depth and uniqueness.

    ``chain`` must be a non-empty list of non-empty strings with no repeated
    subject.  ``max_depth`` is an exclusive bound: the chain is valid only when
    len(chain) < max_depth.  Thus max_depth=2 permits one chain entry and
    rejects a two-entry chain.  Invalid arguments return False.
    """

    if not _is_plain_int(max_depth) or max_depth <= 0:
        return False
    if not isinstance(chain, list) or not chain:
        return False

    seen = set()
    for subject in chain:
        if not isinstance(subject, str) or not subject:
            return False
        # Defect 5: the same subject may not appear twice in the chain.
        if subject in seen:
            return False
        seen.add(subject)

    # Defect 6: exclusive upper bound -- len == max_depth is already too long.
    return len(chain) < max_depth


# ---------------------------------------------------------------------------
# Defect 9 (policy side): unsafe policies must be reported and rejected.
# ---------------------------------------------------------------------------

def validate_policy(policy) -> list:
    """Return a list of policy problems, empty only for a safe policy.

    At minimum this detects: scope escalation being allowed, a missing or
    non-positive delegation-chain limit, and single use not being required.
    Each problem is a human-readable string.  A valid policy returns [].
    """

    if not isinstance(policy, dict):
        return ["policy must be a mapping"]

    issues = []

    # Defect 9: a policy that permits scope escalation is unsafe.
    if policy.get("allow_scope_escalation") is not False:
        issues.append(
            "policy must not allow scope escalation: "
            "allow_scope_escalation must be False (禁止权限扩大)"
        )

    max_chain_depth = policy.get("max_chain_depth")
    if not _is_plain_int(max_chain_depth) or max_chain_depth <= 0:
        issues.append(
            "policy must define a positive max_chain_depth "
            "(缺少或存在非正数的代理链上限 chain limit)"
        )

    if policy.get("require_single_use") is not True:
        issues.append(
            "policy must require single-use exchange tokens: "
            "require_single_use must be True (必须要求单次使用 single use)"
        )

    max_ttl = policy.get("max_ttl")
    if not _is_plain_int(max_ttl) or max_ttl <= 0:
        issues.append("policy must define a positive max_ttl")

    return issues


def _already_consumed(policy, jti) -> bool:
    consumed = policy.get("consumed_jti")
    if consumed is None:
        return False
    try:
        return jti in consumed
    except TypeError:
        return False


def _record_consumed(policy, jti) -> None:
    """Record a redeemed single-use jti in the policy-maintained collection."""

    consumed = policy.get("consumed_jti")
    if consumed is None:
        policy["consumed_jti"] = {jti}
    elif isinstance(consumed, set):
        consumed.add(jti)
    elif isinstance(consumed, list):
        consumed.append(jti)
    # Any other container type is not part of the documented contract.


# ---------------------------------------------------------------------------
# swap: defects 7 & 8 (single use + TTL cap) are enforced here as well.
# ---------------------------------------------------------------------------

def swap(token, request, policy) -> dict:
    """Issue a narrowed, audience-bound, single-use exchange token.

    The request supplies subject, audience, optional scopes (default empty),
    and optional chain (default: the source token chain).  The source token
    must be unexpired and the policy must contain no issues.  Subject,
    audience, scopes, and chain are validated before issuance.

    The returned mapping contains subject, audience (one-element list), scopes,
    chain, expires_at, ttl, issued_at, single_use=True, and a fresh jti.
    expires_at is min(source expiry, now + policy max_ttl), so a long-lived
    source token can never produce a long-lived exchange token.

    A source token marked single_use may be redeemed once.  After a successful
    issuance its jti is recorded in policy["consumed_jti"]; a later attempt
    with the same jti raises ValueError.  Failed attempts do not consume it.
    All rejections raise ValueError.
    """

    # 1) Policy gate first: an unsafe policy can never issue a token.
    issues = validate_policy(policy)
    if issues:
        raise ValueError("unsafe policy: " + "; ".join(issues))

    if not isinstance(request, dict):
        raise ValueError("request must be a mapping")

    # 2) Parse the source token (ValueError propagates for invalid tokens).
    source = parse_token(token)

    # Defect 7 (redemption side): a single-use jti can only be redeemed once.
    if source["single_use"] and _already_consumed(policy, source["jti"]):
        raise ValueError(f"token {source['jti']!r} has already been redeemed")

    now = policy.get("now")
    if now is None:
        now = int(time.time())

    # 3) Source must still be valid at the policy/current time.
    if source["expires_at"] <= now:
        raise ValueError("source token has expired")

    # 4) Exact subject / delegated-party match.
    request_subject = request.get("subject")
    if not subject_ok(source, request_subject):
        raise ValueError("request subject does not exactly match token subject or chain")

    # 5) Exact audience match -- no suffix/subdomain shortcut.
    request_audience = request.get("audience")
    if not audience_ok(source, request_audience):
        raise ValueError("request audience does not exactly match a token audience")

    # 6) Scopes can only narrow; omitted scopes become [] and escalation raises.
    scopes = narrow_scopes(source["scopes"], request.get("scopes"))

    # 7) Delegation chain: request override or the source chain, then enforce
    #    uniqueness and the exclusive depth bound.
    request_chain = request.get("chain")
    if request_chain is None:
        chain = list(source["chain"])
    elif isinstance(request_chain, list):
        chain = list(request_chain)
    else:
        raise ValueError("request chain must be a list of strings")

    if not chain_ok(chain, policy["max_chain_depth"]):
        raise ValueError("delegation chain has duplicates or exceeds max_chain_depth")

    # 8) TTL cap: never outlive either the source token or the policy maximum.
    issued_at = now
    expires_at = min(source["expires_at"], issued_at + policy["max_ttl"])
    ttl = expires_at - issued_at

    exchanged = {
        "subject": request_subject,
        "audience": [request_audience],
        "scopes": scopes,
        "chain": chain,
        "expires_at": expires_at,
        "ttl": ttl,
        "issued_at": issued_at,
        # Defect 7 (issuance side): every exchanged token is single-use.
        "single_use": True,
        "jti": uuid.uuid4().hex,
    }

    # Consumption is recorded only after every check has passed, so failed
    # attempts never consume the source token.
    if source["single_use"]:
        _record_consumed(policy, source["jti"])

    return exchanged


# ---------------------------------------------------------------------------
# Defect 10: batch items are fully independent -- no audience/field carry-over.
# ---------------------------------------------------------------------------

def swap_batch(requests, policy) -> dict:
    """Exchange several source tokens independently.

    ``requests`` is a list of mappings, each shaped as
    {"token": token, "request": request}.  The result is {"results": [...]},
    preserving input order.  Every item is validated with its own audience,
    subject, scopes, and chain; no field is carried over from a previous item.
    Invalid input raises ValueError.
    """

    if not isinstance(requests, list):
        raise ValueError("swap_batch expects a list of {token, request} mappings")

    results = []
    for index, item in enumerate(requests):
        if not isinstance(item, dict) or "token" not in item or "request" not in item:
            raise ValueError(
                f"batch item {index} must be a mapping with 'token' and 'request'"
            )
        # Each call reads only its own item's audience/subject/scopes/chain.
        results.append(swap(item["token"], item["request"], policy))

    return {"results": results}
