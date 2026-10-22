from toolgate.toolgate import (
    FieldSpec,
    Policy,
    ToolSpec,
    check_schema,
    gate,
    redact,
    render_verdict,
)


def _email_tool():
    return ToolSpec(
        name="send_email",
        schema={
            "to": FieldSpec(type="string", required=True, pattern=r"^[^@]+@[^@]+$"),
            "subject": FieldSpec(type="string", required=True, max_length=200),
            "priority": FieldSpec(type="string", allowed=["low", "normal", "high"]),
        },
        policy=Policy(
            deny=[{"key": "to", "pattern": r"(?i)bcc\s*:", "reason": "hidden recipient"}],
            require=["subject"],
        ),
    )


def test_valid_call_allowed():
    v = gate(_email_tool(), {"to": "a@b.com", "subject": "hi", "priority": "high"})
    assert v.allowed and v.reasons == []


def test_missing_required_key():
    v = gate(_email_tool(), {"to": "a@b.com"})
    assert not v.allowed
    assert any("subject" in r for r in v.reasons)


def test_type_mismatch():
    v = gate(_email_tool(), {"to": "a@b.com", "subject": 123})
    assert not v.allowed
    assert any("expected string" in r for r in v.reasons)


def test_allowed_values_enforced():
    v = gate(_email_tool(), {"to": "a@b.com", "subject": "x", "priority": "urgent"})
    assert not v.allowed
    assert any("allowed set" in r for r in v.reasons)


def test_pattern_enforced():
    v = gate(_email_tool(), {"to": "not-an-email", "subject": "x"})
    assert not v.allowed
    assert any("pattern" in r for r in v.reasons)


def test_max_length_enforced():
    v = gate(_email_tool(), {"to": "a@b.com", "subject": "x" * 201})
    assert not v.allowed
    assert any("longer" in r for r in v.reasons)


def test_policy_deny():
    v = gate(_email_tool(), {"to": "a@b.com bcc: evil@x.com", "subject": "x"})
    assert not v.allowed
    assert any("hidden recipient" in r for r in v.reasons)


def test_min_max_numeric():
    tool = ToolSpec(name="t", schema={"n": FieldSpec(type="integer", min=0, max=10)})
    assert gate(tool, {"n": 5}).allowed
    assert not gate(tool, {"n": -1}).allowed
    assert not gate(tool, {"n": 11}).allowed


def test_boolean_and_list_types():
    tool = ToolSpec(name="t", schema={
        "flag": FieldSpec(type="boolean"),
        "items": FieldSpec(type="list"),
    })
    assert gate(tool, {"flag": True, "items": [1]}).allowed
    assert not gate(tool, {"flag": "yes"}).allowed


def test_bool_is_not_number():
    # Python bools are ints; ensure 'number' does not accept a bool.
    tool = ToolSpec(name="t", schema={"n": FieldSpec(type="number")})
    assert not gate(tool, {"n": True}).allowed


def test_redaction_masks_sensitive_keys():
    out = redact({"to": "a@b.com", "api_key": "sk-123", "password": "hunter2"})
    assert out["api_key"] == "***REDACTED***"
    assert out["password"] == "***REDACTED***"
    assert out["to"] == "a@b.com"


def test_preview_is_redacted_but_verdict_still_uses_real_args():
    tool = ToolSpec(
        name="login",
        schema={"username": FieldSpec(type="string", required=True),
                "password": FieldSpec(type="string", required=True)},
    )
    v = gate(tool, {"username": "bob", "password": "hunter2"})
    assert v.allowed
    assert v.preview["password"] == "***REDACTED***"
    assert v.preview["username"] == "bob"


def test_render_verdict_contains_status_and_reasons():
    v = gate(_email_tool(), {"subject": "x"})
    text = render_verdict(v)
    assert text.startswith("DENY")
    assert "send_email" in text
    assert "REDACTED" in text or "preview" in text


def test_check_schema_empty_args_ok_when_nothing_required():
    assert check_schema({}, {}) == []
