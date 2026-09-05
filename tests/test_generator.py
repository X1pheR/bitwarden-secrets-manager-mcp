from __future__ import annotations

import pytest

from bitwarden_secrets_manager_mcp.generator import AMBIGUOUS, LOWERCASE, PasswordGenerationError, _filtered, generate_password


def generate(**overrides):
    policy = {
        "length": 32,
        "uppercase": True,
        "lowercase": True,
        "digits": True,
        "special": True,
        "min_digits": 2,
        "min_special": 3,
        "avoid_ambiguous": True,
    }
    policy.update(overrides)
    return generate_password(**policy)


def test_generated_password_honors_length_minimums_and_ambiguous_filter() -> None:
    for _ in range(100):
        value = generate()
        assert len(value) == 32
        assert sum(character.isdigit() for character in value) >= 2
        assert sum(character in "!@#$%^&*" for character in value) >= 3
        assert not (set(value) & AMBIGUOUS)


def test_generation_can_use_each_character_class_independently() -> None:
    assert generate(uppercase=True, lowercase=False, digits=False, special=False, min_digits=0, min_special=0).isupper()
    assert generate(uppercase=False, lowercase=True, digits=False, special=False, min_digits=0, min_special=0).islower()
    assert generate(uppercase=False, lowercase=False, digits=True, special=False, min_digits=1, min_special=0).isdigit()
    assert set(generate(uppercase=False, lowercase=False, digits=False, special=True, min_digits=0, min_special=1)) <= set("!@#$%^&*")


def test_ambiguous_characters_can_be_allowed() -> None:
    value = generate(uppercase=False, lowercase=False, digits=True, special=False, min_digits=32, min_special=0, avoid_ambiguous=False)
    assert len(value) == 32
    assert value.isdigit()


def test_impossible_generation_policies_fail_closed() -> None:
    with pytest.raises(PasswordGenerationError, match="At least one"):
        generate(uppercase=False, lowercase=False, digits=False, special=False, min_digits=0, min_special=0)
    with pytest.raises(PasswordGenerationError, match="min_digits"):
        generate(digits=False, min_digits=1)
    with pytest.raises(PasswordGenerationError, match="min_special"):
        generate(special=False, min_special=1)
    with pytest.raises(PasswordGenerationError, match="exceed"):
        generate(length=5, min_digits=3, min_special=3)


def test_ambiguous_character_set_matches_bitwarden() -> None:
    assert AMBIGUOUS == frozenset("IOl01")
    assert "o" in _filtered(LOWERCASE, avoid_ambiguous=True)
