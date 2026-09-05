from __future__ import annotations

import secrets
import string


UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*"
AMBIGUOUS = frozenset("IOl01")


class PasswordGenerationError(ValueError):
    """Raised when a requested password policy cannot be satisfied."""


def _filtered(characters: str, *, avoid_ambiguous: bool) -> str:
    if not avoid_ambiguous:
        return characters
    return "".join(character for character in characters if character not in AMBIGUOUS)


def _secure_shuffle(characters: list[str]) -> None:
    for index in range(len(characters) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        characters[index], characters[other] = characters[other], characters[index]


def generate_password(
    *,
    length: int,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    special: bool,
    min_digits: int,
    min_special: int,
    avoid_ambiguous: bool,
) -> str:
    if not 5 <= length <= 128:
        raise PasswordGenerationError("Password length must be between 5 and 128 characters")
    if min_digits < 0 or min_special < 0:
        raise PasswordGenerationError("Minimum character counts cannot be negative")
    if min_digits > length or min_special > length or min_digits + min_special > length:
        raise PasswordGenerationError("Minimum character counts exceed the requested password length")
    if min_digits and not digits:
        raise PasswordGenerationError("min_digits requires digits to be enabled")
    if min_special and not special:
        raise PasswordGenerationError("min_special requires special characters to be enabled")

    pools: list[str] = []
    uppercase_pool = _filtered(UPPERCASE, avoid_ambiguous=avoid_ambiguous)
    lowercase_pool = _filtered(LOWERCASE, avoid_ambiguous=avoid_ambiguous)
    digit_pool = _filtered(DIGITS, avoid_ambiguous=avoid_ambiguous)
    special_pool = _filtered(SPECIAL, avoid_ambiguous=avoid_ambiguous)

    if uppercase:
        pools.append(uppercase_pool)
    if lowercase:
        pools.append(lowercase_pool)
    if digits:
        pools.append(digit_pool)
    if special:
        pools.append(special_pool)
    if not pools:
        raise PasswordGenerationError("At least one character class must be enabled")
    if any(not pool for pool in pools):
        raise PasswordGenerationError("An enabled character class has no usable characters")

    result: list[str] = []
    result.extend(secrets.choice(digit_pool) for _ in range(min_digits))
    result.extend(secrets.choice(special_pool) for _ in range(min_special))

    combined = "".join(pools)
    result.extend(secrets.choice(combined) for _ in range(length - len(result)))
    _secure_shuffle(result)
    return "".join(result)
