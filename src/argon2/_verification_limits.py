# SPDX-License-Identifier: MIT

"""
Verification resource limits and bounded PHC parsing.

The encoded hash handed to :meth:`argon2.PasswordHasher.verify` is external
input.  The parameters embedded in it tell Argon2 how much memory and CPU to
use, so an attacker that can supply hashes can cause expensive computations
simply by writing large ``m``/``t``/``p`` values into an otherwise
valid-looking PHC string.

This module parses and audits the encoded hash *before* the Argon2 C library
is called.  Every numeric field is length-bounded while it is still text, so
a hostile input can never trigger unbounded work in :func:`int` or any
allocation.
"""

from __future__ import annotations

import base64

from dataclasses import dataclass

from ._utils import NoneType, _check_types
from .exceptions import InvalidHashError, VerificationLimitExceeded
from .low_level import ARGON2_VERSION, Type


__all__ = ["VerificationLimits", "parse_and_check_encoded_hash"]


_NAME_TO_TYPE = {"argon2id": Type.ID, "argon2i": Type.I, "argon2d": Type.D}

# Argon2 v1.2 (ARGON2_VERSION_10) hashes omit the version field; the current
# v1.3 (ARGON2_VERSION_13) carries v=19.
_ARGON2_VERSION_10 = 0x10
_ALLOWED_VERSIONS = frozenset({_ARGON2_VERSION_10, ARGON2_VERSION})

_PARAM_FIELDS = frozenset(("m", "t", "p"))

# PHC parameter values are decimal integers.  Bound the digit count while the
# value is still text, so that a megabyte-long number cannot reach int().
# 20 digits is wider than any uint32 parameter the Argon2 encoding could
# legitimately carry.
_MAX_DECIMAL_DIGITS = 20


@dataclass(frozen=True, slots=True)
class VerificationLimits:
    """
    Resource limits for :meth:`argon2.PasswordHasher.verify`.

    Every field is an inclusive upper bound on one property of the *encoded
    hash supplied by the caller* -- none of them rewrite or cap the hash's
    parameters.  ``None`` means that the property is not limited.

    All checks happen purely structurally, *before* any Argon2 computation.
    A hash that violates a limit raises
    :exc:`argon2.exceptions.VerificationLimitExceeded`, which is never a
    password mismatch and never includes the password or the hash.

    Args:
        hash_length:
            Maximum total length of the encoded hash string, in bytes.
            Checked first, before the string is parsed.

        memory_cost:
            Maximum ``memory_cost`` (``m``), in kibibytes.  This is the total
            memory Argon2 uses; it is compared against ``m`` directly and is
            *not* multiplied by ``parallelism``.

        time_cost: Maximum ``time_cost`` (``t``), in iterations.

        parallelism: Maximum ``parallelism`` (``p``), in threads.

        work:
            Maximum ``memory_cost * time_cost`` work factor.  The
            multiplication uses arbitrary-precision integers, so the
            comparison cannot be defeated by integer overflow.

        salt_length: Maximum decoded salt length, in bytes.

        hash_bytes_length: Maximum decoded hash (tag) length, in bytes.

    Raises:
        TypeError: If a field is neither an int nor None.
        ValueError: If a field is a bool, zero, or negative.

    .. versionadded:: 26.1.0
    """

    hash_length: int | None = None
    memory_cost: int | None = None
    time_cost: int | None = None
    parallelism: int | None = None
    work: int | None = None
    salt_length: int | None = None
    hash_bytes_length: int | None = None

    def __post_init__(self) -> None:
        type_error = _check_types(
            **{
                name: (getattr(self, name), (int, NoneType))
                for name in self.__dataclass_fields__
            }
        )
        if type_error is not None:
            raise TypeError(type_error)

        errors = []
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool):
                errors.append(f"'{name}' must not be a bool.")
            elif value is not None and value < 1:
                errors.append(
                    f"'{name}' must be a positive integer (got {value})."
                )
        if errors:
            raise ValueError(" ".join(errors))


@dataclass(frozen=True, slots=True)
class _ParsedHash:
    """
    Structured view of a bounded, well-formed PHC hash.
    """

    type: Type
    version: int
    memory_cost: int
    time_cost: int
    parallelism: int
    salt_len: int
    hash_len: int


def _parse_bounded_int(raw: str) -> int:
    """
    Parse a PHC decimal integer, rejecting non-digits and overlong values.
    """
    if (
        not raw
        or len(raw) > _MAX_DECIMAL_DIGITS
        or not raw.isascii()
        or not raw.isdigit()
    ):
        raise InvalidHashError

    return int(raw)


def _parse_version_field(field: str) -> int:
    """
    Parse the ``v=19`` segment (or the synthetic one for v1.2 hashes).
    """
    key, sep, raw = field.partition("=")
    if not sep or key != "v":
        raise InvalidHashError

    version = _parse_bounded_int(raw)
    if version not in _ALLOWED_VERSIONS:
        raise InvalidHashError

    return version


def _parse_params_field(field: str) -> tuple[int, int, int]:
    """
    Parse the canonical ``m=..,t=..,p=..`` segment.

    Duplicates, unknown parameters and non-canonical ordering are rejected.
    The Argon2 reference decoder expects this exact order too, so anything
    accepted here is also acceptable to the C library.
    """
    values: dict[str, int] = {}
    for chunk in field.split(","):
        key, sep, raw = chunk.partition("=")
        if not sep or key not in _PARAM_FIELDS or key in values:
            raise InvalidHashError
        values[key] = _parse_bounded_int(raw)

    if list(values) != ["m", "t", "p"]:
        raise InvalidHashError

    return values["m"], values["t"], values["p"]


def _decoded_base64_len(field: str) -> int:
    """
    Return the decoded length of an unpadded PHC base64 segment.

    The segment is actually decoded (not just measured) so that illegal
    alphabets and truncation are surfaced as format errors.
    """
    # A base64 string can never have length mod 4 == 1; PHC carries no
    # padding characters.
    if not field or "=" in field or len(field) % 4 == 1:
        raise InvalidHashError

    padded = field + "=" * (-len(field) % 4)
    try:
        return len(base64.b64decode(padded, validate=True))
    except ValueError:
        raise InvalidHashError from None


# Message templates are kept out of the raise statements (TRY003/EM101) and
# never interpolate the password or the hash.
_LENGTH_LIMIT_MSG = (
    "The encoded hash exceeds the configured 'hash_length' verification limit."
)
_SCALAR_LIMIT_MSG = (
    "The hash exceeds the configured {field!r} verification limit."
)
_WORK_LIMIT_MSG = (
    "The hash exceeds the configured 'work' "
    "(memory_cost * time_cost) verification limit."
)


def _enforce_limits(limits: VerificationLimits, parsed: _ParsedHash) -> None:
    """
    Apply the policy to an already well-formed parsed hash.
    """
    scalar_checks = (
        ("memory_cost", limits.memory_cost, parsed.memory_cost),
        ("time_cost", limits.time_cost, parsed.time_cost),
        ("parallelism", limits.parallelism, parsed.parallelism),
        ("salt_length", limits.salt_length, parsed.salt_len),
        ("hash_bytes_length", limits.hash_bytes_length, parsed.hash_len),
    )
    for name, maximum, value in scalar_checks:
        if maximum is not None and value > maximum:
            msg = _SCALAR_LIMIT_MSG.format(field=name)
            raise VerificationLimitExceeded(msg)

    # Python integers cannot overflow: m*t is computed exactly no matter how
    # large the (bounded) inputs are.
    if limits.work is not None and (
        parsed.memory_cost * parsed.time_cost > limits.work
    ):
        raise VerificationLimitExceeded(_WORK_LIMIT_MSG)


def parse_and_check_encoded_hash(
    hash: bytes, limits: VerificationLimits
) -> _ParsedHash:
    """
    Parse and policy-check an encoded Argon2 hash without computing anything.

    The raw string length is checked first; only then are the bounded PHC
    fields parsed.  Malformed strings raise
    :exc:`argon2.exceptions.InvalidHashError`, well-formed strings that
    violate *limits* raise
    :exc:`argon2.exceptions.VerificationLimitExceeded`.  No Argon2 code is
    invoked by this function.
    """
    if limits.hash_length is not None and len(hash) > limits.hash_length:
        raise VerificationLimitExceeded(_LENGTH_LIMIT_MSG)

    try:
        text = hash.decode("ascii")
    except UnicodeDecodeError:
        raise InvalidHashError from None

    parts = text.split("$")
    # Argon2 v1.2 hashes have no explicit version segment.
    if len(parts) == 5:
        parts.insert(2, f"v={_ARGON2_VERSION_10}")
    if len(parts) != 6 or parts[0] != "":
        raise InvalidHashError

    try:
        hash_type = _NAME_TO_TYPE[parts[1]]
    except KeyError:
        raise InvalidHashError from None

    version = _parse_version_field(parts[2])
    memory_cost, time_cost, parallelism = _parse_params_field(parts[3])
    salt_len = _decoded_base64_len(parts[4])
    hash_len = _decoded_base64_len(parts[5])

    parsed = _ParsedHash(
        type=hash_type,
        version=version,
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        salt_len=salt_len,
        hash_len=hash_len,
    )

    _enforce_limits(limits, parsed)

    return parsed
