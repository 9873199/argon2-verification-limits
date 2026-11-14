# SPDX-License-Identifier: MIT

"""
Tests for VerificationLimits and the bounded PHC parser.

The parser is the security boundary: everything here runs without ever
calling into the Argon2 C library.
"""

import base64

from unittest import mock

import pytest

from argon2 import PasswordHasher, Type, VerificationLimits, profiles
from argon2._verification_limits import parse_and_check_encoded_hash
from argon2.exceptions import (
    Argon2Error,
    InvalidHashError,
    VerificationLimitExceeded,
    VerifyMismatchError,
)


# A real, cheap, freshly encoded hash.  All mutation tests derive their
# hostile inputs from it so that every rejected string differs from a known
# good one in exactly one structural property.
@pytest.fixture
def cheap_hash() -> str:
    """
    A real CHEAPEST-profile Argon2id hash.
    """
    ph = PasswordHasher.from_parameters(profiles.CHEAPEST)

    return ph.hash("secret")


# The hand-rolled Argon2i v1.2 vector also used by the hasher test suite.
V12_HASH = "$argon2i$m=8,t=1,p=1$bL/lLsegFKTuR+5vVyA8tA$VKz5CHavCtFOL1N5TIXWSA"


def _replace_params(hash: str, new_params: str) -> str:
    """
    Replace the m/t/p segment of an encoded hash.
    """
    parts = hash.split("$")
    parts[3] = new_params

    return "$".join(parts)


def _replace_segment(hash: str, index: int, value: str) -> str:
    """
    Replace one ``$``-separated segment of an encoded hash.
    """
    parts = hash.split("$")
    parts[index] = value

    return "$".join(parts)


class TestVerificationLimits:
    def test_defaults_are_none(self):
        """
        Every limit defaults to None, meaning "not limited".
        """
        limits = VerificationLimits()

        assert all(
            getattr(limits, name) is None
            for name in limits.__dataclass_fields__
        )

    @pytest.mark.parametrize(
        "name",
        [
            "hash_length",
            "memory_cost",
            "time_cost",
            "parallelism",
            "work",
            "salt_length",
            "hash_bytes_length",
        ],
    )
    def test_positive_int_accepted(self, name):
        """
        Plain positive integers are accepted for every field.
        """
        limits = VerificationLimits(**{name: 42})

        assert getattr(limits, name) == 42

    @pytest.mark.parametrize(
        "name",
        [
            "hash_length",
            "memory_cost",
            "time_cost",
            "parallelism",
            "work",
            "salt_length",
            "hash_bytes_length",
        ],
    )
    def test_bool_rejected(self, name):
        """
        Booleans are rejected even though bool subclasses int.
        """
        with pytest.raises(ValueError, match=f"'{name}' must not be a bool"):
            VerificationLimits(**{name: True})

        with pytest.raises(ValueError, match=f"'{name}' must not be a bool"):
            VerificationLimits(**{name: False})

    @pytest.mark.parametrize("value", [0, -1, -(10**9)])
    def test_non_positive_rejected(self, value):
        """
        Zero and negative integers are rejected with the field name.
        """
        with pytest.raises(ValueError, match="'work' must be a positive"):
            VerificationLimits(work=value)

    @pytest.mark.parametrize("value", ["8", 8.0, 1.5, object()])
    def test_wrong_type_rejected(self, value):
        """
        Non-int, non-None values raise TypeError, not ValueError.
        """
        with pytest.raises(TypeError, match="'memory_cost' must be a"):
            VerificationLimits(memory_cost=value)

    def test_none_explicitly_allowed(self):
        """
        Passing None explicitly is the same as leaving the field out.
        """
        assert VerificationLimits(memory_cost=None).memory_cost is None

    def test_errors_aggregated(self):
        """
        All violations are reported in one message.
        """
        with pytest.raises(ValueError) as exc_info:
            VerificationLimits(memory_cost=0, time_cost=-2)

        message = str(exc_info.value)
        assert "'memory_cost'" in message
        assert "'time_cost'" in message

    def test_frozen(self):
        """
        Limit objects are immutable.
        """
        with pytest.raises(AttributeError):
            VerificationLimits(memory_cost=1).memory_cost = 2  # type: ignore[misc]


class TestParsing:
    def test_valid_v19_hash(self, cheap_hash):
        """
        A well-formed v1.3 hash is fully parsed without any computation.
        """
        parsed = parse_and_check_encoded_hash(
            cheap_hash.encode(), VerificationLimits()
        )

        assert parsed.type is Type.ID
        assert parsed.version == 19
        assert parsed.memory_cost == 8
        assert parsed.time_cost == 1
        assert parsed.parallelism == 1
        assert parsed.salt_len == 8
        assert parsed.hash_len == 4

    def test_implicit_v12_hash(self):
        """
        A five-segment Argon2 v1.2 hash is recognized as version 16.
        """
        parsed = parse_and_check_encoded_hash(
            V12_HASH.encode(), VerificationLimits()
        )

        assert parsed.type is Type.I
        assert parsed.version == 16
        assert parsed.memory_cost == 8
        assert parsed.parallelism == 1
        assert parsed.salt_len == 16
        assert parsed.hash_len == 16

    def test_explicit_v16_hash(self, cheap_hash):
        """
        An explicit v=16 segment is accepted and normalized the same way.
        """
        hash = cheap_hash.replace("v=19", "v=16")

        parsed = parse_and_check_encoded_hash(
            hash.encode(), VerificationLimits()
        )

        assert parsed.version == 16

    @pytest.mark.parametrize("type_name", ["argon2d", "argon2i", "argon2id"])
    def test_all_variants_accepted(self, cheap_hash, type_name):
        """
        All three Argon2 variants are explicitly accepted.
        """
        hash = cheap_hash.replace("argon2id", type_name)

        parsed = parse_and_check_encoded_hash(
            hash.encode(), VerificationLimits()
        )

        assert (
            parsed.type
            is Type[
                {"argon2d": "D", "argon2i": "I", "argon2id": "ID"}[type_name]
            ]
        )

    @pytest.mark.parametrize(
        "hash",
        [
            "",
            "tiger",
            "$$",
            "$argon2id$v=19$m=8,t=1,p=1$x",  # too few segments
            "$argon2id$v=19$m=8,t=1,p=1$x$y$z",  # too many segments
            "garbage" + "$argon2id$v=19$m=8,t=1,p=1$x$y",
            "$argon5$v=19$m=8,t=1,p=1$x$y",  # unknown algorithm
            "$argon2id$x=19$m=8,t=1,p=1$x$y",  # missing v key
            "$argon2id$v=17$m=8,t=1,p=1$x$y",  # unknown version
            "$argon2id$v=20$m=8,t=1,p=1$x$y",
            "$argon2id$v=0$m=8,t=1,p=1$x$y",
            "$argon2id$v=-1$m=8,t=1,p=1$x$y",
            "$argon2id$v=19.0$m=8,t=1,p=1$x$y",
            "$argon2id$v=19$m=8,t=1$x$y",  # missing parameter
            "$argon2id$v=19$m=8,t=1,p=1,q=2$x$y",  # unknown parameter
            "$argon2id$v=19$m=8,m=9,t=1,p=1$x$y",  # duplicate parameter
            "$argon2id$v=19$p=1,m=8,t=1$x$y",  # non-canonical order
            "$argon2id$v=19$m=abc,t=1,p=1$x$y",  # non-numeric
            "$argon2id$v=19$m=-8,t=1,p=1$x$y",  # negative parameter
            "$argon2id$v=19$m=8.0,t=1,p=1$x$y",
            "$argon2id$v=19$m=,t=1,p=1$x$y",  # empty value
            "$argon2id$v=19$m=0x8,t=1,p=1$x$y",
            "$argon2id$v=19$m=8,t=1,p=1$$y",  # empty salt segment
            "$argon2id$v=19$m=8,t=1,p=1$x$",  # empty hash segment
            "$argon2id$v=19$m=8,t=1,p=1$x$y=",  # padding not allowed
            "$argon2id$v=19$m=8,t=1,p=1$x$y!",  # illegal base64 alphabet
            "$argon2id$v=19$m=8,t=1,p=1$x$yy",  # base64 length mod 4 == 1
        ],
    )
    def test_malformed_hash(self, hash):
        """
        Every structural defect raises InvalidHashError, never another type.
        """
        with pytest.raises(InvalidHashError):
            parse_and_check_encoded_hash(hash.encode(), VerificationLimits())

    def test_non_ascii_bytes(self):
        """
        Non-ASCII bytes are a format error, not a Unicode crash.
        """
        with pytest.raises(InvalidHashError):
            parse_and_check_encoded_hash(
                b"$argon2id$v=19$m=8,t=1,p=1$\xff$x",
                VerificationLimits(),
            )

    def test_digit_bound_short_value_parses(self, cheap_hash):
        """
        A 20-digit value is still parsed (then checked against the policy).
        """
        hash = _replace_params(cheap_hash, "m=99999999999999999999,t=1,p=1")

        parsed = parse_and_check_encoded_hash(
            hash.encode(), VerificationLimits()
        )

        assert parsed.memory_cost == 10**20 - 1

    def test_digit_bound_overlong_value_rejected(self, cheap_hash):
        """
        A 21-digit value is rejected as malformed while still text, so int()
        never has to deal with an attacker-sized number.
        """
        hash = _replace_params(cheap_hash, "m=" + "9" * 21 + ",t=1,p=1")

        with pytest.raises(InvalidHashError):
            parse_and_check_encoded_hash(hash.encode(), VerificationLimits())


class TestLimitEnforcement:
    def test_scalar_boundaries(self, cheap_hash):
        """
        A value equal to the inclusive limit passes, one above it fails.

        The "over" case is built by raising the value *in the encoding*,
        never by loosening the policy.
        """
        over_limit_hashes = {
            "memory_cost": (
                8,
                _replace_params(cheap_hash, "m=9,t=1,p=1"),
            ),
            "time_cost": (
                1,
                _replace_params(cheap_hash, "m=8,t=2,p=1"),
            ),
            "parallelism": (
                1,
                _replace_params(cheap_hash, "m=8,t=1,p=2"),
            ),
            "salt_length": (
                8,
                _replace_segment(
                    cheap_hash,
                    4,
                    cheap_hash.split("$")[4]
                    + base64.b64encode(b"abc").decode(),
                ),
            ),
            "hash_bytes_length": (
                4,
                _replace_segment(
                    cheap_hash,
                    5,
                    cheap_hash.split("$")[5]
                    + base64.b64encode(b"abc").decode(),
                ),
            ),
        }

        for field, (limit, over_limit_hash) in over_limit_hashes.items():
            # Exactly at the inclusive boundary: accepted.
            parse_and_check_encoded_hash(
                cheap_hash.encode(), VerificationLimits(**{field: limit})
            )

            # One unit over the boundary: rejected with the limit named.
            with pytest.raises(VerificationLimitExceeded, match=field):
                parse_and_check_encoded_hash(
                    over_limit_hash.encode(),
                    VerificationLimits(**{field: limit}),
                )

    def test_hash_length_checked_first(self, cheap_hash):
        """
        The total encoded length is checked before any field is parsed: a
        malformed string that is too long reports the length violation.
        """
        garbage = "x" * (len(cheap_hash) + 10)

        with pytest.raises(VerificationLimitExceeded, match="hash_length"):
            parse_and_check_encoded_hash(
                garbage.encode(),
                VerificationLimits(hash_length=len(cheap_hash)),
            )

    def test_hash_length_boundary(self, cheap_hash):
        """
        Exactly the limit passes; a single extra byte fails.
        """
        encoded = cheap_hash.encode()

        parse_and_check_encoded_hash(
            encoded, VerificationLimits(hash_length=len(encoded))
        )

        with pytest.raises(VerificationLimitExceeded):
            parse_and_check_encoded_hash(
                encoded, VerificationLimits(hash_length=len(encoded) - 1)
            )

    def test_work_boundary(self, cheap_hash):
        """
        The work limit compares m*t exactly, at and above the boundary.
        """
        # CHEAPEST: m=8, t=1 -> work 8.
        parse_and_check_encoded_hash(
            cheap_hash.encode(), VerificationLimits(work=8)
        )

        slower = _replace_params(cheap_hash, "m=8,t=2,p=1")
        with pytest.raises(VerificationLimitExceeded, match="work"):
            parse_and_check_encoded_hash(
                slower.encode(), VerificationLimits(work=8)
            )

    def test_work_arithmetic_cannot_overflow(self, cheap_hash):
        """
        m*t uses Python big integers: a giant product is compared exactly
        instead of wrapping around.
        """
        hash = _replace_params(
            cheap_hash, "m=99999999999999999999,t=9999999999,p=1"
        )

        # A limit far above the true product passes the check.
        parse_and_check_encoded_hash(
            hash.encode(), VerificationLimits(work=10**40)
        )

        # A limit below the true product rejects it -- on a 32-bit C target
        # the wrapped product would have slipped through.
        with pytest.raises(VerificationLimitExceeded, match="work"):
            parse_and_check_encoded_hash(
                hash.encode(), VerificationLimits(work=10**19)
            )

    def test_memory_is_not_multiplied_by_parallelism(self):
        """
        The memory limit compares m as the total memory directly, for every
        supported parallelism.
        """
        for parallelism in (1, 2, 4):
            ph = PasswordHasher(
                1,
                8 * parallelism,
                parallelism,
                4,
                8,
                verification_limits=VerificationLimits(
                    memory_cost=8 * parallelism
                ),
            )
            hash = ph.hash("secret")

            parsed = parse_and_check_encoded_hash(
                hash.encode(),
                VerificationLimits(memory_cost=8 * parallelism),
            )
            assert parsed.memory_cost == 8 * parallelism
            assert parsed.parallelism == parallelism

    def test_long_decimal_trips_length_first(self, cheap_hash):
        """
        A malicious long decimal field is stopped by the length limit before
        parsing even starts.
        """
        hash = _replace_params(cheap_hash, "m=" + "9" * 5000 + ",t=1,p=1")

        with pytest.raises(VerificationLimitExceeded, match="hash_length"):
            parse_and_check_encoded_hash(
                hash.encode(),
                VerificationLimits(hash_length=len(cheap_hash)),
            )

        # Without a length limit, the digit bound turns it into a format
        # error instead.
        with pytest.raises(InvalidHashError):
            parse_and_check_encoded_hash(hash.encode(), VerificationLimits())

    def test_error_message_does_not_leak(self, cheap_hash):
        """
        Limit errors name the violated limit but never the hash or password.
        """
        forbidden_text = "super-secret-password"
        hash = _replace_params(cheap_hash, "m=9,t=1,p=1")

        with pytest.raises(VerificationLimitExceeded) as exc_info:
            parse_and_check_encoded_hash(
                hash.encode(), VerificationLimits(memory_cost=8)
            )

        message = str(exc_info.value)
        assert forbidden_text not in message
        assert hash not in message
        assert "memory_cost" in message

    def test_exception_hierarchy(self):
        """
        Limit errors are Argon2 errors but neither mismatch nor format
        errors, so callers cannot mistake a policy rejection for a bad
        password.
        """
        assert issubclass(VerificationLimitExceeded, Argon2Error)
        assert not issubclass(VerificationLimitExceeded, VerifyMismatchError)
        assert not issubclass(VerificationLimitExceeded, InvalidHashError)


class TestPasswordHasherIntegration:
    """
    End-to-end behavior through PasswordHasher.verify.

    Positive cases use the real, cheap Argon2 implementation; hostile cases
    only edit an encoded string and prove via a counter that the underlying
    compute function is never entered.
    """

    @pytest.fixture
    def limited_hasher(self):
        """
        A CHEAPEST-profile hasher whose limits match its own hashes exactly.
        """
        return PasswordHasher(
            1,
            8,
            1,
            4,
            8,
            verification_limits=VerificationLimits(
                hash_length=128,
                memory_cost=8,
                time_cost=1,
                parallelism=1,
                work=8,
                salt_length=8,
                hash_bytes_length=4,
            ),
        )

    def test_correct_password_verifies(self, limited_hasher):
        """
        A conforming hash and the correct password still verify for real.
        """
        hash = limited_hasher.hash("secret")

        assert limited_hasher.verify(hash, "secret") is True

    @pytest.mark.parametrize(
        "password", ["wrong", b"wrong"], ids=["str", "bytes"]
    )
    def test_wrong_password_is_a_mismatch(self, limited_hasher, password):
        """
        A conforming hash with a wrong password is a genuine mismatch, not a
        limit error.
        """
        hash = limited_hasher.hash("secret")

        with pytest.raises(VerifyMismatchError):
            limited_hasher.verify(hash, password)

    def test_bytes_hash_and_password(self, limited_hasher):
        """
        The limited path accepts bytes for both hash and password.
        """
        hash = limited_hasher.hash("secret").encode()

        assert limited_hasher.verify(hash, b"secret") is True

    def test_no_limits_keeps_legacy_behavior(self, cheap_hash):
        """
        Without a policy, verification behaves exactly as before, including
        its lightweight header-only validation.
        """
        ph = PasswordHasher.from_parameters(profiles.CHEAPEST)

        assert ph.verification_limits is None
        assert ph.verify(cheap_hash, "secret") is True
        with pytest.raises(InvalidHashError):
            ph.verify("tiger", "secret")

    def test_limits_attribute_stored(self, limited_hasher):
        """
        The configured policy is exposed read-only on the hasher.
        """
        assert isinstance(
            limited_hasher.verification_limits, VerificationLimits
        )
        assert limited_hasher.verification_limits.memory_cost == 8

    @pytest.mark.parametrize(
        ("new_params", "violated"),
        [
            ("m=999999999,t=1,p=1", "memory_cost"),
            ("m=8,t=999999999,p=1", "time_cost"),
            ("m=8,t=1,p=999999999", "parallelism"),
            ("m=65536,t=1,p=1", "memory_cost"),
        ],
    )
    def test_high_cost_hash_never_reaches_argon2(
        self, limited_hasher, new_params, violated
    ):
        """
        A hostile high-cost hash is produced by editing the encoding only.
        The underlying verify_secret counter proves zero Argon2 computations
        and therefore zero large allocations.
        """
        good = limited_hasher.hash("secret")
        hostile = _replace_params(good, new_params)

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(VerificationLimitExceeded, match=violated):
                limited_hasher.verify(hostile, "secret")

            assert verify_secret.call_count == 0

    def test_work_attack_never_reaches_argon2(self):
        """
        An m*t work attack is stopped before any computation.  The scalar
        limits are generous so that only the work limit can fire.
        """
        ph = PasswordHasher(
            1,
            8,
            1,
            4,
            8,
            verification_limits=VerificationLimits(
                memory_cost=1_000_000,
                time_cost=1_000_000,
                parallelism=1_000_000,
                work=8,
            ),
        )
        hostile = _replace_params(ph.hash("secret"), "m=8,t=2,p=1")

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(VerificationLimitExceeded, match="work"):
                ph.verify(hostile, "secret")

            assert verify_secret.call_count == 0

    def test_hash_length_attack_never_reaches_argon2(self, limited_hasher):
        """
        An overlong encoded string is rejected on raw length, before parse.
        """
        good = limited_hasher.hash("secret")
        hostile = good + "A" * 100

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(VerificationLimitExceeded, match="hash_length"):
                limited_hasher.verify(hostile, "secret")

            assert verify_secret.call_count == 0

    def test_malformed_hash_never_reaches_argon2(self, limited_hasher):
        """
        Structural defects raise InvalidHashError and never compute.
        """
        good = limited_hasher.hash("secret")
        hostile = _replace_params(good, "m=8,m=9,t=1,p=1")

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(InvalidHashError):
                limited_hasher.verify(hostile, "secret")

            assert verify_secret.call_count == 0

    @pytest.mark.parametrize(
        "hostile",
        [
            "$argon2id$v=19$m=8,t=1,p=1$ÿ$x",  # non-ASCII str
            b"$argon2id$v=19$m=8,t=1,p=1$\xff$x",  # non-ASCII bytes
        ],
        ids=["str", "bytes"],
    )
    def test_non_ascii_hash_is_format_error(self, limited_hasher, hostile):
        """
        Non-ASCII input is a format error, never an encoding crash or a
        verification computation.
        """
        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(InvalidHashError):
                limited_hasher.verify(hostile, "secret")

            assert verify_secret.call_count == 0

    def test_malicious_long_decimal_never_reaches_argon2(self, limited_hasher):
        """
        A multi-kilobyte decimal field is rejected cheaply and never parsed
        into a giant int or handed to Argon2.
        """
        good = limited_hasher.hash("secret")
        hostile = _replace_params(good, "m=" + "9" * 5000 + ",t=1,p=1")

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises((InvalidHashError, VerificationLimitExceeded)):
                limited_hasher.verify(hostile, "secret")

            assert verify_secret.call_count == 0

    def test_repeated_use_is_isolated(self, limited_hasher):
        """
        Rejected calls leave no residue: the same hasher keeps verifying
        conforming hashes afterwards, and the counter resets per call.
        """
        good = limited_hasher.hash("secret")
        hostile = _replace_params(good, "m=9,t=1,p=1")

        for _ in range(5):
            with mock.patch(
                "argon2._password_hasher.verify_secret"
            ) as verify_secret:
                with pytest.raises(VerificationLimitExceeded):
                    limited_hasher.verify(hostile, "secret")
                assert verify_secret.call_count == 0

        # The hasher still works normally for a conforming hash.
        assert limited_hasher.verify(good, "secret") is True

    def test_rehash_responsibility_unchanged(self, limited_hasher):
        """
        A successful verify does not imply "no rehash needed"; the two
        methods keep independent responsibilities.
        """
        # A hash made with a different Argon2 variant but the same,
        # policy-conforming resource parameters.
        other = PasswordHasher(1, 8, 1, 4, 8, type=Type.I)
        hash = other.hash("secret")

        # verify succeeds because the hash is within the policy...
        assert limited_hasher.verify(hash, "secret") is True
        # ...yet check_needs_rehash still flags the differing variant.
        assert limited_hasher.check_needs_rehash(hash) is True

    def test_policy_does_not_rewrite_parameters(self, limited_hasher):
        """
        Passing limits never changes the parameters used for hashing.
        """
        unlimited = PasswordHasher(1, 8, 1, 4, 8)

        assert (
            limited_hasher.hash("secret").split("$")[3]
            == unlimited.hash("secret").split("$")[3]
        )
        assert limited_hasher.memory_cost == unlimited.memory_cost

    def test_v12_hash_through_limited_hasher(self):
        """
        A legacy v1.2 hash verifies for real when within the policy.
        """
        ph = PasswordHasher(
            1,
            8,
            1,
            16,
            16,
            type=Type.I,
            verification_limits=VerificationLimits(
                memory_cost=8, time_cost=1, parallelism=1
            ),
        )

        assert ph.verify(V12_HASH, "pässword".encode("latin1")) is True

        # The same hash over a tighter limit is blocked pre-computation.
        tight = PasswordHasher(
            1,
            8,
            1,
            16,
            16,
            type=Type.I,
            verification_limits=VerificationLimits(memory_cost=4),
        )
        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(VerificationLimitExceeded):
                tight.verify(V12_HASH, "secret")
            assert verify_secret.call_count == 0

    def test_salt_and_hash_length_limits(self, limited_hasher):
        """
        Decoded salt and tag lengths are measured, not the base64 text.
        """
        good = limited_hasher.hash("secret")
        parts = good.split("$")
        # Grow the salt segment by one base64 group -> +3 decoded bytes.
        long_salt = _replace_segment(
            good, 4, parts[4] + base64.b64encode(b"abc").decode()
        )

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(VerificationLimitExceeded, match="salt_length"):
                limited_hasher.verify(long_salt, "secret")
            assert verify_secret.call_count == 0

    def test_constructor_rejects_bad_limits(self):
        """
        PasswordHasher surfaces invalid VerificationLimits at construction.
        """
        with pytest.raises((TypeError, ValueError)):
            PasswordHasher(
                verification_limits=VerificationLimits(memory_cost=0)
            )

        with pytest.raises(TypeError, match="verification_limits"):
            PasswordHasher(
                verification_limits={"memory_cost": 8}  # type: ignore[arg-type]
            )

    def test_wrong_password_does_not_mask_limit_error(self, limited_hasher):
        """
        A policy violation is reported even when the password is wrong:
        resource checks happen before any password comparison.
        """
        good = limited_hasher.hash("secret")
        hostile = _replace_params(good, "m=9,t=1,p=1")

        with mock.patch(
            "argon2._password_hasher.verify_secret"
        ) as verify_secret:
            with pytest.raises(VerificationLimitExceeded):
                limited_hasher.verify(hostile, "definitely-wrong")
            assert verify_secret.call_count == 0
