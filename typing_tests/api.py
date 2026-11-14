import argon2


argon2.PasswordHasher.from_parameters(argon2.profiles.RFC_9106_HIGH_MEMORY)
ph = argon2.PasswordHasher()

ph.hash("pw")
ph.hash("pw", salt=b"salt")
ph.hash(b"pw")
ph.hash(b"pw", salt=b"salt")
ph.verify("hash", "pw")
ph.verify(b"hash", "pw")
ph.verify(b"hash", b"pw")
ph.verify("hash", b"pw")

if ph.check_needs_rehash("hash") is True:
    ...

params: argon2.Parameters = argon2.profiles.get_default_parameters()

limits: argon2.VerificationLimits = argon2.VerificationLimits(
    hash_length=256,
    memory_cost=65536,
    time_cost=3,
    parallelism=4,
    work=196608,
    salt_length=16,
    hash_bytes_length=32,
)
limited = argon2.PasswordHasher(verification_limits=limits)
stored: argon2.VerificationLimits | None = limited.verification_limits
limited.verify("hash", "pw")

unrestricted = argon2.VerificationLimits()
if unrestricted.memory_cost is None:
    ...
