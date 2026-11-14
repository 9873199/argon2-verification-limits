# How to Hash a Password

*argon2-cffi* comes with an high-level API and uses the officially recommended low-memory Argon2 parameters that result in a verification time of 40--50ms on recent-ish hardware.

:::{warning}
The current memory requirement is set to rather conservative 64 MB.
However, in memory constrained environments such as Docker containers that can lead to problems.
One possible non-obvious symptom are apparent freezes that are caused by swapping.

Please check {doc}`parameters` for more details.
:::

Unless you have any special requirements, all you need to know is:

```python
>>> from argon2 import PasswordHasher
>>> ph = PasswordHasher()
>>> hash = ph.hash("correct horse battery staple")
>>> hash  # doctest: +SKIP
'$argon2id$v=19$m=65536,t=3,p=4$MIIRqgvgQbgj220jfp0MPA$YfwJSVjtjSU0zzV/P3S9nnQ/USre2wvJMjfCIjrTQbg'
>>> ph.verify(hash, "correct horse battery staple")
True
>>> ph.check_needs_rehash(hash)
False
>>> ph.verify(hash, "Tr0ub4dor&3")
Traceback (most recent call last):
...
argon2.exceptions.VerifyMismatchError: The password does not match the supplied hash
```

A login function could thus look like this:

```{literalinclude} login_example.py
```

---

## Limiting verification resources

The encoded hash itself carries the Argon2 `m`, `t` and `p` values, and those values decide how much memory and CPU a verification consumes.
If your application ever verifies hashes it did not mint itself -- a data import or migration being the classic case -- someone who can write arbitrary encodings into your hash store can make a single login attempt allocate gigabytes.

{class}`argon2.VerificationLimits` is the resource gate for {meth}`argon2.PasswordHasher.verify`.
A limited hasher parses and audits the encoded hash *before* Argon2 runs:

```python
from argon2 import PasswordHasher, VerificationLimits
from argon2.exceptions import (
    InvalidHashError,
    VerificationLimitExceeded,
    VerifyMismatchError,
)

limits = VerificationLimits(
    hash_length=256,  # maximum encoded length, in bytes
    memory_cost=65536,  # m in KiB; compared directly, never multiplied by p
    time_cost=3,  # t
    parallelism=4,  # p
    work=196608,  # m*t; compared with exact big-integer arithmetic
    salt_length=16,  # decoded salt length, in bytes
    hash_bytes_length=32,  # decoded tag length, in bytes
)
ph = PasswordHasher(verification_limits=limits)

try:
    ph.verify(stored_hash, password)
except VerificationLimitExceeded:
    # Well-formed but over budget: reject and quarantine the hash.
    # No Argon2 computation happened, so this is not a wrong password.
    ...
except InvalidHashError:
    # Malformed encoding (truncated, bad base64, unknown version, ...).
    ...
except VerifyMismatchError:
    # A genuine wrong password.
    ...
```

The ordering matters: the raw string length is checked first, then the bounded PHC fields are parsed, and only a hash that passes every check reaches Argon2.
A limit violation raises {exc}`argon2.exceptions.VerificationLimitExceeded` rather than a mismatch error, and neither that error nor the format error ever includes the password or the hash.
Fields left at `None` are not limited, and a `PasswordHasher` constructed without `verification_limits` keeps its original unrestricted behavior.
The limits never alter how new hashes are produced, and a successful {meth}`~argon2.PasswordHasher.verify` does not change what {meth}`~argon2.PasswordHasher.check_needs_rehash` reports: the two methods keep separate responsibilities.

---

While the {class}`argon2.PasswordHasher` class has the aspiration to be good to use out of the box, it has all the parametrization you'll need.
