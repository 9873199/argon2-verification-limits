# SPDX-License-Identifier: MIT

from __future__ import annotations


class Argon2Error(Exception):
    """
    Superclass of all argon2 exceptions.

    Never thrown directly.
    """


class VerificationError(Argon2Error):
    """
    Verification failed.

    You can find the original error message from Argon2 in ``args[0]``.
    """


class VerifyMismatchError(VerificationError):
    """
    The secret does not match the hash.

    Subclass of :exc:`argon2.exceptions.VerificationError`.

    .. versionadded:: 16.1.0
    """


class HashingError(Argon2Error):
    """
    Raised if hashing failed.

    You can find the original error message from Argon2 in ``args[0]``.
    """


class VerificationLimitExceeded(Argon2Error):  # noqa: N818
    """
    Raised if a hash passed to :meth:`argon2.PasswordHasher.verify` exceeds
    the configured :class:`argon2.VerificationLimits`.

    This is raised *before* any Argon2 computation is performed and therefore
    does not mean that the password is wrong.  Neither the password nor the
    hash are included in the exception message.

    .. versionadded:: 26.1.0
    """


class InvalidHashError(ValueError):
    """
    Raised if the hash is invalid before passing it to Argon2.

    .. versionadded:: 23.1.0
       As a replacement for :exc:`argon2.exceptions.InvalidHash`.
    """


class UnsupportedParametersError(ValueError):
    """
    Raised if the current platform does not support the parameters.

    For example, in WebAssembly parallelism must be set to 1.

    .. versionadded:: 25.1.0
    """


InvalidHash = InvalidHashError
"""
Deprecated alias for :class:`InvalidHashError`.

.. versionadded:: 18.2.0
.. deprecated:: 23.1.0
    Use :exc:`argon2.exceptions.InvalidHashError` instead.
"""
