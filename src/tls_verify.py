"""TLS certificate verification setting: the one parser of ``EDGEGUARD_SSL_VERIFY`` and ``SSL_VERIFY``.

The rule is fail-closed:

- The first of ``EDGEGUARD_SSL_VERIFY`` and ``SSL_VERIFY`` that is set and not blank decides;
  ``SSL_VERIFY`` is therefore read only when ``EDGEGUARD_SSL_VERIFY`` is unset or blank.
- Its value, with surrounding ASCII whitespace (space, tab, newline, carriage return, form feed,
  vertical tab) ignored and case-insensitive, verifies for ``true``, ``1``, ``yes`` and ``on``, and
  does not verify for ``false``, ``0``, ``no`` and ``off``.
- Neither variable set (or both blank): verify.
- Any other value: verify, and log one WARNING naming the variable and the value. A value carrying
  another character around it (a non-breaking space pasted from a web page, another Unicode space)
  or a byte that is not UTF-8 is such a value.

``config.SSL_VERIFY`` is this rule applied once, at import; the services take that value.
``scripts/preflight_baseline.sh`` applies the same rule in the shell, byte-wise in the C locale, so
it judges a value as the services do whatever the operator's locale. The module imports nothing
outside the standard library, so a reader that must not load ``config`` (which requires
``NEO4J_PASSWORD`` and ``MISP_API_KEY``) reads the setting the same way.
"""

from __future__ import annotations

import logging
import os
from typing import Mapping, NamedTuple, Optional, Set, Tuple

logger = logging.getLogger(__name__)

SSL_VERIFY_ENV_NAMES: Tuple[str, str] = ("EDGEGUARD_SSL_VERIFY", "SSL_VERIFY")
VERIFY_VALUES = frozenset({"true", "1", "yes", "on"})
NO_VERIFY_VALUES = frozenset({"false", "0", "no", "off"})
# What the preflight's [:space:] matches in the C locale. str.strip() without an argument would also
# remove Unicode spaces and the separators \x1c-\x1f, which the shell keeps.
ASCII_WHITESPACE = " \t\n\r\f\v"


class SslVerifySetting(NamedTuple):
    """The setting as read: ``variable`` and ``value`` are ``None`` when neither variable is set."""

    verify: bool
    variable: Optional[str]
    value: Optional[str]
    recognised: bool


def read_ssl_verify_setting(environ: Optional[Mapping[str, str]] = None) -> SslVerifySetting:
    """Apply the rule to ``environ`` (default ``os.environ``) without logging."""
    env = os.environ if environ is None else environ
    for name in SSL_VERIFY_ENV_NAMES:
        raw = env.get(name)
        if raw is None:
            continue
        value = str(raw).strip(ASCII_WHITESPACE)
        if not value:
            continue
        lowered = value.lower()
        if lowered in VERIFY_VALUES:
            return SslVerifySetting(True, name, value, True)
        if lowered in NO_VERIFY_VALUES:
            return SslVerifySetting(False, name, value, True)
        return SslVerifySetting(True, name, value, False)
    return SslVerifySetting(True, None, None, True)


def unrecognised_value_message(setting: SslVerifySetting) -> str:
    """The text for an unrecognised value (logged here, reported by ``edgeguard validate``)."""
    return (
        f"{setting.variable}={setting.value!r} is not a recognised value "
        f"(true, 1, yes, on / false, 0, no, off); TLS verification stays on"
    )


# (variable, value) pairs already logged: one WARNING per process, however many readers call.
_WARNED: Set[Tuple[Optional[str], Optional[str]]] = set()


def edgeguard_ssl_verify_from_env(environ: Optional[Mapping[str, str]] = None) -> bool:
    """True = verify TLS for HTTPS (MISP and the feeds). Logs one WARNING for an unrecognised value."""
    setting = read_ssl_verify_setting(environ)
    if not setting.recognised:
        key = (setting.variable, setting.value)
        if key not in _WARNED:
            _WARNED.add(key)
            logger.warning(unrecognised_value_message(setting))
    return setting.verify
