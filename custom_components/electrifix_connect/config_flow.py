"""One field: the job code. Validated by actually connecting.

WHY IT CONNECTS RATHER THAN CHECKING THE SHAPE
-----------------------------------------------
A job code is 32 random bytes in base64url, so "is it the right length and
alphabet" is a check that passes for every typo that happens to be the right
length -- and the customer then gets a config entry that looks fine, sits
there, and never connects, with the real answer (4401) only in a log they
will never open.

So the flow dials the relay once and asks. The service answers a bad code
by CLOSING with 4401, a rate limit with 4429 and a switched-off relay with
4503, each of which becomes a different sentence in front of the customer.

IT ASKS WITH `check`, NOT WITH `hello` (1.1.2)
-----------------------------------------------
Until 1.1.2 this dialog sent a REAL `hello`, and the service registered it
as the job's agent -- so the check itself became a second socket for the
job, racing the entry's real one. Whichever registered second displaced the
first, and 1.1.1 treated being displaced as the end of the integration: the
server ended up holding a socket nobody was reading and the customer's job
sat "waiting" until someone reloaded the config entry. It happened twice in
production, on 2026-09-16 and 09-17.

`check` does the same authentication and registers nothing, and it answers
in one round trip rather than eight seconds of silence.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Final

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import SOURCE_REAUTH, ConfigFlow, ConfigFlowResult

from .const import (
    CLOSE_BAD_CODE,
    CLOSE_RATE_LIMITED,
    CLOSE_RELAY_OFF,
    CONF_JOB_CODE,
    CONF_USER_ID,
    DEFAULT_RELAY_URL,
    DOMAIN,
    ENV_RELAY_URL,
    INTEGRATION_VERSION,
)

_LOG = logging.getLogger(__name__)

#: How long to wait, after the hello, for the service to object. The service
#: decides in one round trip; this is generous for a domestic uplink and
#: short enough that a customer does not think the dialog has hung.
_VALIDATE_SECONDS = 8.0

STEP_USER_SCHEMA = vol.Schema({vol.Required(CONF_JOB_CODE): str})


class ElectrifixConnectConfigFlow(ConfigFlow, domain=DOMAIN):
    """The whole setup: paste the code, press submit."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        reauth = self.source == SOURCE_REAUTH
        if user_input is not None:
            code = clean_code(user_input.get(CONF_JOB_CODE))
            if not code:
                errors["base"] = "bad_code"
            else:
                if reauth:
                    # UPDATE THE EXISTING ENTRY. Creating a second one would
                    # leave the dead entry beside the live one, each with its
                    # own agent; aborting on `already_configured` -- which is
                    # what the plain user step does when the SAME code is
                    # re-entered -- would make a re-auth impossible to
                    # complete at all.
                    entry = self._get_reauth_entry()
                    error = await _validate(self.hass, code)
                    if error:
                        errors["base"] = error
                    else:
                        return self.async_update_reload_and_abort(
                            entry,
                            unique_id=_fingerprint(code),
                            title="ElectriFix Connect",
                            data_updates={CONF_JOB_CODE: code},
                        )
                else:
                    # ONE ENTRY PER JOB. A second entry with the same code
                    # would be a second agent, and the service would have
                    # them displace each other in a loop.
                    await self.async_set_unique_id(_fingerprint(code))
                    self._abort_if_unique_id_configured()
                    error = await _validate(self.hass, code)
                    if error:
                        errors["base"] = error
                    else:
                        # WHOSE ACCESS THIS IS. Captured HERE, from the
                        # flow's context, because that is the only place it
                        # exists: `ConfigEntry` carries no context, so a
                        # setup that tried to read it later would find
                        # nothing. The token minted at setup belongs to the
                        # person who typed the code, and to nobody else.
                        return self.async_create_entry(
                            title="ElectriFix Connect",
                            data={CONF_JOB_CODE: code,
                                  CONF_USER_ID:
                                      self.context.get("user_id") or ""},
                        )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    # A re-auth is what a rejected code becomes: the entry stays, the
    # customer pastes the current code from their job page.
    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return await self.async_step_user(user_input)


#: The alphabet a job code can contain. The service issues
#: `secrets.token_urlsafe(32)`, which is base64url: letters, digits, `-`
#: and `_`, and nothing else. Pinned here because `clean_code` strips
#: surrounding quotes, and that is only safe while a quote cannot be part of
#: a real code -- a dependency on the server's choice that was previously
#: written nowhere and tested by nothing.
CODE_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def clean_code(raw: Any) -> str:
    """A pasted job code, tidied -- or "" if it cannot be one.

    A copy button sometimes brings surrounding quotes or a trailing newline
    with it, and refusing a code that is actually right over a stray quote
    is a bad experience for someone who has already paid. Stripping them is
    safe ONLY because the code alphabet excludes quotes; `CODE_ALPHABET`
    says so and a test pins it against the service's own generator.

    Anything still outside the alphabet after tidying is rejected here
    rather than dialled: it cannot be a code the service issued.
    """
    code = str(raw or "").strip().strip('"').strip("'").strip()
    if not code or any(ch not in CODE_ALPHABET for ch in code):
        return ""
    return code


def _fingerprint(code: str) -> str:
    """A stable id for this code that is NOT the code.

    The unique id is stored in `.storage` in the clear and shown in
    diagnostics, so it must not be the bearer credential itself.
    """
    import hashlib

    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:32]


async def _validate(hass: Any, code: str) -> str | None:
    """`None` if the code works, else the translation key for the error.

    A `check`, NOT A HELLO (1.1.2). THE FIRST-CONNECTION FAULT, in
    production on 2026-09-16 and again on 09-17: this function used to send
    a real `hello`, which made the SERVICE register this dialog as the
    job's agent. It then closed its socket -- a close that through a
    Cloudflare tunnel the service may not see for a long time -- while the
    entry's real agent dialled in behind it. One of the two sockets got
    told `replaced`, the integration treated that as terminal, and the
    server was left holding a socket with nothing reading it. The customer
    watched their job sit at "waiting" until a
    `homeassistant.reload_config_entry` fixed it instantly.

    `check` verifies the code EXACTLY as a hello does -- the same hello
    budget, the same constant-time hash compare, the same 4401/4429/4503
    closes -- and registers nothing. It also answers in one round trip
    instead of eight seconds of deliberate silence, so Submit returns as
    fast as the customer's uplink allows.

    WHEN THE LEGACY FALLBACK RUNS, AND WHY NOT ON A 4401
    -----------------------------------------------------
    An earlier build fell back to the hello path on ANY 4401, reasoning
    that a server predating `check` closes an unknown first frame with the
    same code it uses for a wrong job code, so the two are
    indistinguishable. True -- but they are not equally likely and the
    fallback is not free (review L2). Both dials spend the per-IP
    `HelloBudget` (10 a minute), so a customer mistyping their code got
    five attempts instead of ten, and the sixth told them "too many
    attempts" rather than "that code is wrong" -- the less useful sentence,
    on exactly the path where the useful one matters.

    The overwhelmingly common meaning of a 4401 is a wrong code, so that is
    what it is taken to mean, in one dial. The fallback now needs EVIDENCE
    that the far end does not understand `check`: either a close whose code
    is none this protocol defines, or a socket that stays OPEN and says
    nothing -- a current server always answers a `check` with `check_ok` or
    a close, so silence on a live socket is not something it does.
    """
    url = os.environ.get(ENV_RELAY_URL) or DEFAULT_RELAY_URL
    #: Set when the far end proved it does not speak `check`. The legacy
    #: dial then happens OUTSIDE the block below (review L3): dialling it
    #: in there held the check socket open for the whole second dial, so
    #: two sockets existed at once during validation -- which is the exact
    #: shape this change set exists to remove.
    legacy_needed = False
    session = aiohttp.ClientSession()
    try:
        async with session.ws_connect(url, heartbeat=None) as ws:
            await ws.send_str(json.dumps({
                "type": "check",
                "job_code": code,
                "integration_version": INTEGRATION_VERSION,
            }))
            try:
                msg = await asyncio.wait_for(ws.receive(), _VALIDATE_SECONDS)
            except asyncio.TimeoutError:
                # NOTHING AT ALL, on a socket that is still open. A current
                # server answers a `check` either way, so this is a far end
                # that read an unknown frame and simply kept reading --
                # which is what a server predating `check` does. The code
                # may be perfectly good, so the hello path decides it.
                legacy_needed = not ws.closed
                if not legacy_needed:
                    return _close_error(ws.close_code)
                msg = None
            if msg is not None:
                if msg.type is aiohttp.WSMsgType.TEXT:
                    try:
                        frame = json.loads(msg.data)
                    except (ValueError, TypeError):
                        frame = {}
                    if (isinstance(frame, dict)
                            and frame.get("type") == "check_ok"):
                        return None
                    # Some other frame: the socket was accepted and the far
                    # end is talking to us, which on any server means the
                    # code got past the hello check.
                    return None
                elif msg.type in (aiohttp.WSMsgType.CLOSE,
                                  aiohttp.WSMsgType.CLOSED,
                                  aiohttp.WSMsgType.CLOSING):
                    # A CLOSE THIS PROTOCOL DEFINES is an answer, including
                    # 4401 -- see the docstring. Only a code we do not
                    # recognise suggests a far end that does not understand
                    # the frame it was sent.
                    if ws.close_code in (CLOSE_BAD_CODE, CLOSE_RATE_LIMITED,
                                         CLOSE_RELAY_OFF):
                        return _close_error(ws.close_code)
                    legacy_needed = True
                elif msg.type is aiohttp.WSMsgType.ERROR:
                    return "cannot_connect"
                else:
                    return None
    except aiohttp.ClientError as exc:
        _LOG.debug("ElectriFix Connect validation failed: %s", exc)
        return "cannot_connect"
    except asyncio.TimeoutError:
        return "cannot_connect"
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("ElectriFix Connect validation error: %s", exc)
        return "unknown"
    finally:
        await session.close()

    # OUTSIDE the block and after `session.close()`: one socket at a time.
    if legacy_needed:
        _LOG.debug(
            "ElectriFix Connect: the relay did not understand `check`; "
            "falling back to the 1.1.1 validation"
        )
        return await _validate_legacy(url, code)
    return None


async def _validate_legacy(url: str, code: str) -> str | None:
    """The 1.1.1 validation, kept ONLY for a server that predates `check`.

    DOCUMENTED DEGRADATION. This sends a real `hello`, so an older service
    registers this socket as the job's agent and the first-connection race
    is back for exactly as long as that deployment lives. It is still the
    right answer here: the alternative is telling a customer whose code is
    fine that it is wrong, and the race is recoverable now that `replaced`
    is no longer terminal in `relay.py`.
    """
    session = aiohttp.ClientSession()
    try:
        async with session.ws_connect(url, heartbeat=None) as ws:
            await ws.send_str(json.dumps({
                "type": "hello",
                "job_code": code,
                "ha_version": "",
                "install_type": "",
                "integration_version": INTEGRATION_VERSION,
            }))
            # Wait for an objection. Silence is success: an older service
            # does not ACK a hello, it simply keeps reading.
            try:
                msg = await asyncio.wait_for(ws.receive(), _VALIDATE_SECONDS)
            except asyncio.TimeoutError:
                return None
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.CLOSING):
                return _close_error(ws.close_code)
            if msg.type is aiohttp.WSMsgType.ERROR:
                return "cannot_connect"
            return None
    except aiohttp.ClientError as exc:
        _LOG.debug("ElectriFix Connect validation failed: %s", exc)
        return "cannot_connect"
    except asyncio.TimeoutError:
        return "cannot_connect"
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("ElectriFix Connect validation error: %s", exc)
        return "unknown"
    finally:
        await session.close()


def _close_error(code: int | None) -> str:
    if code == CLOSE_BAD_CODE:
        return "bad_code"
    if code == CLOSE_RATE_LIMITED:
        return "rate_limited"
    if code == CLOSE_RELAY_OFF:
        return "relay_off"
    return "cannot_connect"
