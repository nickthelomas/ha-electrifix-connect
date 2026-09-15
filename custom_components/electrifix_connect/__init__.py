"""ElectriFix Connect: set up the agent, and mint its own credential.

THE CREDENTIAL, AND WHY THE CUSTOMER NEVER MAKES ONE
----------------------------------------------------
Every other way of giving a service access to Home Assistant asks the
customer to go to their profile, create a long-lived access token, and paste
a 180-character secret into a web page -- which is the step most people get
wrong, and the one that leaves a working credential behind afterwards if
nobody remembers to delete it.

A custom integration runs INSIDE Home Assistant, so it can do what an add-on
cannot: mint its own. `async_create_refresh_token` with
`token_type=LONG_LIVED_ACCESS_TOKEN` gives a token owned by the user who
added the integration, named "ElectriFix Connect" in their profile so they
can see and revoke it, and REVOKED BY US on unload, on removal, and the
moment the service says the job is over. The customer creates nothing and
has nothing to clean up.

The token is then used for exactly one thing: an `Authorization` header on a
loopback request to this same Home Assistant. It is never put in a frame,
never logged, and never sent to ElectriFix -- which is why the service's
copy of this job holds only a hashed job code and no Home Assistant
credential at all.
"""
from __future__ import annotations

import inspect
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_JOB_CODE,
    CONF_USER_ID,
    DOMAIN,
    FINISHED_MESSAGE,
    INTEGRATION_VERSION,
    TOKEN_CLIENT_NAME,
    TOKEN_LIFETIME,
)
from .relay import RelayAgent

_LOG = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR]

#: Where the minted refresh token's id is remembered, so it can be revoked
#: on a later run of Home Assistant -- including one where setup never got
#: far enough to build an agent.
DATA_TOKEN_ID = "token_id"


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """YAML is not a way to configure this. The job code belongs to one
    job and is shown once; a copy of it in `configuration.yaml` would
    outlive the job it belongs to."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    if _is_finished(entry):
        # THE JOB IS OVER, and setting up again would mint a fresh token and
        # redial a dead job. Found on the live throwaway: renaming the entry
        # to "Job finished" is itself an entry update, the update listener
        # reloaded on it, and the reload minted token number two seconds
        # after token number one had been revoked -- a credential created by
        # the very act of saying the job had ended.
        #
        # So a finished entry sets up as an inert one: no token, no socket,
        # nothing to revoke. It exists only so the customer can see the
        # message and remove it.
        _LOG.debug("ElectriFix Connect: entry is finished; not reconnecting")
        # BELT AND BRACES. `_finish` revokes on the `bye` itself, but that
        # runs in a task; if Home Assistant is hard-killed between the two,
        # the token survives -- and with no expiry that is a very long time.
        # Revoking here means every subsequent start of a finished entry
        # sweeps up anything left behind.
        await _revoke_token(hass, entry)
        await _revoke_strays(hass, entry)
        return True

    user = await _entry_user(hass, entry)
    if user is None:
        # The user who added it is gone (deleted, or an entry restored from
        # a backup onto another install). A re-auth is the honest answer:
        # the token must belong to somebody, and we must not pick.
        raise ConfigEntryAuthFailed(
            "The Home Assistant user that added ElectriFix Connect no longer "
            "exists. Remove and re-add the integration."
        )

    token, token_id = await _mint_token(hass, entry, user)

    agent = RelayAgent(
        hass,
        entry.data[CONF_JOB_CODE],
        token=token,
        ha_version=_ha_version(hass),
        install_type=await _install_type(hass),
        on_state=lambda: _publish_state(hass, entry),
    )
    hass.data[DOMAIN][entry.entry_id] = agent
    await agent.async_start()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _LOG.info(
        "ElectriFix Connect %s started (token %s, revoked when this job ends)",
        INTEGRATION_VERSION, token_id[:8] if token_id else "?",
    )
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Stop the agent and REVOKE THE TOKEN.

    Revoking here rather than only on removal is deliberate: an integration
    that is merely disabled must not leave a working credential behind, and
    a fresh one is minted the next time it is set up. There is nothing in
    the token worth preserving -- it is a means, not a record.
    """
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    agent: RelayAgent | None = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if agent is not None:
        await agent.async_stop()
    await _revoke_token(hass, entry)
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Belt and braces: removal after a failed setup never reached unload."""
    await _revoke_token(hass, entry)


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload on a real change -- but never on our own "finished" rename.

    `async_update_entry` fires this listener, and `_finish` calls
    `async_update_entry`, so without this guard the end of a job is also the
    start of a reload. `async_setup_entry` refuses a finished entry as well;
    two guards, because this one is about not doing pointless work and that
    one is about never minting a credential for a job that has ended.
    """
    if _is_finished(entry):
        return
    await hass.config_entries.async_reload(entry.entry_id)


def _is_finished(entry: ConfigEntry) -> bool:
    """Has this entry already been told its job is over?

    Read from the TITLE, which is the thing `_finish` sets and the thing
    that survives a Home Assistant restart -- so a box rebooted a week after
    a job finished still does not redial it.
    """
    return str(entry.title or "").startswith(FINISHED_MESSAGE)


# ------------------------------------------------------------ the token

async def _maybe_await(value: Any) -> Any:
    """Await `value` if it is awaitable, else return it.

    `hass.auth`'s API is inconsistent about this and has changed across
    versions: `async_create_refresh_token` and `async_get_users` are
    coroutines, while `async_remove_refresh_token`, `async_get_refresh_token`
    and `async_create_access_token` are plain synchronous methods that merely
    carry the `async_` prefix (the HA convention for "must be called from the
    event loop"). Awaiting one of the sync ones raises
    `TypeError: 'NoneType' object can't be awaited` -- found exactly that way
    on HA 2026.8.2 -- and not awaiting a coroutine silently does nothing,
    which for a REVOKE would mean a credential quietly outliving the job.

    Handling both here rather than hard-coding today's shape keeps the
    integration working across the whole range of versions it will be
    installed on, which is the entire point of shipping an integration
    rather than an add-on.
    """
    if inspect.isawaitable(value):
        return await value
    return value

async def _entry_user(hass: HomeAssistant, entry: ConfigEntry) -> Any:
    """The user this entry's credential belongs to.

    `context["user_id"]` on the flow that created the entry -- which is the
    person who typed the job code, and therefore the person whose access
    this integration should have and no more.
    """
    user_id = entry.data.get(CONF_USER_ID)
    if user_id:
        user = await hass.auth.async_get_user(user_id)
        if user is not None and user.is_active:
            return user
    # FALLBACK: the owner. Reached when the entry was created by something
    # with no user attached -- a flow started from a script, or an entry
    # restored from a backup whose user did not come with it. The owner is
    # the only defensible choice: it is the account that can grant this
    # access anyway, and picking any other user would be this integration
    # deciding whose house it gets to see.
    for candidate in await hass.auth.async_get_users():
        if candidate.is_owner and candidate.is_active \
                and not candidate.system_generated:
            return candidate
    return None


async def _mint_token(
    hass: HomeAssistant, entry: ConfigEntry, user: Any
) -> tuple[str, str]:
    """A long-lived access token for `user`, and the refresh token's id.

    An EXISTING ElectriFix Connect token for this user is revoked first. A
    reload that minted a second would leave the first behind with nothing
    tracking it, and "how many of these are there" is a question a customer
    looking at their profile should never have to ask.

    THIS IS ALSO THE RE-MINT PATH. A successful re-auth calls
    `async_update_reload_and_abort`, which reloads the entry, which runs
    setup again and lands here -- so entering a new job code revokes the
    credential minted for the old one and issues a fresh one, without any
    separate re-mint branch to keep in step with this.
    """
    for existing in list(user.refresh_tokens.values()):
        if existing.client_name == TOKEN_CLIENT_NAME:
            await _maybe_await(hass.auth.async_remove_refresh_token(existing))

    refresh_token = await hass.auth.async_create_refresh_token(
        user,
        client_name=TOKEN_CLIENT_NAME,
        client_icon="mdi:home-lightning-bolt",
        token_type="long_lived_access_token",
        # AN EXPIRY, because otherwise the revoke is the single point of
        # failure for the whole "access ends with the job" promise and HA's
        # default long-lived token lasts TEN YEARS. A job runs for days, so
        # 30 days is generous; if every revoke path somehow failed, the
        # credential still dies by itself. Verified against the installed
        # HA's `async_create_refresh_token` signature.
        access_token_expiration=TOKEN_LIFETIME,
    )
    access_token = hass.auth.async_create_access_token(refresh_token)
    hass.config_entries.async_update_entry(
        entry, data={**entry.data,
                     DATA_TOKEN_ID: refresh_token.id,
                     CONF_USER_ID: user.id},
    )
    return access_token, refresh_token.id


async def _revoke_strays(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove any leftover ElectriFix Connect token for this entry's user.

    The id in `entry.data` is the token we know about; this catches one we
    do not -- minted by a build that crashed before recording it, or left by
    a Home Assistant killed between `bye` and the revoke. Never raises.
    """
    try:
        user = await _entry_user(hass, entry)
        if user is None:
            return
        for existing in list(user.refresh_tokens.values()):
            if existing.client_name == TOKEN_CLIENT_NAME:
                await _maybe_await(
                    hass.auth.async_remove_refresh_token(existing)
                )
                _LOG.info("ElectriFix Connect: removed a stray access token")
    except Exception:  # noqa: BLE001 - teardown must complete regardless
        _LOG.debug("could not sweep stray tokens", exc_info=True)


async def _revoke_token(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Take the credential back. Never raises -- it runs on teardown."""
    token_id = entry.data.get(DATA_TOKEN_ID)
    if not token_id:
        return
    try:
        refresh_token = await _maybe_await(
            hass.auth.async_get_refresh_token(token_id)
        )
        if refresh_token is not None:
            await _maybe_await(
                hass.auth.async_remove_refresh_token(refresh_token)
            )
            _LOG.info("ElectriFix Connect: revoked its access token")
    except Exception:  # noqa: BLE001 - teardown must complete regardless
        _LOG.debug("could not revoke the token", exc_info=True)


# ------------------------------------------------------------- the state

def _publish_state(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Tell the diagnostics entity something changed.

    A dispatcher signal rather than a direct call: the entity may not exist
    yet (the agent connects before the platform finishes setting up), and a
    signal nobody is listening to is a no-op rather than a crash.
    """
    from homeassistant.helpers.dispatcher import async_dispatcher_send

    async_dispatcher_send(hass, f"{DOMAIN}_state_{entry.entry_id}")

    agent: RelayAgent | None = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if agent is None:
        return
    if agent.finished:
        # The job is over. Say so in the place the customer will actually
        # look -- the integrations page -- rather than only in the log.
        hass.async_create_task(_finish(hass, entry, agent))
    elif agent.rejected:
        # The code was refused. Ask for a new one, and take the credential
        # back now rather than leaving it live on a job the service has
        # already disowned.
        hass.async_create_task(_reject(hass, entry, agent))


async def _reject(
    hass: HomeAssistant, entry: ConfigEntry, agent: RelayAgent
) -> None:
    """A 4401: stop, revoke, and put a re-auth card on the Integrations page.

    Same ORDER as `_finish` and for the same reason -- the in-flight
    requests are cancelled and the credential is taken back before anything
    that might cancel this coroutine. `async_start_reauth` is what turns a
    dead entry into one the customer can fix without deleting it.
    """
    if agent.reauth_started:
        return
    agent.reauth_started = True
    await agent.async_stop()
    await _revoke_token(hass, entry)
    entry.async_start_reauth(hass)


async def _finish(
    hass: HomeAssistant, entry: ConfigEntry, agent: RelayAgent
) -> None:
    """`bye`: revoke now, and leave the entry saying it is done.

    The token goes IMMEDIATELY rather than when the customer gets round to
    removing the integration: the job is over, so the access should be too,
    and an entry that lingers for a week must not linger with a credential.

    ORDER MATTERS, and it was found the hard way on the live throwaway.
    This coroutine is reached from the agent's own read loop (`bye` frame ->
    `_on_bye` -> the state listener), and `agent.async_stop()` CANCELS that
    read loop's task. Awaiting the stop first therefore cancelled this
    coroutine partway through, and the revoke below never ran: the socket
    closed, the entry was never renamed, and the token the integration
    minted stayed live in the customer's Home Assistant -- a credential
    outliving the job it belonged to, which is the exact failure this whole
    design exists to prevent.

    So THE CREDENTIAL GOES FIRST, while this coroutine is certain to be
    running, and the socket is stopped afterwards. If anything cancels this
    after the revoke, the worst case is a socket that closes a moment later
    on its own -- which it does anyway, because the service has finished
    with it.
    """
    if entry.title.startswith(FINISHED_MESSAGE):
        return
    await _revoke_token(hass, entry)
    hass.config_entries.async_update_entry(
        entry,
        title=FINISHED_MESSAGE,
        data={k: v for k, v in entry.data.items() if k != DATA_TOKEN_ID},
    )
    await agent.async_stop()


# ------------------------------------------------------------- HA facts

def _ha_version(hass: HomeAssistant) -> str:
    try:
        from homeassistant.const import __version__

        return str(__version__)
    except Exception:  # noqa: BLE001
        return ""


async def _install_type(hass: HomeAssistant) -> str:
    """OS / Supervised / Container / Core, from the inside.

    Strictly better evidence than the service's probe, which has to guess
    from `/api/config` -- and it is why the service records what the
    integration says rather than what it detected.
    """
    try:
        from homeassistant.helpers.system_info import async_get_system_info

        info = await async_get_system_info(hass)
        return str(info.get("installation_type", "")).replace(
            "Home Assistant ", ""
        ).strip().lower() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"
