"""Constants for ElectriFix Connect, including the local allow-list.

WHY THE ALLOW-LIST IS COPIED HERE RATHER THAN FETCHED
-----------------------------------------------------
The service checks `RELAY_ALLOWED` before it puts a frame on the wire. This
file is the SECOND, INDEPENDENT copy of the same rule, checked again inside
Home Assistant before anything touches the customer's core.

Two copies is the point. A credential that can only ever be used for what
is on this list is safe in a way that "the far end promised to be careful"
is not: if the service is ever wrong -- a bug, a bad deploy, someone else's
frame on a confused socket -- this end still refuses. Defence in depth means
the check must not depend on the thing it is defending against, so it is
NOT fetched at runtime from the service and NOT negotiated in the hello.

Drift between the two is caught by `tests/test_integration_files.py` in the
service repo, which imports both and asserts they are equal. The service's
`haclient.relay.RELAY_ALLOWED` is the single source of truth; this is its
mirror, and the test is what keeps the mirror honest.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Final

DOMAIN: Final = "electrifix_connect"

#: Bumped with the integration; sent in the hello so the service's logs and
#: the job record say which build a customer is on when something is odd.
INTEGRATION_VERSION: Final = "1.1.3"

#: Where the agent dials. Overridable by an environment variable ONLY, and
#: not by anything a frame can say: a relay that could redirect its own
#: agent to another host would be a redirect of the customer's credential.
DEFAULT_RELAY_URL: Final = "wss://fix.electrifixperth.com.au/relay/agent"
ENV_RELAY_URL: Final = "EF_RELAY_URL"

CONF_JOB_CODE: Final = "job_code"

#: The Home Assistant user whose access this integration mints a token for.
#: Recorded by the config flow from its own context -- a `ConfigEntry` has
#: no context of its own, so if it is not captured at creation there is no
#: later opportunity to learn who added this.
CONF_USER_ID: Final = "user_id"

#: The name the minted refresh token carries. The customer sees this in
#: Settings -> People -> (their user) -> Refresh tokens, so it says what it
#: is in words rather than in an id.
TOKEN_CLIENT_NAME: Final = "ElectriFix Connect"

#: How long the minted access token stays valid without being refreshed.
#: Home Assistant's default for a long-lived token is TEN YEARS, which would
#: make the revoke the only thing standing between a finished job and a
#: decade-long credential. A job runs for days; 30 days is generous and
#: still bounded.
TOKEN_LIFETIME: Final = timedelta(days=30)

#: Backoff: 5 s, doubling, capped at 10 minutes.
#:
#: ONLY A SUCCESSFUL HELLO RESETS THIS. An earlier build reset the delay
#: whenever the socket closed cleanly -- and a server-side `ws.close(4503)`
#: or `ws.close(4429)` IS a clean close, so the two codes that exist
#: specifically to ask the agent to slow down were the two that guaranteed
#: it would not. With the relay switched off (the documented default) every
#: install became a ~12-attempts-per-minute redial that the server's own
#: rate limiter was structurally unable to slow, because the rate-limit
#: close reset the very timer meant to respond to it.
BACKOFF_START: Final = 5.0
BACKOFF_MAX: Final = 600.0
BACKOFF_FACTOR: Final = 2.0

#: The floor after a 4429. The server has just said this IP's hello budget is
#: spent for a full window, so coming back inside that window can only earn
#: another 4429. Starting at 30 s means the next attempt lands after the
#: window has actually turned over.
BACKOFF_AFTER_RATE_LIMIT: Final = 30.0

#: How long a socket must stay up before it counts as "a session that did
#: work" for the purpose of resetting the backoff. Below this, a connection
#: that was accepted and immediately closed is treated as a failure, which
#: is what it is.
BACKOFF_RESET_AFTER: Final = 30.0

#: Jitter fraction applied to every wait. Without it, every integration
#: knocked off by one service restart comes back in the same second.
BACKOFF_JITTER: Final = 0.25

#: How long a forwarded request may take against the local core before the
#: agent answers with a 504 of its own. Below the service's 60 s so the
#: customer's own side is what times out, with a message that names it.
LOCAL_REQUEST_TIMEOUT: Final = 55.0

#: Close codes the service uses. Each means "stop doing what you are doing"
#: in a different way, and the agent must tell them apart -- telling a
#: customer their code is wrong when the real answer is "not enabled here"
#: sends them hunting for a code that is perfectly fine.
CLOSE_BAD_CODE: Final = 4401
CLOSE_RATE_LIMITED: Final = 4429
CLOSE_RELAY_OFF: Final = 4503

#: The message the config entry carries once the service says `bye`.
FINISHED_MESSAGE: Final = "Job finished — you can remove this integration"

#: Shown on the diagnostic sensor when the service has refused the job code.
#: A rejected agent is NOT reconnecting, and must not claim to be.
REJECTED_MESSAGE: Final = "Code rejected — re-enter your job code"

# --------------------------------------------- being replaced (1.1.2)
#
# THE FIRST-CONNECTION FAULT, in production on 2026-09-16 and again on
# 09-17. Two sockets existed for one job -- the config flow's validation
# socket and the entry's real agent -- and whichever registered second
# displaced the first. 1.1.1 treated `replaced` as terminal ("the newer
# socket is ours too"), so the integration stopped for good on the socket
# the SERVER was actually holding. The stale socket was then dropped for
# silence after 45 s and nothing ever redialled: the customer's job sat
# "waiting" until a `homeassistant.reload_config_entry` fixed it in
# seconds.
#
# 1.1.2 stops the DISPLACED SOCKET and redials, and the wait is what makes
# that safe.

#: How long to wait before redialling after a `replaced`.
#:
#: LONGER THAN THE SERVER'S 45 s LIVENESS DROP, on purpose, and that is the
#: whole design. By the time we come back the newer socket is in one of two
#: states:
#:
#:   * alive and answering -- a genuine second connection. The server
#:     replaces US this time, we back off again, and after
#:     `MAX_REPLACEMENTS` we stop and say so rather than oscillate.
#:   * dead and already dropped -- the stale-socket case that caused the
#:     fault. Our redial is then the thing that restores service, with no
#:     reload and nobody watching.
#:
#: Redialling sooner would land inside the server's liveness window, where
#: a stale socket is still registered, and could only earn another
#: `replaced`.
REPLACED_BACKOFF_S: Final = 45.0

#: How many CONSECUTIVE replacements before the integration stops trying.
#: Two installs genuinely sharing one job code would displace each other
#: forever; three attempts is enough to ride out the racing-socket case and
#: few enough that a real collision stops quickly and visibly. A session
#: that does real work clears the count.
MAX_REPLACEMENTS: Final = 3

#: Shown on the diagnostic sensor once the replacements are spent. Names
#: the actual situation -- another instance on this job code -- rather than
#: claiming to be reconnecting, which is what a stopped agent must never do.
REPLACED_MESSAGE: Final = (
    "Another ElectriFix Connect instance is using this job code"
)

# ------------------------------------------------------------- the limits
#
# Bounds on what a misbehaving or compromised SERVER can make this Home
# Assistant do. The allow-list says what operations are permitted; these say
# how many and how large. Both are needed: 50 000 `ws_open` frames are every
# one of them a permitted operation, and they would still take a Raspberry
# Pi out on file descriptors alone.

#: Largest relay frame accepted. 1 MiB is far above any real control frame
#: (the biggest is a `http` frame carrying an automation document) and far
#: below what it takes to exhaust a small box. A backup is never carried
#: INBOUND -- it travels agent -> service, where this limit does not apply.
MAX_MSG_SIZE: Final = 1024 * 1024

#: The LOCAL socket to this Home Assistant's own /api/websocket is a different
#: animal: its replies are the registry and state dumps the service asks for,
#: and on a real house those pass 1 MiB easily (a 950-entity install closed
#: the session with 1009 "message too big" on 2026-09-17, which made every
#: later command on that session wait out its timeout). 16 MiB matches what
#: the Home Assistant frontend itself accepts.
LOCAL_MAX_MSG_SIZE: Final = 16 * 1024 * 1024

#: How many Home Assistant websocket sessions the service may hold open
#: through us. ONE: the sweep and the planner open a session, use it and
#: close it, so a second concurrent one is a bug or an attack. Opening a new
#: one closes the old rather than refusing, so a server that lost track of a
#: session can still make progress.
MAX_WS_SESSIONS: Final = 1

#: How many forwarded requests may be in flight at once. A sweep pipelines a
#: handful; 8 leaves headroom without letting an unbounded fan-out of frames
#: become an unbounded fan-out of loopback requests.
MAX_INFLIGHT: Final = 8

# --------------------------------------------------------- the allow-list
#
# A VERBATIM copy of `haclient.relay.RELAY_ALLOWED`. Keep the shape as well
# as the contents identical: the parity test compares the structures, and a
# reshaping here that happened to hold the same strings would still be a
# divergence from the thing being mirrored.

#: GET anywhere under /api/ -- reading is the job.
GET_PREFIXES: Final[tuple[str, ...]] = ("/api/",)

#: The allow-listed service calls, in `domain.service` form.
SERVICES: Final[frozenset[str]] = frozenset({
    "automation.turn_off",
    "automation.turn_on",
    "backup.create",
    "hassio.backup_full",
    "homeassistant.reload_config_entry",
    "recorder.purge",
})

#: Exact POST paths: the service calls above, as paths. EXACT and never a
#: prefix -- a prefix under /api/services/ would admit every service in the
#: domain, which for `automation` alone would include `automation.trigger`.
POST_PATHS: Final[frozenset[str]] = frozenset(
    "/api/services/" + key.replace(".", "/") for key in SERVICES
)

#: POST prefixes: the automation config documents, and nothing else.
POST_PREFIXES: Final[tuple[str, ...]] = ("/api/config/automation/config/",)

#: DELETE prefixes: the same documents, so a created automation can be
#: rolled back. A bare prefix names no document and is refused.
DELETE_PREFIXES: Final[tuple[str, ...]] = ("/api/config/automation/config/",)

#: WebSocket commands. The read-only registry/system commands the sweep
#: needs, plus the writes the executor makes over the socket.
#:
#: The three `lovelace/*` entries are the whole of `dashboard_edit` (service
#: v1.1.0): a storage-mode dashboard can ONLY be read and saved through
#: these commands, never through a file. `lovelace/resources*` is
#: deliberately absent -- that edits the JavaScript every dashboard loads,
#: which is a far larger blast radius than a card.
WS_COMMANDS: Final[frozenset[str]] = frozenset({
    "auth/current_user",
    "cloud/status",
    "config/area_registry/list",
    "config/auth/list",
    "config/category_registry/list",
    "config/device_registry/list",
    "config/entity_registry/list",
    "config/entity_registry/list_for_display",
    "config/entity_registry/remove",
    "config/floor_registry/list",
    "config/label_registry/list",
    "config_entries/get",
    "energy/info",
    "get_config",
    "get_panels",
    "get_services",
    "get_states",
    "integration/descriptions",
    "logger/log_info",
    "lovelace/config",
    "lovelace/config/save",
    "lovelace/dashboards/list",
    "manifest/list",
    "recorder/info",
    "repairs/list_issues",
    "system_health/info",
    "system_log/list",
})

#: The same mapping the service exports, so the parity test can compare one
#: object against one object rather than field by field.
RELAY_ALLOWED: Final[dict[str, Any]] = {
    "get_prefixes": GET_PREFIXES,
    "post_paths": POST_PATHS,
    "post_prefixes": POST_PREFIXES,
    "delete_prefixes": DELETE_PREFIXES,
    "services": SERVICES,
    "ws_commands": WS_COMMANDS,
}

#: Services this integration will not carry under ANY circumstances, waiver
#: or not (spec §8.1). Mirrors `haclient.safety.guard.FORBIDDEN_CALL_DOMAINS`:
#: locks, alarms, cameras, covers and similar are CONFIGURED by this service,
#: never operated by it. A second gate behind `POST_PATHS`, so that widening
#: the service allow-list one day cannot quietly widen this too. The parity
#: test asserts it equals the service's own set.
FORBIDDEN_SERVICE_DOMAINS: Final[frozenset[str]] = frozenset({
    "lock",
    "alarm_control_panel",
    "camera",
    "cover",
    "valve",
    "water_heater",
})
