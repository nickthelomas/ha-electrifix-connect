"""The agent: one outbound WebSocket, and a guard in front of it.

WHAT THIS IS
------------
Home Assistant dials OUT to ElectriFix and holds one WebSocket open. Nothing
is opened up at the customer's end, no port is forwarded, no DNS record
exists and no tunnel is created -- so there is nothing to tear down, and
access ends when the socket closes, which is a thing that happens by itself.

Over that socket the service asks for exactly what a sweep and a repair
need: reads from this Home Assistant's own API, and a short list of writes.
Each request arrives as a JSON frame, is CHECKED AGAINST THIS FILE'S OWN
ALLOW-LIST, and is then made against `http://127.0.0.1:<api port>` with a
token this integration minted for itself.

THE TOKEN NEVER LEAVES THIS PROCESS
-----------------------------------
`__init__.py` mints a long-lived access token and hands it here. It is put
in an `Authorization` header on a loopback request and nowhere else: it is
never sent in a frame, never logged, and never given to the service. The
service's end of this relay has no Home Assistant token at all, which is why
the job's vault holds only a hashed job code.

DENY BY DEFAULT, HERE, AGAIN
----------------------------
The service checks its own `RELAY_ALLOWED` before writing a frame. This end
checks `const.RELAY_ALLOWED` before touching the core. The two are asserted
equal by a test in the service repo. Checking twice is the point: a request
outside the list is refused HERE with a 403 and logged in Home Assistant, so
a wrong or compromised service end still cannot reach past this file.

WHY NOT AIOHTTP'S `ws_connect` DIRECTLY ON A SHARED SESSION
------------------------------------------------------------
The agent owns its socket and its reconnect loop, and a shared session that
HA closes at shutdown would take the socket with it mid-frame. It uses HA's
shared client session for the LOOPBACK requests (cheap, pooled, correct at
shutdown) and its own session for the long-lived outbound socket.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import time
from typing import Any, Callable
from urllib.parse import unquote

import aiohttp

from .const import (
    BACKOFF_AFTER_RATE_LIMIT,
    BACKOFF_FACTOR,
    BACKOFF_JITTER,
    BACKOFF_MAX,
    BACKOFF_RESET_AFTER,
    BACKOFF_START,
    CLOSE_BAD_CODE,
    CLOSE_RATE_LIMITED,
    CLOSE_RELAY_OFF,
    DEFAULT_RELAY_URL,
    ENV_RELAY_URL,
    FINISHED_MESSAGE,
    FORBIDDEN_SERVICE_DOMAINS,
    INTEGRATION_VERSION,
    LOCAL_REQUEST_TIMEOUT,
    MAX_INFLIGHT,
    MAX_MSG_SIZE,
    MAX_REPLACEMENTS,
    MAX_WS_SESSIONS,
    RELAY_ALLOWED,
    REPLACED_BACKOFF_S,
    REPLACED_MESSAGE,
)

_LOG = logging.getLogger(__name__)


class NotAllowed(Exception):
    """This request is not on the allow-list. Refused before it is made."""


# ------------------------------------------------------------- the backoff

def next_delay(
    delay: float, close_code: int | None, served_for: float
) -> float:
    """How long to wait before redialling. A PURE FUNCTION, on purpose.

    The reconnect curve is the one piece of this integration that is felt by
    somebody other than its owner -- every install that cannot connect is
    load on the service -- and it is also the piece hardest to observe from
    outside. Making it a pure function of (current delay, why the socket
    closed, how long it was up) means the curve can be asserted directly,
    which is how CRITICAL-1 would have been caught.

    The rules, in order:

    * **4429** -- the server has said this IP's hello budget is spent for a
      full window. Coming back inside that window earns another 4429, so the
      delay jumps to at least `BACKOFF_AFTER_RATE_LIMIT` and keeps growing.
    * **4503** -- the relay is switched off at the far end. The code is
      fine; there is simply nothing to connect to, possibly for days. Keep
      growing.
    * **a session that did real work** (`served_for >= BACKOFF_RESET_AFTER`)
      -- a genuine blip after a working connection. Start again from the
      bottom, which is what makes a brief network drop recover quickly.
    * **anything else** -- a refused TCP connection, a TLS error, or a
      socket accepted and dropped immediately. Keep growing.

    A server-initiated close NEVER resets, however long the socket was up:
    4429 and 4503 mean "stop asking", and a long-lived socket that ends in
    one of them is still an instruction to slow down.
    """
    if close_code == CLOSE_RATE_LIMITED:
        return min(BACKOFF_MAX, max(delay, BACKOFF_AFTER_RATE_LIMIT)
                   * BACKOFF_FACTOR)
    if close_code == CLOSE_RELAY_OFF:
        return min(BACKOFF_MAX, delay * BACKOFF_FACTOR)
    if served_for >= BACKOFF_RESET_AFTER:
        return BACKOFF_START
    return min(BACKOFF_MAX, delay * BACKOFF_FACTOR)


# ------------------------------------------------------------- the guard

def decoded_path(path: str) -> str:
    """The path with the query stripped and percent-encoding resolved.

    PERCENT-DECODING MATTERS because `%2e%2e` is `..` to every server that
    will eventually route this, and a `".." in p` test on the RAW path lets
    it straight through. Verified before the fix: both this guard and the
    service's allowed `GET /api/%2e%2e/secrets`.

    Decoded ONCE, not to a fixed point: a single decode is what a normal
    server does, so matching that is matching reality. Double-encoding
    (`%252e`) decodes to the literal text `%2e`, which contains no `..` and
    is not a traversal to anyone downstream either.
    """
    p = path or ""
    if "?" in p:
        p = p.split("?", 1)[0]
    try:
        return unquote(p)
    except Exception:  # noqa: BLE001 - an undecodable path is used as-is
        return p


def forbidden_domain(path: str) -> str:
    """The security domain this service path operates, or "".

    Parses `domain.service` out of a path EXACTLY as the server's
    `is_forbidden_service` does -- rebuild the dotted key from the last two
    segments and require the dot -- so the two cannot disagree about what a
    path means. The rule is copied rather than imported: this file must
    stand alone inside a customer's Home Assistant.
    """
    tail = "/".join((path or "").rsplit("/", 2)[-2:])
    key = tail.replace("/", ".")
    if "." not in key:
        return ""
    domain = key.split(".", 1)[0].strip().lower()
    return domain if domain in FORBIDDEN_SERVICE_DOMAINS else ""


def check_allowed(method: str, path: str) -> None:
    """Raise `NotAllowed` unless this exact request is permitted.

    A LOCAL MIRROR of the service's `check_allowed`, deliberately written
    out rather than derived from anything the service sends: a guard that
    asked the thing it guards against what the rules are would not be one.
    """
    m = (method or "").upper()
    p = decoded_path(path)
    # A traversal in the tail walks a permitted prefix out of its own
    # subtree, which is the one way a prefix rule fails open.
    if ".." in p:
        raise NotAllowed(f"{m} {path} contains a path traversal")

    if m == "GET":
        if p.startswith(tuple(RELAY_ALLOWED["get_prefixes"])):
            return
        raise NotAllowed(f"GET {path} is not on the allow-list")

    if m == "POST":
        # THE SECURITY-DOMAIN GATE RUNS FIRST, on every POST anywhere under
        # the services tree -- not, as it did, only inside the branch that
        # had already matched the allow-list. There it could never fire,
        # because `post_paths` is derived from `SERVICES` and no forbidden
        # domain appears in it: a gate that no input can reach is not a
        # gate. Here it is a real one, and it is what a widening of the
        # service allow-list would meet first.
        if p.startswith("/api/services/"):
            domain = forbidden_domain(p)
            if domain:
                raise NotAllowed(
                    f"{path} operates a security device ({domain}), which "
                    "this integration never does"
                )
        if p in RELAY_ALLOWED["post_paths"]:
            return
        if p.startswith("/api/services/"):
            raise NotAllowed(f"service path {path} is not on the allow-list")
        for pre in RELAY_ALLOWED["post_prefixes"]:
            if p.startswith(pre):
                return
        raise NotAllowed(f"POST {path} is not on the allow-list")

    if m == "DELETE":
        for pre in RELAY_ALLOWED["delete_prefixes"]:
            # A bare prefix names no document.
            if p.startswith(pre) and len(p) > len(pre):
                return
        raise NotAllowed(f"DELETE {path} is not on the allow-list")

    raise NotAllowed(f"method {m or '?'} is not carried by this integration")


def check_ws_allowed(command: str) -> None:
    if command not in RELAY_ALLOWED["ws_commands"]:
        raise NotAllowed(f"WS command {command!r} is not on the allow-list")


# --------------------------------------------------------------- the agent

class RelayAgent:
    """One outbound socket, its reconnect loop, and the local forwarding.

    Lifecycle is owned by the config entry: `async_start` on setup,
    `async_stop` on unload. `finished` goes true when the service says
    `bye`, and the loop then stops for good -- an abandoned integration must
    not redial a dead job forever.
    """

    def __init__(
        self,
        hass: Any,
        job_code: str,
        *,
        token: str,
        ha_version: str = "",
        install_type: str = "",
        on_state: Callable[[], None] | None = None,
    ) -> None:
        self.hass = hass
        self._job_code = job_code          # never logged
        self._token = token                # never logged, never sent
        self.ha_version = ha_version
        self.install_type = install_type
        self._on_state = on_state

        self.connected = False
        self.finished = False
        self.finished_reason = ""
        self.last_error = ""
        #: Set when the service says the code is wrong. A config entry in
        #: this state is re-authenticated, not retried: redialling with a
        #: code the service has rejected is a guaranteed-failing loop.
        self.rejected = False
        #: Guards against starting the re-auth flow twice for one agent --
        #: the state listener can fire more than once on the way down.
        self.reauth_started = False
        #: Set when the integration has given up after `MAX_REPLACEMENTS`
        #: consecutive displacements. Like `rejected` this is a STOPPED
        #: state, and the sensor must say so rather than claim to be
        #: reconnecting.
        self.replaced = False

        #: How many CONSECUTIVE times the service has displaced this
        #: agent. Reset by any session that did real work: three
        #: replacements spread across a week of a long job are not a
        #: collision, they are three ordinary reconnect races.
        self._replacements = 0
        #: True while the LAST socket ended because we were replaced. Read
        #: once by `_run` to choose `REPLACED_BACKOFF_S` over the
        #: exponential curve, then cleared.
        self._was_replaced = False

        self._task: asyncio.Task | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._session: aiohttp.ClientSession | None = None
        self._send_lock = asyncio.Lock()
        #: HA websocket sessions the service has opened through us, by id.
        self._ws_sessions: dict[str, "_LocalWSSession"] = {}
        #: Forwarded requests currently running. Tracked so they can be
        #: cancelled before the token they carry is revoked.
        self._inflight: set[asyncio.Task] = set()
        self._stopping = False

    # ------------------------------------------------------------ plumbing

    @property
    def relay_url(self) -> str:
        """Where to dial. Environment only -- never anything a frame said."""
        return os.environ.get(ENV_RELAY_URL) or DEFAULT_RELAY_URL

    @property
    def local_base(self) -> str:
        """This Home Assistant, over loopback.

        `hass.config.api.port` rather than a configured URL: the request
        must not leave the box, and an external URL could be a proxy, a
        Nabu Casa address, or simply wrong.
        """
        port = 8123
        api = getattr(self.hass.config, "api", None)
        if api is not None and getattr(api, "port", None):
            port = int(api.port)
        return f"http://127.0.0.1:{port}"

    def _notify(self) -> None:
        if self._on_state is not None:
            try:
                self._on_state()
            except Exception as exc:  # noqa: BLE001 - must not kill the loop
                # WARNING, not DEBUG. The listener is what revokes the token
                # and renames the entry on `bye`, so an exception here is a
                # job that silently does not end -- and at DEBUG (HA hides
                # INFO and below by default) it is invisible. A broken
                # listener that is swallowed must at least be audible.
                _LOG.warning("ElectriFix Connect state listener raised: %s: %s",
                             type(exc).__name__, exc, exc_info=True)

    # ------------------------------------------------------------ lifecycle

    async def async_start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping = False
            self._task = self.hass.async_create_background_task(
                self._run(), "electrifix_connect agent"
            ) if hasattr(self.hass, "async_create_background_task") else (
                self.hass.loop.create_task(self._run())
            )

    async def async_stop(self) -> None:
        """Stop for good. Never raises: it runs on the unload path."""
        self._stopping = True
        # IN-FLIGHT REQUESTS FIRST. `async_unload_entry` revokes the token
        # immediately after this returns, and a forwarded request still
        # running would keep using a credential that no longer exists --
        # 401s in the customer's log at best, and a genuine
        # use-after-revoke window at worst.
        await self._cancel_inflight()
        task, self._task = self._task, None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:  # noqa: BLE001
                pass
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        await self._close_all_ws_sessions()
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:  # noqa: BLE001
                pass
            self._session = None
        self.connected = False
        self._notify()

    async def _run(self) -> None:
        """Dial, serve, back off, redial -- until `bye`, a 4401, or unload.

        THE BACKOFF ONLY RESETS ON A SESSION THAT ACTUALLY DID WORK. A
        server-initiated close is a CLEAN close, so an earlier build that
        reset on "no exception raised" reset on exactly the two codes
        (4503, 4429) that exist to ask the agent to slow down. See
        `next_delay`, which is a pure function so the curve can be tested
        without a socket.
        """
        delay = BACKOFF_START
        while not self._stopping and not self.finished and not self.rejected:
            close_code: int | None = None
            served_for = 0.0
            self._was_replaced = False
            try:
                close_code, served_for = await self._connect_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - any failure is a retry
                self.last_error = f"{type(exc).__name__}: {exc}"
                _LOG.debug("ElectriFix Connect: %s", self.last_error)
            finally:
                self.connected = False
                self._notify()
            if self._stopping or self.finished or self.rejected:
                break
            # A SESSION THAT DID REAL WORK AND WAS NOT ITSELF REPLACED
            # clears the count. Both halves are load-bearing, and each was
            # learned by getting it wrong.
            #
            # `served_for >= BACKOFF_RESET_AFTER` rather than "the socket
            # came up", because the latter is true of the replaced session
            # too -- it dials, is displaced a moment later, and the reset
            # lands on the very connection that incremented the counter.
            #
            # `and not self._was_replaced`, because the threshold ALONE has
            # exactly the same hole one level up (review H1). In the steady
            # state of two installs trading one job code, each holds the
            # registration for the OTHER's whole `REPLACED_BACKOFF_S`
            # (45 s) before being displaced -- comfortably past
            # `BACKOFF_RESET_AFTER` (30 s). So every displaced session
            # cleared the count again, both copies sat at 1 of 3 forever,
            # and the cap this whole branch exists for could never fire:
            # the customer saw "Reconnecting..." indefinitely instead of
            # being told that something else is on their job code.
            #
            # Counting CONSECUTIVE replacements is the point: three of them
            # spread over a week of a long job are three ordinary reconnect
            # races, not two installs fighting, and stopping on those would
            # end a working integration for a reason that had gone away
            # days earlier. A replacement is never one of those "in
            # between" sessions -- it is the thing being counted.
            if served_for >= BACKOFF_RESET_AFTER and not self._was_replaced:
                self._replacements = 0
            if self._was_replaced:
                # A REPLACEMENT IS NOT A NETWORK FAILURE, so it does not
                # feed the exponential curve -- it has its own fixed wait,
                # keyed to the server's liveness window (see
                # `REPLACED_BACKOFF_S`). The curve is left untouched so a
                # genuine outage after this still backs off correctly.
                self._was_replaced = False
                try:
                    await asyncio.sleep(REPLACED_BACKOFF_S)
                except asyncio.CancelledError:
                    raise
                continue
            delay = next_delay(delay, close_code, served_for)
            # Jitter so a service restart does not bring every integration
            # in the world back in the same second.
            #
            # DOWNWARD ONLY, so the wait can never exceed `BACKOFF_MAX` by
            # construction. Two-sided jitter put a wait at the cap in the
            # range 450-750 s against a ruled ten-minute cap; spreading the
            # herd is the entire point of jitter and spreading it earlier
            # does that just as well, without the cap becoming a number the
            # code can exceed.
            wait = delay * (1 - random.uniform(0.0, BACKOFF_JITTER))
            try:
                await asyncio.sleep(max(1.0, wait))
            except asyncio.CancelledError:
                raise

    async def _connect_once(self) -> tuple[int | None, float]:
        """One dial. Returns `(close_code, seconds the socket was up)`.

        Both are what `next_delay` needs, and returning them rather than
        stashing them on `self` keeps the decision a pure function of what
        happened.
        """
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        url = self.relay_url
        _LOG.debug("ElectriFix Connect: dialling %s", url)
        close_code: int | None = None
        up_since = 0.0
        async with self._session.ws_connect(
            url, heartbeat=30, max_msg_size=MAX_MSG_SIZE,
            timeout=aiohttp.ClientWSTimeout(ws_close=10)
            if hasattr(aiohttp, "ClientWSTimeout") else 30,
        ) as ws:
            self._ws = ws
            await self._send({
                "type": "hello",
                "job_code": self._job_code,
                "ha_version": self.ha_version,
                "install_type": self.install_type,
                "integration_version": INTEGRATION_VERSION,
            })
            # The service does not ACK a hello: a socket that stays open is
            # the acknowledgement, and a bad code is a close code. So the
            # agent is "connected" the moment the hello is away and the
            # socket has not been shut -- and the first close tells it why
            # if it was wrong.
            self.connected = True
            self.last_error = ""
            up_since = time.monotonic()
            self._notify()
            try:
                await self._read_loop(ws)
            finally:
                # IN THE `finally`, and reading the code off `ws` BEFORE the
                # context manager exits. Previously this sat after the
                # `async with`, so any raise during teardown -- including
                # from `_close_all_ws_sessions` -- skipped it entirely and a
                # 4401 went unread, leaving a bad code redialling forever.
                close_code = ws.close_code
                self._ws = None
                await self._cancel_inflight()
                await self._close_all_ws_sessions()
                self._explain_close(close_code)
        served_for = time.monotonic() - up_since if up_since else 0.0
        return close_code, served_for

    def _explain_close(self, code: int | None) -> None:
        if code == CLOSE_BAD_CODE:
            # TERMINAL FOR THIS ENTRY. The service has refused the code, so
            # redialling it can only fail again -- and an entry that sits
            # there silently not-reconnecting is worse than one that says
            # so. `_notify` carries `rejected` up to `__init__`, which
            # starts a re-auth flow and takes the minted token back: a
            # credential for a job the service has disowned should not
            # outlive the refusal.
            self.rejected = True
            self.last_error = (
                "ElectriFix did not accept this job code. Open the "
                "integration and enter the current code from your job page."
            )
            _LOG.error("ElectriFix Connect: %s", self.last_error)
        elif code == CLOSE_RELAY_OFF:
            # NOT `rejected`: the code is fine, the far end is switched off.
            # Keep backing off rather than sending the customer hunting for
            # a code that is perfectly correct.
            self.last_error = (
                "ElectriFix Connect is not switched on at the other end "
                "just now; still trying."
            )
            _LOG.warning("ElectriFix Connect: %s", self.last_error)
        elif code == CLOSE_RATE_LIMITED:
            self.last_error = "ElectriFix asked us to slow down; backing off."
            _LOG.warning("ElectriFix Connect: %s", self.last_error)

    async def _read_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        async for msg in ws:
            if msg.type is not aiohttp.WSMsgType.TEXT:
                if msg.type in (aiohttp.WSMsgType.CLOSE,
                                aiohttp.WSMsgType.CLOSED,
                                aiohttp.WSMsgType.ERROR):
                    break
                continue
            try:
                frame = json.loads(msg.data)
            except (ValueError, TypeError):
                continue          # one bad frame must not drop the socket
            if not isinstance(frame, dict):
                continue
            kind = frame.get("type")
            if kind == "bye":
                await self._on_bye(str(frame.get("reason") or ""))
                break
            if kind == "ping":
                # ANSWERED HERE, IN THE READER, not handed to `_dispatch`.
                #
                # It is one line of work with no Home Assistant call behind
                # it, so a task would cost more than it does -- and, more
                # importantly, `_dispatch` goes through the MAX_INFLIGHT
                # cap. A box that is busy enough to be at the cap is
                # exactly the box whose pong must still get out: refusing
                # it there would make "busy" indistinguishable from "gone"
                # and have the service drop a working integration.
                #
                # The service treats ANY frame as life, so this matters
                # most on a quiet job, where there is no other traffic to
                # prove the socket is still there.
                await self._send({"type": "pong", "id": frame.get("id")})
                continue
            if kind == "replaced":
                # A newer connection for this job took over. STOP THIS
                # SOCKET, NOT THE INTEGRATION (1.1.2).
                #
                # THE FIRST-CONNECTION FAULT, in production on 2026-09-16
                # and again on 09-17. 1.1.1 set `_stopping` here on the
                # reasoning that "the newer socket is ours too" -- and it
                # very often was NOT. The config flow's validation socket
                # sent a real hello, so a second socket existed for the job
                # that nothing in this process was reading; whichever of
                # the two registered second displaced the other, and this
                # branch then ended the integration for good. The server
                # dropped the stale socket for silence 45 s later and
                # nothing ever redialled: the customer's job sat "waiting"
                # until a `homeassistant.reload_config_entry` fixed it in
                # seconds.
                #
                # So we redial, after `REPLACED_BACKOFF_S` -- deliberately
                # longer than the server's own liveness drop, so that by
                # the time we come back the newer socket has either proved
                # itself (and will replace us again, which we count) or
                # been dropped (and our redial is what restores service).
                self._replacements += 1
                self._was_replaced = True
                if self._replacements >= MAX_REPLACEMENTS:
                    # Not a race any more. Two installs are genuinely
                    # sharing one job code and redialling would oscillate
                    # forever, so stop and SAY WHICH -- an integration that
                    # has given up must never look like one that is
                    # retrying.
                    self.replaced = True
                    self.last_error = REPLACED_MESSAGE
                    self._stopping = True
                    _LOG.warning(
                        "ElectriFix Connect: replaced %d times in a row; "
                        "%s", self._replacements, REPLACED_MESSAGE,
                    )
                else:
                    _LOG.info(
                        "ElectriFix Connect: replaced by a newer connection "
                        "(%d of %d); redialling in %.0fs",
                        self._replacements, MAX_REPLACEMENTS,
                        REPLACED_BACKOFF_S,
                    )
                break
            # Everything else is work, and work must not block the reader:
            # a long request would stall every other frame on the socket.
            #
            # BOUNDED AND TRACKED. Unbounded fire-and-forget meant a server
            # sending thousands of frames became thousands of concurrent
            # loopback requests on what is often a Raspberry Pi -- every one
            # of them individually permitted, which is precisely why the
            # allow-list alone is not enough. And an untracked task outlives
            # the entry: it kept using the minted token for up to
            # LOCAL_REQUEST_TIMEOUT after the token had been revoked.
            # `ws_send` and `ws_close` are EXEMPT from the cap. They carry
            # no `id` (see the protocol docstring in `haclient.relay`), so
            # there is no key the far end correlates a refusal on: a dropped
            # one leaves the service blocking in `ws_recv` until the full
            # 60 s timeout and then reporting the customer's Home Assistant
            # as unreachable when it is merely busy.
            #
            # Exempting them is safe because they are not what the cap
            # exists to bound: neither opens a loopback HTTP request or a
            # task that outlives the frame. `ws_send` writes one message to
            # an already-open socket and `ws_close` closes one. The cap is
            # there to stop unbounded concurrent requests against the
            # customer's core, and these are neither unbounded (one session
            # at a time, MAX_WS_SESSIONS) nor requests.
            if (frame.get("type") not in ("ws_send", "ws_close")
                    and len(self._inflight) >= MAX_INFLIGHT):
                _LOG.warning(
                    "ElectriFix Connect: %d requests already in flight; "
                    "refusing another", len(self._inflight)
                )
                if frame.get("id") is not None:
                    await self._send({
                        "type": "error", "id": frame.get("id"),
                        "error": "busy: too many requests in flight",
                    })
                continue
            task = self.hass.async_create_task(self._dispatch(frame))
            self._inflight.add(task)
            task.add_done_callback(self._inflight.discard)

    async def _on_bye(self, reason: str) -> None:
        """The job is over. Stop, and say so where the customer will see it."""
        self.finished = True
        self.finished_reason = reason or "job complete"
        self.last_error = ""
        _LOG.info("ElectriFix Connect: %s (%s)", FINISHED_MESSAGE,
                  self.finished_reason)
        self._notify()

    # ------------------------------------------------------------ dispatch

    async def _dispatch(self, frame: dict[str, Any]) -> None:
        kind = frame.get("type")
        try:
            if kind == "http":
                await self._do_http(frame)
            elif kind == "ws_open":
                await self._do_ws_open(frame)
            elif kind == "ws_send":
                await self._do_ws_send(frame)
            elif kind == "ws_close":
                await self._do_ws_close(frame)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - never drop the socket
            _LOG.debug("frame %r failed: %s", kind, exc, exc_info=True)
            if frame.get("id") is not None:
                await self._send({"type": "error", "id": frame.get("id"),
                                  "error": f"{type(exc).__name__}: {exc}"})

    async def _do_http(self, frame: dict[str, Any]) -> None:
        msg_id = frame.get("id")
        method = str(frame.get("method") or "")
        path = str(frame.get("path") or "")

        # THE GUARD, before anything touches this Home Assistant. The refusal
        # is a 403 response rather than an `error` frame on purpose: the
        # service's caller sees a status it already knows how to handle, and
        # the refusal is visible in this house's own log as well.
        try:
            check_allowed(method, path)
        except NotAllowed as exc:
            _LOG.warning(
                "ElectriFix Connect REFUSED %s %s: %s", method, path, exc
            )
            await self._send({
                "type": "http_response", "id": msg_id, "status": 403,
                "headers": {"Content-Type": "application/json"},
                "binary": False,
                "body": json.dumps({"message": str(exc),
                                    "refused_by": "electrifix_connect"}),
            })
            return

        body = _decode_body(frame)
        headers = {
            # Only the headers a body needs. The service's own headers are
            # NOT forwarded wholesale: one of them could be an Authorization
            # that displaced the token we mint here.
            "Authorization": f"Bearer {self._token}",
            "Content-Type": str(
                (frame.get("headers") or {}).get("Content-Type")
                or "application/json"
            ),
        }
        session = _http_session(self.hass)
        try:
            async with session.request(
                method.upper(), self.local_base + path,
                headers=headers, data=body or None,
                timeout=aiohttp.ClientTimeout(total=LOCAL_REQUEST_TIMEOUT),
            ) as resp:
                raw = await resp.read()
                out_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in ("content-type", "content-length")
                }
                await self._send({
                    "type": "http_response", "id": msg_id,
                    "status": resp.status, "headers": out_headers,
                    **_encode_body(raw),
                })
        except asyncio.TimeoutError:
            await self._send({
                "type": "http_response", "id": msg_id, "status": 504,
                "headers": {"Content-Type": "application/json"},
                "binary": False,
                "body": json.dumps(
                    {"message": "Home Assistant did not answer in time"}
                ),
            })

    # ----------------------------------------------------------- websocket

    async def _do_ws_open(self, frame: dict[str, Any]) -> None:
        """Open one authenticated session to this core's own /api/websocket.

        The auth handshake happens HERE, with the minted token, so the
        service never sees a credential and never has to implement HA's
        auth flow.
        """
        msg_id = frame.get("id")
        session_id = str(frame.get("session") or "")
        # ONE AT A TIME. The sweep and the planner each open a session, use
        # it and close it, so a second concurrent one is a bug or an attack
        # -- and an unbounded dict of them is a real socket and a real task
        # per entry, which is how a confused server takes a small box out on
        # file descriptors alone. Closing the old rather than refusing means
        # a server that lost track of a session can still make progress.
        while len(self._ws_sessions) >= MAX_WS_SESSIONS:
            old_id, old = next(iter(self._ws_sessions.items()))
            self._ws_sessions.pop(old_id, None)
            _LOG.debug("closing ws session %s to make room", old_id)
            await old.async_close()
        try:
            sess = _LocalWSSession(self, session_id)
            await sess.async_open()
        except Exception as exc:  # noqa: BLE001
            await self._send({"type": "ws_opened", "id": msg_id,
                              "session": session_id, "ok": False,
                              "error": f"{type(exc).__name__}: {exc}"})
            return
        self._ws_sessions[session_id] = sess
        await self._send({"type": "ws_opened", "id": msg_id,
                          "session": session_id, "ok": True,
                          "ha_version": sess.ha_version or self.ha_version})

    async def _do_ws_send(self, frame: dict[str, Any]) -> None:
        session_id = str(frame.get("session") or "")
        payload = frame.get("payload")
        sess = self._ws_sessions.get(session_id)
        if sess is None or not isinstance(payload, dict):
            return
        command = str(payload.get("type") or "")
        try:
            # ALWAYS, even when empty. A deny-by-default guard that returns
            # early on malformed input has the wrong default: "" is not on
            # the list, so refusing it is the correct answer and the server's
            # own `check_ws_allowed` has no such bypass either.
            check_ws_allowed(command)
        except NotAllowed as exc:
            _LOG.warning("ElectriFix Connect REFUSED ws %s: %s", command, exc)
            # Shaped like HA's own failure result, so the service's existing
            # error handling reads it without a special case.
            await self._send({"type": "ws_recv", "session": session_id,
                              "payload": {"id": payload.get("id"),
                                          "type": "result", "success": False,
                                          "error": {
                                              "code": "not_allowed",
                                              "message": str(exc)}}})
            return
        await sess.async_send(payload)

    async def _do_ws_close(self, frame: dict[str, Any]) -> None:
        sess = self._ws_sessions.pop(str(frame.get("session") or ""), None)
        if sess is not None:
            await sess.async_close()

    async def _cancel_inflight(self) -> None:
        """Stop every forwarded request, and WAIT for them to actually stop.

        Awaited before the token is revoked, so no request can still be
        carrying a credential that has just been taken back.
        """
        tasks, self._inflight = set(self._inflight), set()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _close_all_ws_sessions(self) -> None:
        sessions, self._ws_sessions = self._ws_sessions, {}
        for sess in sessions.values():
            await sess.async_close()

    # --------------------------------------------------------------- send

    async def _send(self, frame: dict[str, Any]) -> None:
        ws = self._ws
        if ws is None or ws.closed:
            return
        try:
            async with self._send_lock:
                await ws.send_str(json.dumps(frame))
        except Exception as exc:  # noqa: BLE001 - a send failure is a drop
            _LOG.debug("send failed: %s", exc)


class _StopRetrying(Exception):
    """Raised when redialling cannot possibly help."""


class _LocalWSSession:
    """One authenticated websocket to this Home Assistant's own core.

    Multiplexed onto the relay by its session id: the service can have a
    sweep and a planner lookup open at once, and they must not read each
    other's replies.
    """

    def __init__(self, agent: RelayAgent, session_id: str) -> None:
        self.agent = agent
        self.session_id = session_id
        self.ha_version = ""
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._task: asyncio.Task | None = None

    async def async_open(self) -> None:
        session = _http_session(self.agent.hass)
        url = self.agent.local_base + "/api/websocket"
        ws = await session.ws_connect(url, heartbeat=30,
                                      max_msg_size=MAX_MSG_SIZE)
        self._ws = ws
        # HA's handshake: auth_required -> auth -> auth_ok.
        msg = await ws.receive_json(timeout=LOCAL_REQUEST_TIMEOUT)
        if msg.get("type") == "auth_required":
            self.ha_version = str(msg.get("ha_version") or "")
            await ws.send_json({"type": "auth",
                                "access_token": self.agent._token})
            msg = await ws.receive_json(timeout=LOCAL_REQUEST_TIMEOUT)
        if msg.get("type") != "auth_ok":
            await ws.close()
            self._ws = None
            raise RuntimeError(
                f"Home Assistant refused the token: {msg.get('message') or msg}"
            )
        self.ha_version = str(msg.get("ha_version") or self.ha_version)
        self._task = self.agent.hass.async_create_task(self._pump())

    async def _pump(self) -> None:
        ws = self._ws
        if ws is None:
            return
        try:
            async for msg in ws:
                if msg.type is not aiohttp.WSMsgType.TEXT:
                    break
                try:
                    payload = json.loads(msg.data)
                except (ValueError, TypeError):
                    continue
                await self.agent._send({"type": "ws_recv",
                                        "session": self.session_id,
                                        "payload": payload})
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            pass
        finally:
            await self.agent._send({"type": "ws_closed",
                                    "session": self.session_id})

    async def async_send(self, payload: dict[str, Any]) -> None:
        ws = self._ws
        if ws is None or ws.closed:
            return
        await ws.send_str(json.dumps(payload))

    async def async_close(self) -> None:
        task, self._task = self._task, None
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


# --------------------------------------------------------------- helpers

def _http_session(hass: Any) -> aiohttp.ClientSession:
    """Home Assistant's shared client session.

    NO FALLBACK. This used to return a fresh `ClientSession()` that nobody
    closed if the import failed -- and because `_do_http` calls this per
    request, one failed import turned every forwarded request into a leaked
    session and an "Unclosed client session" warning storm. Inside Home
    Assistant the import cannot fail; outside it, a loud failure is more
    honest than a quiet leak.

    The import is lazy so that this module's pure functions (the guard, the
    body codec, `next_delay`) can be exercised without Home Assistant
    installed -- which is what `tests/test_integration_files.py` does.
    """
    from homeassistant.helpers.aiohttp_client import async_get_clientsession

    return async_get_clientsession(hass)


def _encode_body(raw: bytes) -> dict[str, Any]:
    """`{"body": str, "binary": bool}`.

    UTF-8 goes across as text, which keeps a frame readable in a log.
    Anything else is base64 -- a backup is bytes, and silently mangling it
    would corrupt exactly the artefact whose integrity is the point.
    """
    if not raw:
        return {"body": "", "binary": False}
    try:
        return {"body": raw.decode("utf-8"), "binary": False}
    except UnicodeDecodeError:
        return {"body": base64.b64encode(raw).decode("ascii"), "binary": True}


def _decode_body(frame: dict[str, Any]) -> bytes:
    body = frame.get("body")
    if body is None:
        return b""
    if not isinstance(body, str):
        return json.dumps(body).encode()
    if frame.get("binary"):
        try:
            return base64.b64decode(body, validate=True)
        except Exception:  # noqa: BLE001
            return b""
    return body.encode("utf-8")
