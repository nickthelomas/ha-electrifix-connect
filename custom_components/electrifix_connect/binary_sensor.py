"""One diagnostic entity: is ElectriFix connected right now.

A customer who is watching their job page wants to know whether the problem
is at their end or ours. This is that answer, in the place they already
look, rather than in a log.

Diagnostic category on purpose: it is not something to automate on, and it
should not clutter a dashboard.
"""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DOMAIN,
    FINISHED_MESSAGE,
    INTEGRATION_VERSION,
    REJECTED_MESSAGE,
    REPLACED_MESSAGE,
)
from .relay import RelayAgent


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    agent: RelayAgent | None = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if agent is not None:
        async_add_entities([ElectrifixConnectionSensor(entry, agent)])


class ElectrifixConnectionSensor(BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Connection"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_should_poll = False

    def __init__(self, entry: ConfigEntry, agent: RelayAgent) -> None:
        self._entry = entry
        self._agent = agent
        self._attr_unique_id = f"{entry.entry_id}_connection"

    @property
    def is_on(self) -> bool:
        return bool(self._agent.connected)

    @property
    def available(self) -> bool:
        # A finished job is not "unavailable" -- it is finished, and saying
        # so is more useful than a greyed-out entity.
        return True

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "status": (
                FINISHED_MESSAGE if self._agent.finished
                # BEFORE the "Reconnecting…" fallback. A rejected agent is
                # NOT reconnecting and never will be, and an integration
                # that claims to be retrying while doing nothing is worse
                # than one that says plainly what went wrong.
                else REJECTED_MESSAGE if self._agent.rejected
                # ALSO BEFORE the fallback, for the same reason. An agent
                # that has spent its replacements has STOPPED, and the
                # honest sentence names the situation the customer can
                # actually act on: something else is on this job code.
                else REPLACED_MESSAGE if self._agent.replaced
                else "Connected" if self._agent.connected
                else "Reconnecting…"
            ),
            "integration_version": INTEGRATION_VERSION,
            "last_error": self._agent.last_error or "",
        }

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{DOMAIN}_state_{self._entry.entry_id}",
                self._changed,
            )
        )

    @callback
    def _changed(self) -> None:
        self.async_write_ha_state()
