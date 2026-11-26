"""Read the controller's site-scoped Shadow Mode roles and desired revisions."""

from http.cookiejar import MozillaCookieJar
from functools import partial
import json
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from backends.vyos_failover import _invalid_constant, _unique_fields
from provisioners.vyos_shadow_binding import (
    _identifier, _management_origin, bind_shadow_enrollments, bind_shadow_primary_admission,
)


_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
SHADOW_ADMISSION_STATES = frozenset({"FIRMWARE_NOT_SUPPORTED", "READY_FOR_SETUP"})
_ADVERTISED_PAIR_STATES = SHADOW_ADMISSION_STATES | {"IN_PROGRESS", "SETUP_COMPLETED"}


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("UniFi redirected a Shadow Mode inventory request")


def _read_json(origin, path, *, opener):
    request = Request(origin + path, headers={"Accept": "application/json"}, method="GET")
    try:
        with opener.open(request, timeout=5) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise ValueError(f"UniFi Shadow Mode inventory returned HTTP {error.code}") from None
    except OSError:
        raise ValueError("UniFi Shadow Mode inventory could not be reached over verified HTTPS") from None
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("UniFi Shadow Mode inventory response exceeded its size limit")
    try:
        return json.loads(body, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise ValueError("UniFi returned invalid Shadow Mode inventory JSON") from None


class ShadowControllerReader:
    def __init__(self, *, origin, site, site_id, ca_file, session_file):
        _management_origin(origin)
        if (not isinstance(site, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", site) is None
                or not _identifier(site_id) or not ca_file):
            raise ValueError("Shadow Mode controller reads require a pinned origin and exact site")
        self._origin = origin.rstrip("/")
        self._site_id = site_id
        self._group_path = f"/proxy/network/v2/api/site/{site}/shadowmode/managed/group"
        self._devices_path = f"/proxy/network/api/s/{site}/stat/device"
        self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls.load_verify_locations(cafile=ca_file)
        self._session_file = Path(session_file)

    def read_pair(self, *, routers):
        """Require the same roles, phase and desired revisions in two consecutive observations."""
        def bind(group, inventory):
            return bind_shadow_enrollments(site_id=self._site_id, pair=group, inventory=inventory, routers=routers)

        return self._read_stable(bind)

    def read_primary_admission(self, *, router, firmware, applied_revision):
        """Verify the active primary before Network admits a standby."""
        def bind(group, inventory):
            return bind_shadow_primary_admission(site_id=self._site_id, group=group, inventory=inventory,
                                                 router=router, firmware=firmware, applied_revision=applied_revision)

        return self._read_stable(bind)

    def read_capability_binding(self, *, routers, role, firmware, applied_revision):
        """Bind the announcing worker in the pre-pair and enrolled-pair phases."""
        if role not in ("primary", "standby"):
            raise ValueError("Shadow Mode capability requires a configured router role")
        bind = partial(self._bind_capability, routers=routers, role=role, firmware=firmware,
                       applied_revision=applied_revision)
        return self._read_stable(bind)

    def _bind_capability(self, group, inventory, *, routers, role, firmware, applied_revision):
        if group["state"] == "NO_SHADOW_CANDIDATE_ADOPTED" and role == "primary":
            return bind_shadow_primary_admission(site_id=self._site_id, group=group, inventory=inventory,
                                                 router=routers[0], firmware=firmware, applied_revision=applied_revision)
        pair = bind_shadow_enrollments(site_id=self._site_id, pair=group, inventory=inventory, routers=routers)
        if pair.state not in _ADVERTISED_PAIR_STATES or pair.firmware != firmware:
            raise ValueError("UniFi Shadow Mode pair is outside a compatible setup phase")
        return pair

    def _read_stable(self, bind):
        jar = MozillaCookieJar(self._session_file)
        try:
            jar.load(ignore_discard=True)
        except OSError:
            raise ValueError("The UniFi Shadow Mode read session could not be loaded") from None
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=self._tls), _NoRedirects(), HTTPCookieProcessor(jar))
        observed = bind(*self._read_inventory(opener))
        if bind(*self._read_inventory(opener)) != observed:
            raise ValueError("UniFi Shadow Mode pairing changed during the inventory read")
        return observed

    def _read_inventory(self, opener):
        group = _read_json(self._origin, self._group_path, opener=opener)
        if (not isinstance(group, dict) or not _identifier(group.get("state"))
                or group.get("interface_name") != "eth1"):
            raise ValueError("UniFi did not return a Shadow Mode group on Enterprise port 2")
        inventory = _read_json(self._origin, self._devices_path, opener=opener)
        if (not isinstance(inventory, dict) or not isinstance(inventory.get("meta"), dict)
                or inventory["meta"].get("rc") != "ok"):
            raise ValueError("UniFi did not return the Shadow Mode site device inventory")
        return group, inventory.get("data")
