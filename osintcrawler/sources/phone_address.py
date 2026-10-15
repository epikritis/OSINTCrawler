"""Phone number and physical address sources."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import quote_plus

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, SourceError, check

_NUMBER_TYPES = {v: k.lower() for k, v in vars(phonenumbers.PhoneNumberType).items() if k.isupper()}


class PhoneParser(Source):
    name = "Phone (offline)"
    types = frozenset({IType.PHONE})
    local_only = True
    homepage = "https://github.com/daviddrysdale/python-phonenumbers"
    description = "Country, region, line type, original carrier (no network)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        n = phonenumbers.parse(ind.value, None)
        ntype = _NUMBER_TYPES.get(phonenumbers.number_type(n), "unknown")
        region = phonenumbers.region_code_for_number(n)
        data = {
            "e164": ind.value,
            "international": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL),
            "valid": phonenumbers.is_valid_number(n),
            "region": region,
            "location": geocoder.description_for_number(n, "en"),
            "carrier": carrier.name_for_number(n, "en"),
            "line_type": ntype,
            "timezones": list(pn_timezone.time_zones_for_number(n)),
        }
        tags = [] if data["valid"] else ["invalid-number"]
        if ntype in ("voip", "premium_rate", "shared_cost"):
            tags.append(ntype.replace("_", "-"))
        findings = [f"{'Valid' if data['valid'] else 'INVALID'} {ntype} number, {data['location'] or region}"
                    + (f", original carrier {data['carrier']}" if data["carrier"] else "")]
        return self.ok(findings=findings, tags=tags, data=data)


class Numverify(Source):
    name = "Numverify"
    types = frozenset({IType.PHONE})
    key_env = "NUMVERIFY_API_KEY"
    homepage = "https://numverify.com"
    description = "Live carrier / line-type validation"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        # HTTPS only: never send the access key in clear text, even if the free plan prefers HTTP.
        resp = check(await ctx.client.get("https://apilayer.net/api/validate",
                                          params={"access_key": ctx.key(self.key_env), "number": ind.value.lstrip("+")}),
                     key_name=self.key_env)
        if resp is None:
            return self.not_found()
        d = resp.json()
        if d.get("success") is False or "error" in d:
            err = d.get("error") or {}
            if err.get("code") == 105:
                raise SourceError("Numverify plan does not allow HTTPS; upgrade plan (HTTP is refused to protect the key)")
            raise SourceError(f"Numverify error {err.get('code')}: {err.get('type')}")
        return self.ok(
            findings=[f"valid={d.get('valid')}; {d.get('line_type') or 'unknown'} line, carrier "
                      f"{d.get('carrier') or 'unknown'}, {d.get('location') or d.get('country_name')}"],
            tags=[d["line_type"]] if d.get("line_type") in ("voip", "special_services", "premium_rate") else [],
            data=d,
        )


_nominatim_lock = asyncio.Lock()
_nominatim_last = 0.0


class Nominatim(Source):
    name = "OpenStreetMap Nominatim"
    types = frozenset({IType.ADDRESS})
    homepage = "https://nominatim.openstreetmap.org"
    description = "Geocoding of physical addresses (keyless, 1 req/s)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        global _nominatim_last
        async with _nominatim_lock:  # usage policy: max 1 request per second
            wait = 1.0 - (time.monotonic() - _nominatim_last)
            if wait > 0:
                await asyncio.sleep(wait)
            resp = check(await ctx.client.get(
                "https://nominatim.openstreetmap.org/search",
                params={"q": ind.value, "format": "jsonv2", "addressdetails": 1, "limit": 3, "extratags": 1},
            ))
            _nominatim_last = time.monotonic()
        maps = f"https://www.google.com/maps/search/?api=1&query={quote_plus(ind.value)}"
        rows = resp.json() if resp is not None else []
        if not rows:
            return self.not_found("Address could not be geocoded", link=maps)
        best = rows[0]
        lat, lon = best.get("lat"), best.get("lon")
        return self.ok(
            findings=[f"{best.get('display_name')} ({best.get('category')}/{best.get('type')})",
                      f"Coordinates {lat}, {lon}"],
            link=f"https://www.openstreetmap.org/{best.get('osm_type')}/{best.get('osm_id')}",
            data={"matches": [{"display_name": r.get("display_name"), "lat": r.get("lat"), "lon": r.get("lon"),
                               "category": r.get("category"), "type": r.get("type"),
                               "address": r.get("address"), "importance": r.get("importance")} for r in rows],
                  "map_links": {
                      "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon}",
                      "google_maps": maps,
                      "google_street_view": f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}",
                  }},
        )
