"""Source registry. Add a new source by appending an instance to ``_SOURCES``."""

from __future__ import annotations

from .abusech import MalwareBazaar, ThreatFox, URLhaus
from .base import Context, Source
from .crypto import Blockstream, Chainabuse, Etherscan
from .enrichment import Enrichment
from .identity import EmailRep, Gravatar, HaveIBeenPwned, Hunter
from .infra import DNS, RDAP, CrtSh, IPInfo, RIPEstat, SecurityTrails, Shodan, ShodanInternetDB
from .phone_address import Nominatim, Numverify, PhoneParser
from .threatintel import (
    AbuseIPDB,
    AlienVaultOTX,
    CIRCLHashlookup,
    GoogleSafeBrowsing,
    GreyNoise,
    URLScan,
    VirusTotal,
)
from .usernames import Usernames
from .vuln import CISAKEV, EPSS, NVD

_SOURCES: list[Source] = [
    # threat intel
    VirusTotal(), AbuseIPDB(), AlienVaultOTX(), GreyNoise(), URLhaus(), MalwareBazaar(), ThreatFox(),
    GoogleSafeBrowsing(), URLScan(), CIRCLHashlookup(),
    # infrastructure
    ShodanInternetDB(), Shodan(), IPInfo(), RDAP(), RIPEstat(), DNS(), SecurityTrails(), CrtSh(), Enrichment(),
    # identity
    HaveIBeenPwned(), Hunter(), EmailRep(), Gravatar(),
    # phone / address
    PhoneParser(), Numverify(), Nominatim(),
    # vulnerabilities
    NVD(), CISAKEV(), EPSS(),
    # crypto
    Blockstream(), Etherscan(), Chainabuse(),
    # people
    Usernames(),
]


def all_sources() -> list[Source]:
    return list(_SOURCES)


__all__ = ["Context", "Source", "all_sources"]
