"""Cryptocurrency wallet sources."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, SourceError, check

BTC, ETH = IType.BTC, IType.ETH


def _date(epoch: int | str | None) -> str | None:
    if not epoch:
        return None
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d")


class Blockstream(Source):
    name = "Blockstream (BTC)"
    types = frozenset({BTC})
    homepage = "https://blockstream.info"
    description = "Bitcoin balance & transaction history (keyless)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        base = "https://blockstream.info/api"
        resp = check(await ctx.client.get(f"{base}/address/{ind.value}"), not_found=(404, 400))
        link = f"https://blockstream.info/address/{ind.value}"
        if resp is None:
            return self.not_found("Address unknown / invalid", link=link)
        d = resp.json()
        cs, ms = d.get("chain_stats", {}), d.get("mempool_stats", {})
        received = cs.get("funded_txo_sum", 0)
        balance = received - cs.get("spent_txo_sum", 0)
        txs = []
        if cs.get("tx_count"):
            r2 = check(await ctx.client.get(f"{base}/address/{ind.value}/txs"))
            txs = r2.json() if r2 is not None else []
        times = [t.get("status", {}).get("block_time") for t in txs if t.get("status", {}).get("block_time")]
        data = {
            "tx_count": cs.get("tx_count", 0), "unconfirmed_tx_count": ms.get("tx_count", 0),
            "total_received_btc": received / 1e8, "total_sent_btc": cs.get("spent_txo_sum", 0) / 1e8,
            "balance_btc": balance / 1e8,
            "latest_tx": _date(max(times)) if times else None,
            "recent_txids": [t.get("txid") for t in txs[:10]],
        }
        return self.ok(
            findings=[f"{data['tx_count']} tx(s); received {data['total_received_btc']:.8f} BTC; "
                      f"balance {data['balance_btc']:.8f} BTC" + (f"; latest {data['latest_tx']}" if times else "")],
            data=data, link=link,
        )


class Etherscan(Source):
    name = "Etherscan (ETH)"
    types = frozenset({ETH})
    key_env = "ETHERSCAN_API_KEY"
    homepage = "https://etherscan.io"
    description = "Ethereum balance & activity"

    async def _call(self, ctx: Context, **params: str) -> object:
        params |= {"chainid": "1", "module": "account", "apikey": ctx.key(self.key_env) or ""}
        resp = check(await ctx.client.get("https://api.etherscan.io/v2/api", params=params), key_name=self.key_env)
        d = resp.json() if resp is not None else {}
        if d.get("status") == "0" and d.get("message") not in ("No transactions found",):
            raise SourceError(f"Etherscan: {d.get('message')} {str(d.get('result'))[:80]}")
        return d.get("result")

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        wei = await self._call(ctx, action="balance", address=ind.value, tag="latest")
        first = await self._call(ctx, action="txlist", address=ind.value, page="1", offset="1", sort="asc")
        last = await self._call(ctx, action="txlist", address=ind.value, page="1", offset="1", sort="desc")
        first_tx = first[0] if isinstance(first, list) and first else {}
        last_tx = last[0] if isinstance(last, list) and last else {}
        balance = int(wei or 0) / 1e18
        data = {"balance_eth": balance, "first_tx": _date(first_tx.get("timeStamp")),
                "last_tx": _date(last_tx.get("timeStamp")), "first_tx_hash": first_tx.get("hash"),
                "last_tx_hash": last_tx.get("hash"), "is_contract_creation": bool(first_tx.get("contractAddress"))}
        active = f"active {data['first_tx']} -> {data['last_tx']}" if data["first_tx"] else "no transactions"
        return self.ok(findings=[f"Balance {balance:.6f} ETH; {active}"], data=data,
                       link=f"https://etherscan.io/address/{ind.value}")


class Chainabuse(Source):
    name = "Chainabuse"
    types = frozenset({BTC, ETH, IType.DOMAIN, IType.URL})
    key_env = "CHAINABUSE_API_KEY"
    homepage = "https://www.chainabuse.com"
    description = "Crypto scam reports"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        key = ctx.key(self.key_env) or ""
        auth = base64.b64encode(f"{key}:{key}".encode()).decode()
        param = "address" if ind.type in (BTC, ETH) else "domain"
        value = ind.meta.get("host") or ind.value if ind.type is IType.URL else ind.value
        resp = check(await ctx.client.get("https://api.chainabuse.com/v0/reports",
                                          params={param: value, "perPage": 50},
                                          headers={"Authorization": f"Basic {auth}", "Accept": "application/json"}),
                     key_name=self.key_env)
        d = resp.json() if resp is not None else []
        reports = d if isinstance(d, list) else (d.get("reports") or d.get("data") or [])
        link = f"https://www.chainabuse.com/{'address' if param == 'address' else 'domain'}/{value}"
        if not reports:
            return self.ok(score=0, confidence=0.4, findings=["No scam reports"], link=link)
        cats = sorted({str(r.get("scamCategory") or r.get("category") or "OTHER") for r in reports})
        return self.ok(
            score=min(95, 60 + 5 * len(reports)), confidence=0.8,
            findings=[f"{len(reports)} scam report(s): {', '.join(cats[:5])}"],
            tags=["scam-reported"], link=link,
            data={"report_count": len(reports), "categories": cats,
                  "reports": [{"category": r.get("scamCategory"), "created": r.get("createdAt"),
                               "description": (r.get("description") or "")[:200]} for r in reports[:10]]},
        )
