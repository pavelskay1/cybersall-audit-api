"""Казначейство Cybersall — работа с mm CLI (MetaMask Agent Wallet).

Обёртка над mm CLI: балансы, свапы, бриджи, статус транзакций.
Конфиг и секреты — в secret/treasury.json (chmod 600), не в коде.
"""
import json
import logging
import shlex
import subprocess
from pathlib import Path
from datetime import datetime, timezone

log = logging.getLogger("treasury")

SECRET_DIR = Path(__file__).parent.parent / "secret"
CONFIG_FILE = SECRET_DIR / "treasury.json"
DEFAULT_CHAIN_ID = 43114  # Avalanche C-Chain

MM_BIN = "/usr/bin/mm"
LOW_GAS_WARNING = 0.1  # AVAX


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_config() -> dict:
    if not CONFIG_FILE.exists():
        raise RuntimeError(f"Нет конфига: {CONFIG_FILE}")
    return json.loads(CONFIG_FILE.read_text())


def _run(args: list, timeout: int = 120) -> dict:
    """Выполнить mm-команду, вернуть JSON."""
    cmd = [MM_BIN] + args + ["--json"]
    log.debug("mm exec: %s", shlex.join(cmd[1:]))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"mm timeout: {args[0]}")
    try:
        data = json.loads(r.stdout or r.stderr)
    except json.JSONDecodeError:
        raise RuntimeError(f"mm не JSON: {r.stdout[:200]} / {r.stderr[:200]}")
    if not data.get("ok"):
        err = data.get("error", {})
        raise RuntimeError("mm {}: {}".format(args[0], err.get("message", data)))
    return data.get("data", {})


def wallet_address() -> str:
    cfg = _load_config()
    ns = cfg.get("chain_namespace", "evm")
    d = _run(["wallet", "address", "--chain-namespace", ns])
    return d.get("address", "")


def balance(chain_id: int = None, tokens: list = None) -> dict:
    cfg = _load_config()
    chain_id = chain_id or cfg.get("default_chain_id", DEFAULT_CHAIN_ID)
    args = ["wallet", "balance", "--chain-ids", str(chain_id)]
    for t in tokens or []:
        args += ["--token", t]
    d = _run(args, timeout=90)
    # Собрать итог
    out = {
        "chain_id": chain_id,
        "total_usd": d.get("totalValue", "0"),
        "chains": [],
        "unpriced": d.get("unpricedAssetIds", []),
    }
    for ch in d.get("chains", []):
        tokens_list = []
        native_amt = "0"
        native_usd = "0"
        for b in ch.get("tokens", []) or []:
            t = b.get("token", "?")
            amt = b.get("amount", "0")
            usd = b.get("usdValue", "0")
            if b.get("type") == "native":
                native_amt = amt
                native_usd = usd
            tokens_list.append({
                "token": t,
                "address": b.get("assetId", ""),
                "amount": amt,
                "usd": usd,
            })
        out["chains"].append({
            "chain_id": ch.get("chainId"),
            "chain_name": ch.get("name", ""),
            "native": native_amt,
            "native_usd": native_usd,
            "tokens": tokens_list,
        })
    return out


def quote(_from: str, _to: str, amount: str, chain_id: int = None,
          to_chain_id: int = None, slippage: float = 0.5) -> dict:
    cfg = _load_config()
    chain_id = chain_id or cfg.get("default_chain_id", DEFAULT_CHAIN_ID)
    args = ["swap", "quote", "--from", _from, "--to", _to,
            "--amount", str(amount), "--from-chain-id", str(chain_id),
            "--slippage", str(slippage)]
    if to_chain_id:
        args += ["--to-chain-id", str(to_chain_id)]
    d = _run(args, timeout=180)
    q = d.get("quote", d)
    fd = q.get("feeData", {}) or {}
    mb = fd.get("metabridge", {}) or {}
    pd = q.get("priceData", {}) or {}
    price = None
    if isinstance(pd, dict):
        price = pd.get("totalToAmountUsd")
    route = None
    if isinstance(q.get("protocols"), list) and q["protocols"]:
        route = q["protocols"][0]
    return {
        "quote_id": d.get("quoteId") or q.get("quoteId"),
        "from": _from,
        "to": _to,
        "amount": amount,
        "expected_out": q.get("destAssetAmount"),
        "min_out": q.get("minDestAssetAmount"),
        "network_fee_avax": (q.get("networkFee") or {}).get("amount", "0"),
        "fee_bps": mb.get("quoteBpsFee", 0),
        "fee_usd": mb.get("usd", "0"),
        "price_impact": pd.get("priceImpact", "0") if isinstance(pd, dict) else "0",
        "route": route,
        "gas_sponsored": q.get("gasSponsored", False),
        "warnings": d.get("warnings", []),
        "hint": d.get("hint", ""),
    }


def execute(quote_id: str, timeout: int = 600) -> dict:
    """Выполнить свап/бридж по quote_id. В guard-режиме требует 2FA."""
    d = _run(["swap", "execute", "--quote-id", quote_id, "--wallet-timeout", str(timeout)],
             timeout=timeout + 30)
    return {
        "status": d.get("status", "executed"),
        "tx_hash": d.get("txHash") or d.get("transactionHash"),
        "route": d.get("route"),
        "job_id": d.get("jobId"),
    }


def swap_status(quote_id: str = None, tx_hash: str = None) -> dict:
    args = ["swap", "status"]
    if quote_id:
        args += ["--quote-id", quote_id]
    if tx_hash:
        args += ["--tx-hash", tx_hash]
    d = _run(args, timeout=120)
    return d


def send(to: str, amount: str, token: str = "native", chain_id: int = None,
         wait: bool = True) -> dict:
    cfg = _load_config()
    chain_id = chain_id or cfg.get("default_chain_id", DEFAULT_CHAIN_ID)
    args = ["transfer", "--to", to, "--amount", str(amount),
            "--token", token, "--chain-id", str(chain_id)]
    if wait:
        args.append("--wait")
    d = _run(args, timeout=300)
    return {"tx_hash": d.get("txHash"), "status": d.get("status", "sent")}


def gas_check(chain_id: int = None) -> dict:
    """Проверить, хватает ли нативного токена на газ."""
    b = balance(chain_id)
    total = 0.0
    for ch in b.get("chains", []):
        try:
            total += float(ch["native"])
        except (ValueError, TypeError):
            pass
    return {"native_avax": total, "low": total < LOW_GAS_WARNING, "ok": total >= LOW_GAS_WARNING}


def status() -> dict:
    return {
        "wallet": wallet_address(),
        "gas": gas_check(),
        "configured": CONFIG_FILE.exists(),
        "ts": _ts(),
    }
