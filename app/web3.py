"""Web3 модуль — проверка баланса CYB и списание за запросы.

Использует mm CLI для взаимодействия с Avalanche C-Chain.
"""
import json
import logging
from pathlib import Path
from .treasury import _load_config, _run, wallet_address

log = logging.getLogger("web3")

# ABI для useForService (минимальный, только нужные функции)
CYB_ABI = [
    {
        "name": "useForService",
        "type": "function",
        "inputs": [
            {"name": "user", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "name": "balanceOf",
        "type": "function",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view"
    },
    {
        "name": "decimals",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view"
    }
]


def get_cyb_balance(wallet: str) -> float:
    """Получить баланс CYB у пользователя."""
    cfg = _load_config()
    chain_id = cfg.get("cyb_chain", 43114)
    cyb_address = cfg.get("cyb_proxy", "")
    
    if not cyb_address:
        return 0.0
    
    # Используем mm CLI для получения баланса токена
    try:
        d = _run([
            "wallet", "balance",
            "--chain-ids", str(chain_id),
            "--token", cyb_address,
            "--address", wallet
        ], timeout=60)
        
        # Ищем CYB в ответе
        for ch in d.get("chains", []):
            for t in ch.get("tokens", []):
                if t.get("address", "").lower() == cyb_address.lower():
                    return float(t.get("amount", 0))
        return 0.0
    except Exception as e:
        log.error("CYB balance check failed: %s", e)
        return 0.0


def deduct_cyb(user_wallet: str, amount: int) -> dict:
    """Списать CYB у пользователя через useForService.
    
    Args:
        user_wallet: Адрес пользователя (0x...)
        amount: Сумма в минимальных единицах (с учётом decimals)
    
    Returns:
        dict с tx_hash и статусом
    """
    cfg = _load_config()
    chain_id = cfg.get("cyb_chain", 43114)
    cyb_address = cfg.get("cyb_proxy", "")
    
    if not cyb_address:
        raise RuntimeError("CYB contract address not configured")
    
    # Вызываем useForService через mm CLI
    # mm позволяет делать raw contract calls
    try:
        # mm не поддерживает прямые вызовы контрактов через CLI,
        # поэтому используем web3.py напрямую
        from web3 import Web3
        from eth_account import Account
        
        # Загружаем приватный ключ (owner wallet)
        private_key_file = Path("/opt/audit-api/secret/byok_private.txt")
        if not private_key_file.exists():
            raise RuntimeError("Private key not found")
        
        private_key = private_key_file.read_text().strip()
        
        # Подключаемся к Avalanche RPC
        w3 = Web3(Web3.HTTPProvider("https://api.avax.network/ext/bc/C/rpc"))
        
        # Формируем call useForService(user, amount)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(cyb_address),
            abi=CYB_ABI
        )
        
        # Строим транзакцию
        account = Account.from_key(private_key)
        nonce = w3.eth.get_transaction_count(account.address)
        
        tx = contract.functions.useForService(
            Web3.to_checksum_address(user_wallet),
            amount
        ).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 200000,
            'gasPrice': w3.eth.gas_price,
            'chainId': chain_id,
        })
        
        # Подписываем и отправляем
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Ждём подтверждения
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        return {
            "ok": True,
            "tx_hash": tx_hash.hex(),
            "status": "confirmed" if receipt.status == 1 else "failed",
            "gas_used": receipt.gasUsed,
        }
        
    except ImportError:
        raise RuntimeError("web3.py not installed")
    except Exception as e:
        log.error("CYB deduct failed: %s", e)
        return {"ok": False, "error": str(e)}


def verify_cyb_allowance(wallet: str, min_amount: int) -> bool:
    """Проверить, есть ли у пользователя достаточно CYB для запроса."""
    balance = get_cyb_balance(wallet)
    return balance >= min_amount / 10**6  # CYB has 6 decimals


# Тарифы в CYB (минимальные единицы, 6 decimals)
TARIFFS = {
    "code_audit_lite": 5 * 10**6,        # 5 CYB
    "code_audit_pro": 40 * 10**6,        # 40 CYB
    "code_audit_enterprise": 300 * 10**6, # 300 CYB
    "python_cpp_lite": 50 * 10**6,       # 50 CYB
    "python_cpp_pro": 40 * 10**6,        # 40 CYB
    "python_cpp_enterprise": 350 * 10**6, # 350 CYB
}


def get_tariff(service: str) -> int:
    """Получить стоимость услуги в минимальных единицах CYB."""
    return TARIFFS.get(service, 5 * 10**6)  # default 5 CYB
