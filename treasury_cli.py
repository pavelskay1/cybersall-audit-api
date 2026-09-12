#!/usr/bin/env python3
"""CLI казначейства Cybersall.

Примеры:
  python3 treasury_cli.py status
  python3 treasury_cli.py balance
  python3 treasury_cli.py quote USDC CYB 10
  python3 treasury_cli.py execute <quote_id>
  python3 treasury_cli.py send 0xADDR 1.5 CYB
"""
import sys, json
sys.path.insert(0, "/opt/audit-api")
from app.treasury import (status, balance, quote, execute, send, swap_status, gas_check)

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    cmd = args[0]
    try:
        if cmd == "status":
            print(json.dumps(status(), ensure_ascii=False, indent=2))
        elif cmd == "balance":
            print(json.dumps(balance(), ensure_ascii=False, indent=2))
        elif cmd == "gas":
            print(json.dumps(gas_check(), ensure_ascii=False, indent=2))
        elif cmd == "quote" and len(args) >= 4:
            print(json.dumps(quote(args[1], args[2], args[3]), ensure_ascii=False, indent=2))
        elif cmd == "execute" and len(args) >= 2:
            print(json.dumps(execute(args[1]), ensure_ascii=False, indent=2))
        elif cmd == "status-swap" and len(args) >= 2:
            print(json.dumps(swap_status(quote_id=args[1]), ensure_ascii=False, indent=2))
        elif cmd == "send" and len(args) >= 3:
            token = args[3] if len(args) > 3 else "native"
            print(json.dumps(send(args[1], args[2], token), ensure_ascii=False, indent=2))
        else:
            print("Неизвестная команда или аргументы:", cmd, args[1:])
            print(__doc__)
            return 1
    except Exception as e:
        print("Ошибка:", e, file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
