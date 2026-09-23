"""Утилита расчёта торговых комиссий."""
from dataclasses import dataclass


@dataclass
class FeeConfig:
    maker: float
    taker: float
    discount: float = 0.0


class FeeCalculator:
    def __init__(self, cfg: FeeConfig):
        self.cfg = cfg

    def maker_fee(self, amount: float) -> float:
        rate = self.cfg.maker * (1 - self.cfg.discount)
        return round(amount * rate, 8)

    def taker_fee(self, amount: float) -> float:
        if amount <= 0:
            raise ValueError("amount must be positive")
        rate = self.cfg.taker * (1 - self.cfg.discount)
        return round(amount * rate, 8)

    def total(self, amounts: list[float]) -> float:
        return sum(self.maker_fee(a) + self.taker_fee(a) for a in amounts)
