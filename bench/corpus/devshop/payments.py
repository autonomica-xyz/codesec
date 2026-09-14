"""Coupon redemption + balance transfer."""
from __future__ import annotations
import sqlite3

DB_PATH = "devshop.db"

def redeem_coupon(code: str, amount: int) -> dict:
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT percent FROM coupons WHERE code = ?", (code,)).fetchone()
    if not row:
        return {"error": "invalid coupon"}
    discount = amount * row[0] // 100
    return {"code": code, "amount": amount, "discount": discount, "pay": amount - discount}

def transfer(user: str, to: str, amount: int) -> dict:
    # P2P balance transfer
    with sqlite3.connect(DB_PATH) as c:
        mine = c.execute("SELECT balance FROM users WHERE username = ?", (user,)).fetchone()
        if not mine:
            return {"error": "no account"}
        balance = mine[0]
        if amount > 0 and balance - amount >= 0:
            c.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, user))
            c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, to))
            return {"sent": amount, "to": to}
    return {"error": "insufficient funds"}
