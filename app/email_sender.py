"""Модуль отправки email с отчётами.

Использует SMTP mail.ru (SSL 465).
"""
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

SMTP_HOST = "smtp.mail.ru"
SMTP_PORT = 465
SMTP_USER = "luxset@mail.ru"
TO_EMAIL = "309303@mail.ru"


def _get_password() -> str:
    key_path = Path(__file__).parent.parent / "secret" / "mail.txt"
    try:
        return key_path.read_text().strip()
    except FileNotFoundError:
        raise RuntimeError(f"Пароль не найден: {key_path}")


def send_report(to_email: str, subject: str, body_html: str, pdf_bytes: bytes = None, filename: str = "report.pdf") -> bool:
    """Отправляет email с HTML-телом и опциональным PDF-вложением."""
    password = _get_password()

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body_html, "html", "utf-8"))

    if pdf_bytes:
        part = MIMEBase("application", "pdf")
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
        msg.attach(part)

    try:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
        server.login(SMTP_USER, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[email] Ошибка отправки: {e}")
        return False
