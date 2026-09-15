"""Генерация PDF-отчётов аудита кода."""
import textwrap
from datetime import datetime, timezone


def _soft_wrap(text: str, width: int = 95) -> str:
    """Разбивает очень длинные строки без пробелов, чтобы fpdf не падал."""
    if len(text) <= width:
        return text
    return textwrap.fill(text, width=width)


def generate_audit_report(report_text: str, model: str = "ensemble", elapsed: float = 0, blocks: int = 1) -> bytes:
    from fpdf import FPDF

    regular = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_font("DV", "", regular)
    pdf.add_font("DV", "B", bold)

    pdf.add_page()
    pdf.set_font("DV", "B", 20)
    pdf.set_text_color(30, 58, 95)
    pdf.cell(0, 15, "Cybersall AI Agent", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("DV", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, "Отчёт аудита кода", new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(91, 140, 255)
    pdf.set_line_width(0.8)
    y = pdf.get_y() + 5
    pdf.line(20, y, 190, y)
    pdf.ln(12)

    pdf.set_font("DV", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 7, f"Дата: {now}  |  Режим: {model}  |  Время: {elapsed}с  |  Блоков: {blocks}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    for line in report_text.split("\n"):
        stripped = line.strip()
        if not stripped:
            pdf.ln(3)
            continue

        if stripped.startswith("## "):
            pdf.set_font("DV", "B", 13)
            pdf.set_text_color(30, 58, 95)
            _safe_multi(pdf, _soft_wrap(stripped[3:]), 8)
            pdf.ln(2)
        elif stripped.startswith("### "):
            pdf.set_font("DV", "B", 11)
            pdf.set_text_color(50, 50, 50)
            _safe_multi(pdf, _soft_wrap(stripped[4:]), 7)
            pdf.ln(1)
        elif stripped.startswith("```"):
            continue
        else:
            pdf.set_font("DV", "", 9)
            pdf.set_text_color(30, 30, 30)
            clean = stripped.replace("**", "").replace("__", "")
            _safe_multi(pdf, _soft_wrap(clean), 5)

    pdf.ln(10)
    pdf.set_font("DV", "", 7)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "Cybersall AI Agent v1.0", new_x="LMARGIN", new_y="NEXT")

    return pdf.output()


def _safe_multi(pdf, text: str, height: float):
    """multi_cell с явной шириной и сбросом x — фикс fpdf2 2.8.8."""
    if not text:
        return
    pdf.set_x(pdf.l_margin)
    width = pdf.w - pdf.l_margin - pdf.r_margin
    try:
        pdf.multi_cell(width, height, text)
    except Exception:
        # Точечно пропускаем проблемный фрагмент (например, слишком широкий глиф)
        pdf.ln(1)
