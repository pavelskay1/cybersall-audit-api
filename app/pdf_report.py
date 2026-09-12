"""Генерация PDF-отчётов аудита кода."""
from datetime import datetime, timezone


def generate_audit_report(report_text: str, model: str = "ensemble", elapsed: float = 0, blocks: int = 1) -> bytes:
    from fpdf import FPDF

    regular = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_font("DV", "", regular, uni=True)
    pdf.add_font("DV", "B", bold, uni=True)

    pdf.add_page()
    pdf.set_font("DV", "B", 20)
    pdf.set_text_color(30, 58, 95)
    pdf.cell(0, 15, "Cybersall AI Agent", ln=True, align="C")

    pdf.set_font("DV", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, "Отчёт аудита кода", ln=True, align="C")

    pdf.set_draw_color(91, 140, 255)
    pdf.set_line_width(0.8)
    y = pdf.get_y() + 5
    pdf.line(20, y, 190, y)
    pdf.ln(12)

    pdf.set_font("DV", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 7, f"Дата: {now}  |  Режим: {model}  |  Время: {elapsed}с  |  Блоков: {blocks}", ln=True)
    pdf.ln(8)

    for line in report_text.split("\n"):
        stripped = line.strip()
        if not stripped:
            pdf.ln(3)
            continue

        if stripped.startswith("## "):
            pdf.set_font("DV", "B", 13)
            pdf.set_text_color(30, 58, 95)
            pdf.multi_cell(0, 8, stripped[3:])
            pdf.ln(2)
        elif stripped.startswith("### "):
            pdf.set_font("DV", "B", 11)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 7, stripped[4:])
            pdf.ln(1)
        elif stripped.startswith("```"):
            continue
        else:
            pdf.set_font("DV", "", 9)
            pdf.set_text_color(30, 30, 30)
            # Strip markdown formatting for clean PDF
            clean = stripped.replace("**", "").replace("__", "")
            pdf.multi_cell(0, 5, clean)

    pdf.ln(10)
    pdf.set_font("DV", "", 7)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "Cybersall AI Agent v1.0", ln=True, align="C")

    return pdf.output()
