"""Render the editable Angelia project report Markdown to a shareable PDF.

Usage: python tools/report/render_project_report.py [source.md] [output.pdf]
"""

from __future__ import annotations

import html
import os
import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "reports" / "ANGELIA_TECHNICAL_PROJECT_REPORT.md"
OUTPUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "output" / "pdf" / "Angelia_Technical_Project_Report.pdf"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

FONT_DIR = Path(r"C:\Windows\Fonts")
pdfmetrics.registerFont(TTFont("Segoe", str(FONT_DIR / "segoeui.ttf")))
pdfmetrics.registerFont(TTFont("Segoe-Bold", str(FONT_DIR / "segoeuib.ttf")))
pdfmetrics.registerFont(TTFont("Consolas", str(FONT_DIR / "consola.ttf")))
pdfmetrics.registerFontFamily("Segoe", normal="Segoe", bold="Segoe-Bold", italic="Segoe", boldItalic="Segoe-Bold")

NAVY = colors.HexColor("#102D3B")
TEAL = colors.HexColor("#007B83")
INK = colors.HexColor("#253540")
MUTED = colors.HexColor("#61717B")
PALE = colors.HexColor("#EAF3F3")
LINE = colors.HexColor("#D6E1E4")

PAGE_W, PAGE_H = A4
LEFT = RIGHT = 49
TOP = 54
BOTTOM = 50
CONTENT_W = PAGE_W - LEFT - RIGHT

styles = {
    "title": ParagraphStyle("title", fontName="Segoe-Bold", fontSize=29, leading=35, textColor=NAVY, spaceAfter=9),
    "subtitle": ParagraphStyle("subtitle", fontName="Segoe", fontSize=15, leading=21, textColor=TEAL, spaceAfter=24),
    "cover": ParagraphStyle("cover", fontName="Segoe", fontSize=10.5, leading=17, textColor=INK, spaceAfter=3),
    "h2": ParagraphStyle("h2", fontName="Segoe-Bold", fontSize=14.2, leading=19, textColor=NAVY, spaceBefore=13, spaceAfter=6, keepWithNext=True),
    "h3": ParagraphStyle("h3", fontName="Segoe-Bold", fontSize=10.8, leading=15, textColor=TEAL, spaceBefore=10, spaceAfter=4, keepWithNext=True),
    "body": ParagraphStyle("body", fontName="Segoe", fontSize=9.1, leading=13.3, textColor=INK, spaceAfter=7),
    "bullet": ParagraphStyle("bullet", fontName="Segoe", fontSize=8.9, leading=12.5, textColor=INK, leftIndent=16, firstLineIndent=-10, spaceAfter=3),
    "table": ParagraphStyle("table", fontName="Segoe", fontSize=7.8, leading=10.7, textColor=INK),
    "tablehead": ParagraphStyle("tablehead", fontName="Segoe-Bold", fontSize=7.8, leading=10.7, textColor=NAVY),
    "code": ParagraphStyle("code", fontName="Consolas", fontSize=7, leading=9.2, textColor=NAVY),
}


def clean(s: str) -> str:
    return (s.replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")
             .replace("\u2192", "->").replace("\u00a0", " "))


def inline(s: str) -> str:
    s = html.escape(clean(s), quote=False)
    def link_markup(match):
        target = match.group(2)
        if not re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            target = os.path.relpath((SOURCE.parent / target).resolve(), OUTPUT.parent.resolve()).replace("\\", "/")
        return f'<link href="{html.escape(target, quote=True)}" color="#007B83">{match.group(1)}</link>'
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link_markup, s)
    s = re.sub(r"`([^`]+)`", r'<font name="Consolas" color="#0B6570">\1</font>', s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    return s.replace("  <br/>", "<br/>")


def table_flow(lines: list[str]) -> LongTable:
    rows = []
    for line in lines:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
            continue
        rows.append(cells)
    n = max(map(len, rows))
    if n == 3:
        ratios = [0.23, 0.25, 0.52]
    elif n == 4:
        ratios = [0.20, 0.24, 0.28, 0.28]
    else:
        ratios = [1 / n] * n
    widths = [CONTENT_W * x for x in ratios]
    data = []
    for i, row in enumerate(rows):
        row += [""] * (n - len(row))
        data.append([Paragraph(inline(cell), styles["tablehead"] if i == 0 else styles["table"]) for cell in row])
    table = LongTable(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PALE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFA")]),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, TEAL),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def parse_markdown(source: str):
    lines = source.splitlines()
    story = []
    i = 0
    cover = True
    while i < len(lines):
        line = lines[i].rstrip()
        if not line:
            i += 1
            continue
        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), styles["title"]))
            i += 1
            continue
        if line.startswith("## "):
            if cover:
                story.append(Paragraph(inline(line[3:]), styles["subtitle"]))
            else:
                story.append(Paragraph(inline(line[3:]), styles["h2"]))
            i += 1
            continue
        if line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), styles["h3"]))
            i += 1
            continue
        if line == "---":
            if cover:
                story.append(Spacer(1, 25))
                story.append(HRFlowable(width="100%", thickness=2, color=TEAL))
                story.append(PageBreak())
                cover = False
            else:
                story.append(HRFlowable(width="100%", thickness=0.5, color=LINE))
            i += 1
            continue
        if line == "<!-- pdf:pagebreak -->":
            story.append(PageBreak())
            i += 1
            continue
        if line.startswith("```"):
            i += 1
            code = []
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(clean(lines[i]))
                i += 1
            i += 1
            # Code blocks are kept together when they fit, preserving diagrams.
            flow = Preformatted("\n".join(code), styles["code"], maxLineLength=105, splitChars=" ")
            story.append(KeepTogether([Spacer(1, 4), flow, Spacer(1, 9)]))
            continue
        if line.startswith("|"):
            block = []
            while i < len(lines) and lines[i].startswith("|"):
                block.append(lines[i])
                i += 1
            story.extend([Spacer(1, 5), table_flow(block), Spacer(1, 9)])
            continue
        if line.startswith("- ") or re.match(r"\d+\. ", line):
            block = []
            while i < len(lines) and (lines[i].startswith("- ") or re.match(r"\d+\. ", lines[i])):
                item = lines[i]
                prefix, content = ("\u2022", item[2:]) if item.startswith("- ") else re.match(r"(\d+)\. (.*)", item).groups()
                block.append(Paragraph(f"{prefix}. {inline(content)}" if prefix != "\u2022" else f"{prefix} {inline(content)}", styles["bullet"]))
                i += 1
            story.extend(block)
            story.append(Spacer(1, 4))
            continue
        paragraph = []
        while i < len(lines) and lines[i].strip() and not re.match(r"(?:#|\||```|- |\d+\. |---)", lines[i]):
            paragraph.append(lines[i].rstrip())
            i += 1
        if not paragraph:
            i += 1
            continue
        text = "<br/>".join(inline(part) for part in paragraph) if cover else inline(" ".join(paragraph))
        story.append(Paragraph(text, styles["cover"] if cover else styles["body"]))
    return story


def page_chrome(canvas, doc):
    canvas.saveState()
    if doc.page > 1:
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(LEFT, PAGE_H - 34, PAGE_W - RIGHT, PAGE_H - 34)
        canvas.setFont("Segoe-Bold", 8)
        canvas.setFillColor(NAVY)
        canvas.drawString(LEFT, PAGE_H - 28, "ANGELIA  |  TECHNICAL PROJECT REPORT")
    canvas.setStrokeColor(LINE)
    canvas.line(LEFT, 38, PAGE_W - RIGHT, 38)
    canvas.setFont("Segoe", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(LEFT, 25, "Version 0.4.0  |  25 October 2026")
    canvas.drawRightString(PAGE_W - RIGHT, 25, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(
    str(OUTPUT), pagesize=A4, rightMargin=RIGHT, leftMargin=LEFT,
    topMargin=TOP, bottomMargin=BOTTOM,
    title="Angelia Technical Project Report", author="Angelia project",
    subject="Architecture, workflow, validation, limitations, and reproduction",
)
doc.build(parse_markdown(SOURCE.read_text(encoding="utf-8")), onFirstPage=page_chrome, onLaterPages=page_chrome)
print(OUTPUT)
