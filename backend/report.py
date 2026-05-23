"""Render the run evidence: audit-log.json + report.pdf.

The report object shape is the contract defined by the pdf-generator skill, so the same
renderer works whether the report came from the cloud agent or the local fallback pipeline.
"""

from __future__ import annotations

import json
from fpdf import FPDF

_INK = (17, 24, 39)
_MUTE = (107, 114, 128)
_LOCAL = (16, 122, 87)
_CLOUD = (37, 99, 235)


def write_audit_log(report: dict, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)


def _latin1(s: str) -> str:
    """fpdf2 core fonts are latin-1 only; keep the bullet glyph readable as '*'."""
    return str(s).replace("•", "*").encode("latin-1", "replace").decode("latin-1")


def render_pdf(report: dict, path: str) -> None:
    s = report["summary"]
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_text_color(*_INK)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "Sentinel - Privacy Routing Report", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_MUTE)
    pdf.cell(0, 6, _latin1(f"Document: {report['document']}   Generated: {report['generated_at']}"), ln=1)
    pdf.ln(3)

    # Attestation banner
    pdf.set_fill_color(236, 253, 245)
    pdf.set_text_color(*_LOCAL)
    pdf.set_font("Helvetica", "B", 11)
    pdf.multi_cell(0, 7, _latin1(
        f"Raw sensitive bytes sent to cloud: {s['raw_sensitive_bytes_to_cloud']}   |   "
        f"Sensitive spans processed locally on {s.get('local_endpoint_host', 'local')} "
        f"by {s.get('local_model', 'local model')}."), fill=True)
    pdf.ln(3)

    # Summary line
    pdf.set_text_color(*_INK)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 6, _latin1(
        f"Spans: {s['spans_total']} total  -  {s['routed_local']} routed local  -  "
        f"{s['processed_cloud']} processed cloud"), ln=1)
    pdf.ln(2)

    # Per-span rows
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*_MUTE)
    pdf.cell(12, 7, "ID")
    pdf.cell(24, 7, "CATEGORY")
    pdf.cell(34, 7, "DESTINATION")
    pdf.cell(0, 7, "PREVIEW  /  DERIVATIVE", ln=1)
    pdf.set_draw_color(229, 231, 235)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(1)

    for span in report["spans"]:
        local = span["destination"] == "local-gemma"
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_INK)
        pdf.cell(12, 6, _latin1(span["id"]))
        pdf.cell(24, 6, _latin1(span["category"]))
        pdf.set_text_color(*(_LOCAL if local else _CLOUD))
        pdf.cell(34, 6, _latin1("local-gemma" if local else "cloud-sandbox"))
        pdf.set_text_color(*_INK)
        pdf.set_font("Helvetica", "", 9)
        deriv = span.get("safe_derivative") or {}
        extra = ""
        if local and deriv:
            extra = f"  ->  {deriv.get('display', '')}  ({deriv.get('note', '')})"
        pdf.multi_cell(0, 6, _latin1(span.get("preview", "") + extra))
        pdf.set_text_color(*_MUTE)
        pdf.set_font("Helvetica", "", 7)
        tail = f"sha256 {span['sha256'][:16]}"
        if local and span.get("latency_ms") is not None:
            tail += f"   local latency {span['latency_ms']} ms"
        pdf.cell(0, 4, _latin1(tail), ln=1)
        pdf.ln(1)

    pdf.output(path)
