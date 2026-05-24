"""Render docs/bank-loan-use-case.md as a branded PDF.

Reuses the Sentinel report palette (see backend/report.py) so the explainer matches the
evidence artifacts. fpdf2 core fonts are latin-1 only — _t() sanitizes accordingly.

    python3 docs/build_loan_usecase_pdf.py
"""

from __future__ import annotations

import os
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# Brand palette (mirrors backend/report.py)
INK = (17, 24, 39)
MUTE = (107, 114, 128)
LOCAL = (16, 122, 87)      # green  = stays/handled local
CLOUD = (37, 99, 235)      # blue   = cloud agent
LOCAL_BG = (236, 253, 245)
CLOUD_BG = (239, 246, 255)
RULE = (229, 231, 235)

OUT = os.path.join(os.path.dirname(__file__), "bank-loan-use-case.pdf")


def _t(s: str) -> str:
    return str(s).replace("•", "*").replace("–", "-").replace("—", "-").encode("latin-1", "replace").decode("latin-1")


class Doc(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_y(8)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTE)
        self.cell(0, 5, "Sentinel - Caso de uso: aprobacion de prestamos", align="L")
        self.cell(0, 5, f"{self.page_no()}", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MUTE)
        self.cell(0, 4, _t("Construido sobre Google Managed Agents - datos sinteticos, sin datos personales reales."), align="C")


def h1(pdf, text):
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*INK)
    pdf.ln(2)
    pdf.cell(0, 8, _t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*RULE)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(2)


def body(pdf, text, size=10):
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 5.2, _t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)


def bullet(pdf, text, accent=INK):
    x0 = pdf.l_margin
    pdf.set_x(x0)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*accent)
    pdf.cell(5, 5.2, _t("*"))
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*INK)
    avail = pdf.w - pdf.r_margin - pdf.get_x()
    pdf.multi_cell(avail, 5.2, _t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def banner(pdf, text, fg, bg):
    pdf.set_x(pdf.l_margin)
    pdf.set_fill_color(*bg)
    pdf.set_text_color(*fg)
    pdf.set_font("Helvetica", "B", 10)
    pdf.multi_cell(0, 6.5, _t(text), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def step(pdf, num, title, accent, bg, lines):
    """One numbered step as a colored card with an accent left bar."""
    pdf.ln(1)
    x0, y0 = pdf.l_margin, pdf.get_y()
    # heading
    pdf.set_fill_color(*bg)
    pdf.set_text_color(*accent)
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_x(x0 + 3)
    pdf.cell(0, 7, _t(f"{num}.  {title}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
    # body lines
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(*INK)
    for ln in lines:
        pdf.set_x(x0 + 6)
        pdf.multi_cell(pdf.w - pdf.r_margin - (x0 + 6), 4.8, _t(ln),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    y1 = pdf.get_y()
    # accent bar on the left
    pdf.set_fill_color(*accent)
    pdf.rect(x0, y0, 1.6, y1 - y0, style="F")
    pdf.ln(2)


def two_col_table(pdf, headers, rows, col_w, accents=None):
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*MUTE)
    for w, hd in zip(col_w, headers):
        pdf.cell(w, 6, _t(hd), border=0)
    pdf.ln(6)
    pdf.set_draw_color(*RULE)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(1)
    for r, row in enumerate(rows):
        y0 = pdf.get_y()
        x = pdf.l_margin
        maxy = y0
        for c, (w, cell) in enumerate(zip(col_w, row)):
            pdf.set_xy(x, y0)
            if c == 0:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*(accents[r] if accents and r < len(accents) else INK))
            else:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*INK)
            pdf.multi_cell(w, 4.8, _t(cell))
            maxy = max(maxy, pdf.get_y())
            x += w
        pdf.set_y(maxy)
        pdf.set_draw_color(*RULE)
        pdf.line(pdf.l_margin, pdf.get_y() + 0.5, pdf.w - pdf.r_margin, pdf.get_y() + 0.5)
        pdf.ln(2)


def build():
    pdf = Doc(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    # Title block
    pdf.set_text_color(*INK)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, _t("Sentinel - Caso de uso"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*CLOUD)
    pdf.cell(0, 8, _t("Aprobacion de prestamos"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    banner(pdf,
           "El agente de IA en la nube aprueba el credito sin ver jamas el SSN, el numero de "
           "cuenta ni el nombre del solicitante - y cada decision queda probada linea por linea "
           "con raw_sensitive_bytes_to_cloud: 0.",
           LOCAL, LOCAL_BG)

    # 1. Problem
    h1(pdf, "1. El problema del banco")
    body(pdf,
         "Hoy un banco recibe la solicitud de Juan: recibos de nomina, estados de cuenta, "
         "declaracion de impuestos y su SSN. Un analista humano lee todo y decide. Es lento "
         "(dias), caro (~$80k/anio, ~20 casos/dia) y no escala.")
    body(pdf,
         "El banco quiere que un agente de IA en la nube haga ese trabajo - razonamiento de un "
         "modelo frontier, no un regex local. Pero los documentos estan llenos de datos "
         "regulados (SSN, cuentas, saldos) que legalmente no puede mandar crudos a una API. "
         "Esta atrapado: proceso humano lento, o riesgo legal. Sentinel es la tercera opcion.")

    # 2. Objective
    h1(pdf, "2. El objetivo de negocio")
    body(pdf, "El banco no compra 'privacidad'. Compra velocidad, costo y escala:")
    bullet(pdf, "Mas rapido - aprobar en minutos, no en dias; no pierde al cliente.")
    bullet(pdf, "Mas barato - automatizar lo que hoy hacen ejercitos de analistas.")
    bullet(pdf, "A escala - 100x volumen sin contratar 100x personas.")
    bullet(pdf, "Consistente - la IA no decide distinto sobre el mismo caso.")
    pdf.ln(1)
    body(pdf,
         "La privacidad no es el objetivo: es el muro que hoy le impide alcanzarlo. "
         "Sentinel derriba el muro.")

    # 3. Key distinction
    h1(pdf, "3. La clave: identificadores vs. variables de decision")
    body(pdf,
         "Una decision de credito es ratios y consistencia - no identidad. Los documentos "
         "contienen dos tipos de datos casi disjuntos:")
    two_col_table(
        pdf,
        ["TIPO", "EJEMPLOS", "NECESITA?", "SENTINEL"],
        [
            ["A - Identificadores",
             "Nombre, SSN, n. de cuenta, direccion, fecha de nacimiento",
             "No para decidir. Solo si existe y es valido.",
             "Enmascara local; nunca sube crudo"],
            ["B - Variables de decision",
             "Ingreso $8,000/mes, deuda $2,000/mes, antiguedad 4 anios, saldo $15,000",
             "Si - mueve la decision",
             "Razona sobre el valor anonimo o solo el resultado"],
        ],
        col_w=[34, 52, 48, 44],
        accents=[LOCAL, CLOUD],
    )
    body(pdf, "El DTI (deuda/ingreso = 25%) es lo que aprueba o rechaza, no los digitos del SSN.")

    # 4. Flow
    pdf.add_page()
    h1(pdf, "4. El flujo, paso a paso")
    step(pdf, 1, "REDACT  (local, en tu DGX Spark)", LOCAL, LOCAL_BG, [
        "Documento crudo:",
        "   'Juan Perez, SSN 412-55-7890, cuenta 0033219, gana $8,000/mes, debe $2,000/mes'",
        "El modelo local enmascara los identificadores. Lo que sube a la nube:",
        "   '[PERSON_1], SSN [SSN_1], cuenta [ACCT_1], gana $8,000/mes, debe $2,000/mes'",
    ])
    step(pdf, 2, "REASON  (agente cloud, sobre el doc enmascarado)", CLOUD, CLOUD_BG, [
        "Calcula DTI = 2000 / 8000 = 25%  ->  saludable.",
        "Ve 0 sobregiros y 4 anios de empleo  ->  perfil estable.",
        "Pero no confia ciegamente: el ingreso declarado, es real? el SSN, existe?",
    ])
    step(pdf, 3, "VERIFY  (callback al modelo local - solo si/no)", LOCAL, LOCAL_BG, [
        "El agente pregunta a tu Spark a traves del allowlist:",
        "   - SSN [SSN_1] es valido y no esta en lista de fraude?      ->  SI",
        "   - los depositos reales en [ACCT_1] confirman los $8,000?   ->  SI",
        "   - la cuenta pertenece al solicitante?                      ->  SI",
        "Recibe veredictos. Nunca recibe el SSN ni el numero de cuenta.",
    ])
    step(pdf, 4, "DECIDE + audit", CLOUD, CLOUD_BG, [
        "'Recomiendo APROBAR: DTI 25%, ingreso verificado, identidad verificada,",
        " sin senales de fraude.'",
        "+ audit-log.json :  raw_sensitive_bytes_to_cloud = 0",
    ])

    # 5. What data helps
    h1(pdf, "5. Que datos si le sirven al agente?")
    body(pdf, "Tres cosas, y ninguna es un identificador crudo:")
    bullet(pdf, "Valores agregados/derivados: ingreso, deuda, ratios, antiguedad, tendencia del saldo.", CLOUD)
    bullet(pdf, "Veredictos booleanos que solo el lado local produce: 'SSN valido', 'ingreso coincide', 'sin fraude'.", LOCAL)
    bullet(pdf, "Contexto e inconsistencias: 'declara $8k pero los depositos suman $5k'.", CLOUD)

    # 6. Dial
    h1(pdf, "6. El dial: modo estandar vs. estricto")
    bullet(pdf, "Modo estandar - enmascara solo identificadores; los montos pasan anonimos. Sin identidad, no es PII reidentificable.", CLOUD)
    bullet(pdf, "Modo estricto - ni los montos suben. El DTI se calcula local; al agente solo le llega 'DTI: saludable' + veredictos. Razona sobre datos que nunca poseyo.", LOCAL)

    # 7. Why it matters
    h1(pdf, "7. Por que importa")
    two_col_table(
        pdf,
        ["SIN SENTINEL", "CON SENTINEL"],
        [
            ["Proceso humano lento y caro, o", "Decision en segundos"],
            ["Riesgo legal de mandar PII a la nube", "raw_sensitive_bytes_to_cloud: 0, probado"],
            ["'Confia en nosotros'", "Audit-log linea por linea"],
        ],
        col_w=[89, 89],
        accents=[MUTE, MUTE, MUTE],
    )
    body(pdf,
         "Sentinel no vende privacidad. Vende el objetivo de negocio desbloqueado - velocidad, "
         "costo, escala - con la privacidad resuelta como condicion de entrada, y la prueba "
         "para demostrarlo.")

    pdf.output(OUT)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    build()
