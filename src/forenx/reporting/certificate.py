from __future__ import annotations

from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

MAX_WORKSHEET_BYTES = 8 * 1024 * 1024
OFFICIAL_BSA_URI = (
    "https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf"
)


class CertificateWorksheetRenderingError(RuntimeError):
    """Raised when the unsigned legal-support worksheet cannot be rendered."""


def render_section_63_support_worksheet(report: dict[str, Any]) -> bytes:
    """Render a static, unsigned worksheet from verified report facts."""
    output = BytesIO()
    styles = _styles()
    try:
        case = report["case"]
        exhibit = report["exhibit"]
        source = report["source_evidence"]
        document = SimpleDocTemplate(
            output,
            pagesize=A4,
            rightMargin=17 * mm,
            leftMargin=17 * mm,
            topMargin=19 * mm,
            bottomMargin=19 * mm,
            title="Section 63(4) certificate support worksheet",
            author="ForenX",
            subject="Unsigned electronic-record certificate preparation worksheet",
        )
        story: list[Any] = []
        _add_header(story, styles)
        story.append(
            Paragraph(
                "This worksheet organizes verified technical facts and identifies missing "
                "declarations. It is not the statutory certificate, is not signed, and must not "
                "be filed as one. The authorized party, expert, and legal reviewer must compare "
                "it with the current Schedule and complete the required certificate for each "
                "submission instance.",
                styles["warning"],
            )
        )
        story.append(Spacer(1, 4 * mm))
        _add_fact_table(
            story,
            "Verified ForenX facts",
            (
                ("Case reference", case["case_reference"]),
                ("Report ID", report["report_id"]),
                ("Exhibit number", exhibit["exhibit_number"]),
                ("Electronic record", source["original_filename"]),
                ("Media kind", source["media_kind"]),
                ("Byte size", source["byte_size"]),
                ("SHA-256", source["sha256"]),
                ("Integrity re-check", "PASSED" if source["integrity_verified"] else "FAILED"),
            ),
            styles,
        )
        _add_fact_table(
            story,
            "Device or digital-record source details - verify before use",
            (
                ("Source category", _source_category(exhibit, source)),
                ("Make and model", _joined(exhibit.get("manufacturer"), exhibit.get("model"))),
                ("Color", "NOT RECORDED - COMPLETE MANUALLY"),
                ("Serial number", _known(exhibit.get("serial_number"))),
                ("IMEI / UIN / UID / MAC / Cloud ID", "NOT RECORDED - COMPLETE MANUALLY"),
                (
                    "Other relevant information",
                    "Collection authority reference: "
                    f'{_known(exhibit.get("authorization_reference"))}',
                ),
            ),
            styles,
        )
        _add_part_a(story, styles)
        story.append(PageBreak())
        _add_header(story, styles)
        _add_part_b(story, report, styles)
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Completion and review gate", styles["heading"]))
        for item in (
            "[ ] The electronic record being submitted is identified exactly.",
            "[ ] The manner of production and all involved devices are described.",
            "[ ] Part A is completed and signed by an appropriate person in lawful control.",
            "[ ] Part B is completed and signed by the appropriate expert.",
            "[ ] A hash report is enclosed and agrees with the submitted electronic record.",
            "[ ] Date, IST time, place, names, designations, and signatures are complete.",
            "[ ] Qualified legal and forensic reviewers approve the final certificate.",
        ):
            story.append(Paragraph(escape(item), styles["body"]))
        story.append(Spacer(1, 4 * mm))
        story.append(
            Paragraph(
                f"Official reference: Bharatiya Sakshya Adhiniyam, 2023, section 63(4) "
                f"and Schedule - {escape(OFFICIAL_BSA_URI)}",
                styles["source"],
            )
        )
        document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    except (KeyError, TypeError, ValueError) as exc:
        raise CertificateWorksheetRenderingError(
            "Certificate-support worksheet data is incomplete or invalid"
        ) from exc
    payload = output.getvalue()
    if not payload.startswith(b"%PDF-") or len(payload) > MAX_WORKSHEET_BYTES:
        raise CertificateWorksheetRenderingError(
            "Certificate-support worksheet is invalid or exceeds its size limit"
        )
    return payload


def _add_header(story: list[Any], styles: dict[str, ParagraphStyle]) -> None:
    story.extend(
        (
            Paragraph("FORENX / LEGAL HANDOFF", styles["eyebrow"]),
            Paragraph("Section 63(4) certificate support worksheet", styles["title"]),
            Paragraph("UNSIGNED WORKSHEET - NOT A CERTIFICATE", styles["banner"]),
            Spacer(1, 4 * mm),
        )
    )


def _add_part_a(story: list[Any], styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("Part A preparation - party in lawful control", styles["heading"]))
    for item in (
        "Name: ________________________________________________________________",
        "Son / daughter / spouse of: ___________________________________________",
        "Residential or employment address: ____________________________________",
        "Relationship to source: [ ] Owned  [ ] Maintained  [ ] Managed  [ ] Operated",
        "[ ] I will identify the submitted electronic record and how it was produced.",
        "[ ] I will confirm lawful control and ordinary-course use of the source.",
        "[ ] I will address regular information input and proper device operation.",
        "[ ] Any malfunction and its effect on accuracy will be explained.",
        "[ ] SHA-256 shown above matches the electronic record being submitted.",
    ):
        story.append(Paragraph(escape(item), styles["body"]))
    _add_signature_block(story, "Party", styles)


def _add_part_b(
    story: list[Any],
    report: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    source = report["source_evidence"]
    exhibit = report["exhibit"]
    story.append(Paragraph("Part B preparation - expert", styles["heading"]))
    story.append(
        Paragraph(
            "The expert must independently confirm the source, acquisition or production "
            "method, identifiers, and hash before signing.",
            styles["body"],
        )
    )
    _add_fact_table(
        story,
        "Technical values for independent verification",
        (
            ("Source category", _source_category(exhibit, source)),
            ("Make and model", _joined(exhibit.get("manufacturer"), exhibit.get("model"))),
            ("Serial number", _known(exhibit.get("serial_number"))),
            ("Electronic record", source["original_filename"]),
            ("SHA-256", source["sha256"]),
            ("Hash algorithm", "SHA-256"),
            ("ForenX source ID", source["source_id"]),
        ),
        styles,
    )
    for item in (
        "Expert name: __________________________________________________________",
        "Son / daughter / spouse of: ___________________________________________",
        "Residential or employment address: ____________________________________",
        "Designation: ___________________________________________________________",
        "Independent hash observed: _____________________________________________",
        "[ ] I verified the electronic record and device/source particulars.",
        "[ ] I verified the enclosed hash report against the submitted record.",
    ):
        story.append(Paragraph(escape(item), styles["body"]))
    _add_signature_block(story, "Expert", styles)


def _add_signature_block(
    story: list[Any],
    label: str,
    styles: dict[str, ParagraphStyle],
) -> None:
    story.append(Spacer(1, 3 * mm))
    table = Table(
        [
            ["Name and signature", "Date (DD/MM/YYYY)"],
            [f"{label}: ______________________________", "____________________"],
            ["Time (IST, 24-hour)", "Place"],
            ["____________________ hours", "____________________"],
        ],
        colWidths=(90 * mm, 70 * mm),
    )
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#C9D8D6")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF5F4")),
                ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#EEF5F4")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 2), (-1, 2), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(table)


def _add_fact_table(
    story: list[Any],
    title: str,
    rows: tuple[tuple[str, object], ...],
    styles: dict[str, ParagraphStyle],
) -> None:
    story.append(Paragraph(escape(title), styles["heading"]))
    table_rows = [
        [Paragraph(escape(label), styles["label"]), Paragraph(_safe(value), styles["value"])]
        for label, value in rows
    ]
    table = Table(table_rows, colWidths=(53 * mm, 107 * mm), repeatRows=0)
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF5F4")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D8D6")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(table)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "eyebrow": ParagraphStyle(
            "WorksheetEyebrow",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F766E"),
            spaceAfter=3,
        ),
        "title": ParagraphStyle(
            "WorksheetTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=23,
            textColor=colors.HexColor("#102A2B"),
            spaceAfter=5,
        ),
        "banner": ParagraphStyle(
            "WorksheetBanner",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#8B2D2D"),
            backColor=colors.HexColor("#FCEBEB"),
            borderColor=colors.HexColor("#D88D8D"),
            borderWidth=0.6,
            borderPadding=6,
        ),
        "warning": ParagraphStyle(
            "WorksheetWarning",
            parent=base["BodyText"],
            fontSize=8.6,
            leading=12.5,
            textColor=colors.HexColor("#5F3A16"),
            backColor=colors.HexColor("#FFF7E8"),
            borderColor=colors.HexColor("#E7C681"),
            borderWidth=0.5,
            borderPadding=7,
        ),
        "heading": ParagraphStyle(
            "WorksheetHeading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#102A2B"),
            spaceBefore=5,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "WorksheetBody",
            parent=base["BodyText"],
            fontSize=8.7,
            leading=13,
            textColor=colors.HexColor("#263E40"),
            spaceAfter=2,
        ),
        "label": ParagraphStyle(
            "WorksheetLabel",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=colors.HexColor("#526566"),
        ),
        "value": ParagraphStyle(
            "WorksheetValue",
            parent=base["Normal"],
            fontSize=8.3,
            leading=10.8,
            textColor=colors.HexColor("#102A2B"),
            wordWrap="CJK",
        ),
        "source": ParagraphStyle(
            "WorksheetSource",
            parent=base["Normal"],
            fontSize=7.2,
            leading=10,
            textColor=colors.HexColor("#526566"),
            wordWrap="CJK",
        ),
    }


def _source_category(exhibit: dict[str, Any], source: dict[str, Any]) -> str:
    description = f'{exhibit.get("device_type", "")} {source.get("media_kind", "")}'.lower()
    if "dvr" in description or "nvr" in description:
        return "DVR / NVR - CONFIRM THE SCHEDULE CATEGORY"
    if "raw-disk-image" in description:
        return "Storage media / DVR - CONFIRM THE SCHEDULE CATEGORY"
    return "Other / exported electronic record - COMPLETE MANUALLY"


def _known(value: object) -> str:
    if value is None or not str(value).strip():
        return "NOT RECORDED - COMPLETE MANUALLY"
    return str(value).strip()


def _joined(first: object, second: object) -> str:
    values = [
        str(value).strip()
        for value in (first, second)
        if value is not None and str(value).strip()
    ]
    return " / ".join(values) if values else "NOT RECORDED - COMPLETE MANUALLY"


def _safe(value: object) -> str:
    return escape(_known(value))


def _footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#C9D8D6"))
    canvas.line(17 * mm, 13 * mm, A4[0] - 17 * mm, 13 * mm)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(colors.HexColor("#8B2D2D"))
    canvas.drawString(17 * mm, 8.5 * mm, "UNSIGNED WORKSHEET - NOT A CERTIFICATE")
    canvas.setFillColor(colors.HexColor("#526566"))
    canvas.drawRightString(A4[0] - 17 * mm, 8.5 * mm, f"Page {document.page}")
    canvas.restoreState()
