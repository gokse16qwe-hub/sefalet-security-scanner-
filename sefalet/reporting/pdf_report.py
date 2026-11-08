"""Türkçe PDF güvenlik raporu.

ReportLab'in "platypus" katmanını kullanıyoruz: Sayfayı koordinatlarla
çizmek yerine paragraf, tablo, boşluk gibi "akan" (flowable) parçaları
bir listeye ekliyoruz; ReportLab bunları sayfalara kendisi yerleştirir.

Türkçe karakterler: ReportLab'in hazır fontları (Helvetica vb.) ş, ğ, ı, İ
harflerini gösteremez. Pakete eklediğimiz DejaVu Sans fontunu kaydedip
kullanıyoruz.

Rapor bölümleri:
    1. Kapak (hedef, tarih, genel not, yetki bilgisi)
    2. Yönetici özeti
    3. Kapsam ve yöntem (kontrol durumları, puanlama yöntemi)
    4. Bulgu özeti tablosu
    5. Detaylı bulgular
    6. Teknik ayrıntılar
    7. Sınırlamalar ve yasal uyarı
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from sefalet import __version__
from sefalet.models import CheckStatus, Confidence, Finding, ScanResult, Severity
from sefalet.risk import METHODOLOGY_TR
from sefalet.scanner import CHECK_LABELS_TR

FONT_DIR = Path(__file__).parent / "fonts"
FONT = "DejaVuSans"
FONT_BOLD = "DejaVuSans-Bold"

SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#7f1d1d"),
    Severity.HIGH: colors.HexColor("#dc2626"),
    Severity.MEDIUM: colors.HexColor("#d97706"),
    Severity.LOW: colors.HexColor("#2563eb"),
    Severity.INFO: colors.HexColor("#6b7280"),
}
GRADE_COLORS = {"A": "#15803d", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}
STATUS_COLORS = {
    CheckStatus.COMPLETED: colors.HexColor("#15803d"),
    CheckStatus.ERROR: colors.HexColor("#dc2626"),
    CheckStatus.SKIPPED: colors.HexColor("#6b7280"),
}
BORDER = colors.HexColor("#d1d5db")
LIGHT = colors.HexColor("#f3f4f6")
DARK = colors.HexColor("#111827")
MUTED = colors.HexColor("#4b5563")

LIMITATIONS_TR = [
    "Bu rapor yalnızca taramanın yapıldığı andaki dışarıdan görülebilen yapılandırmayı yansıtır.",
    "Tarama; saldırı, açık istismarı (exploit), parola denemesi veya yük testi içermez. "
    "Uygulama mantığı, kimlik doğrulama arkasındaki sayfalar ve kaynak kod incelenmemiştir.",
    "'Olası' olarak işaretlenen bulgular doğrulanmamıştır ve kesin güvenlik açığı olarak "
    "değerlendirilmemelidir; manuel doğrulama önerilir.",
    "'Test edilemedi' veya 'tamamlanamadı' olarak belirtilen kontroller için güvenli durum "
    "varsayılmamalıdır.",
    "Bulgu bulunmaması sitenin güvenli olduğu anlamına gelmez; bu rapor kapsamlı bir sızma "
    "testinin yerini tutmaz.",
    "Tarama, raporda belirtilen yetki/izin kaydına dayanarak gerçekleştirilmiştir. İzin "
    "beyanının doğruluğundan beyan eden kişi sorumludur.",
]


# ---------------------------------------------------------------------------
# Font ve stiller
# ---------------------------------------------------------------------------

_fonts_registered = False


def _register_fonts() -> None:
    global _fonts_registered
    if _fonts_registered:
        return
    regular = FONT_DIR / "DejaVuSans.ttf"
    bold = FONT_DIR / "DejaVuSans-Bold.ttf"
    if not regular.exists() or not bold.exists():
        raise FileNotFoundError(
            f"PDF fontları bulunamadı ({FONT_DIR}). Paket kurulumu eksik olabilir."
        )
    pdfmetrics.registerFont(TTFont(FONT, str(regular)))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(bold)))
    pdfmetrics.registerFontFamily(FONT, normal=FONT, bold=FONT_BOLD, italic=FONT, boldItalic=FONT_BOLD)
    _fonts_registered = True


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName=FONT, fontSize=9.5, leading=13, textColor=DARK)
    return {
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8.5, leading=11),
        "cell_bold": ParagraphStyle("cell_bold", parent=base, fontName=FONT_BOLD, fontSize=8.5, leading=11),
        "h1": ParagraphStyle("h1", parent=base, fontName=FONT_BOLD, fontSize=16, leading=20,
                             spaceBefore=6, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base, fontName=FONT_BOLD, fontSize=11.5, leading=15,
                             spaceBefore=10, spaceAfter=4),
        "title": ParagraphStyle("title", parent=base, fontName=FONT_BOLD, fontSize=24, leading=30,
                                alignment=TA_CENTER),
        "subtitle": ParagraphStyle("subtitle", parent=base, fontSize=12, leading=16,
                                   alignment=TA_CENTER, textColor=MUTED),
        "grade": ParagraphStyle("grade", parent=base, fontName=FONT_BOLD, fontSize=44, leading=50,
                                alignment=TA_CENTER, textColor=colors.white),
        "center": ParagraphStyle("center", parent=base, alignment=TA_CENTER),
    }


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    """Metni güvenle paragrafa çevirir.

    Paragraph, metni basit bir HTML/XML gibi yorumlar. Bulgu kanıtında
    "<script>" gibi ifadeler olabilir; escape() bunları zararsız hale getirir.
    """
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _format_dt(value) -> str:
    return value.strftime("%d.%m.%Y %H:%M UTC") if value else "-"


def _grid_table(rows, col_widths, header=True) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), LIGHT))
    table.setStyle(TableStyle(commands))
    return table


# ---------------------------------------------------------------------------
# Bölümler
# ---------------------------------------------------------------------------


def _cover(scan: ScanResult, s) -> list:
    risk = scan.risk
    grade = risk.grade if risk else "-"
    grade_box = Table([[_p(grade, s["grade"])]], colWidths=[45 * mm], rowHeights=[38 * mm])
    grade_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(GRADE_COLORS.get(grade, "#6b7280"))),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    grade_box.hAlign = "CENTER"

    auth = scan.authorization
    info_rows = [
        [_p("Hedef", s["cell_bold"]), _p(scan.target, s["cell"])],
        [_p("IP adresleri", s["cell_bold"]), _p(", ".join(scan.target_ips) or "-", s["cell"])],
        [_p("Tarama başlangıcı", s["cell_bold"]), _p(_format_dt(scan.started_at), s["cell"])],
        [_p("Tarama bitişi", s["cell_bold"]), _p(_format_dt(scan.finished_at), s["cell"])],
        [_p("Tarama kimliği", s["cell_bold"]), _p(scan.scan_id, s["cell"])],
        [_p("Tarama izni", s["cell_bold"]), _p(auth.method.label_tr, s["cell"])],
        [_p("İzin kaydı", s["cell_bold"]), _p(f"{auth.details} ({_format_dt(auth.verified_at)})", s["cell"])],
        [_p("Araç sürümü", s["cell_bold"]), _p(f"Sefalet Security Scanner {scan.scanner_version}", s["cell"])],
    ]
    score_text = f"Güvenlik puanı: {risk.score} / 100" if risk else ""
    if risk and not risk.complete:
        score_text += " (bazı kontroller tamamlanamadı)"

    return [
        Spacer(1, 25 * mm),
        _p("Güvenlik Yapılandırma Raporu", s["title"]),
        Spacer(1, 4 * mm),
        _p(scan.target, s["subtitle"]),
        Spacer(1, 18 * mm),
        grade_box,
        Spacer(1, 4 * mm),
        _p(score_text, s["center"]),
        Spacer(1, 18 * mm),
        _grid_table(info_rows, [45 * mm, 125 * mm], header=False),
        PageBreak(),
    ]


def _executive_summary(scan: ScanResult, s) -> list:
    risk = scan.risk
    story = [_p("1. Yönetici Özeti", s["h1"])]
    if risk:
        story.append(_p(risk.summary_tr, s["body"]))
    story.append(Spacer(1, 4 * mm))

    counts = scan.severity_counts()
    white = ParagraphStyle("white", parent=s["cell_bold"], textColor=colors.white, alignment=TA_CENTER)
    header = [_p(sev.label_tr, white) for sev in Severity]
    values = [_p(str(counts[sev]), s["center"]) for sev in Severity]
    table = Table([header, values], colWidths=[34 * mm] * 5)
    style = [("GRID", (0, 0), (-1, -1), 0.5, BORDER), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for i, sev in enumerate(Severity):
        style.append(("BACKGROUND", (i, 0), (i, 0), SEVERITY_COLORS[sev]))
    table.setStyle(TableStyle(style))
    story += [table, Spacer(1, 4 * mm)]

    story.append(_p(
        "Güven düzeyleri: 'Doğrulandı' bulgular doğrudan gözlemlenmiştir. 'Olası' bulgular "
        "belirtilere dayanır ve manuel doğrulama gerektirir. 'Bilgi amaçlı' bulgular bir sorun "
        "değil, bağlam bilgisidir.", s["small"]))
    return story


def _scope(scan: ScanResult, s) -> list:
    story = [_p("2. Kapsam ve Yöntem", s["h1"]),
             _p("Aşağıdaki kontroller hedefe dışarıdan, yalnızca yapılandırma bilgilerini "
                "okuyarak uygulanmıştır.", s["body"]), Spacer(1, 3 * mm)]
    rows = [[_p(h, s["cell_bold"]) for h in ("Kontrol", "Durum", "Bulgu", "Süre", "Not")]]
    for check in scan.checks:
        status = ParagraphStyle("st", parent=s["cell_bold"], textColor=STATUS_COLORS[check.status])
        rows.append([
            _p(CHECK_LABELS_TR.get(check.check_name, check.check_name), s["cell"]),
            _p(check.status.label_tr, status),
            _p(str(len(check.findings)), s["cell"]),
            _p(f"{check.duration_seconds:.1f} sn", s["cell"]),
            _p(check.message or "-", s["cell"]),
        ])
    story += [_grid_table(rows, [34 * mm, 34 * mm, 15 * mm, 15 * mm, 72 * mm]),
              Spacer(1, 4 * mm), _p("Puanlama yöntemi", s["h2"]), _p(METHODOLOGY_TR, s["body"])]
    return story


def _findings_overview(findings: list[Finding], s) -> list:
    story = [_p("3. Bulgu Özeti", s["h1"])]
    if not findings:
        return story + [_p("Taranan kontrollerde bulgu tespit edilmedi.", s["body"])]
    rows = [[_p(h, s["cell_bold"]) for h in ("Kod", "Bulgu", "Risk", "Güven")]]
    for f in findings:
        sev = ParagraphStyle("sv", parent=s["cell_bold"], textColor=SEVERITY_COLORS[f.severity])
        rows.append([_p(f.id, s["cell"]), _p(f.title, s["cell"]), _p(f.severity.label_tr, sev),
                     _p(f.confidence.label_tr, s["cell"])])
    return story + [_grid_table(rows, [20 * mm, 92 * mm, 20 * mm, 38 * mm])]


def _finding_detail(f: Finding, s) -> list:
    color = SEVERITY_COLORS[f.severity]
    head = Table([[_p(f"{f.id}  ·  {f.title}", ParagraphStyle(
        "fh", parent=s["cell_bold"], textColor=colors.white, fontSize=9.5, leading=12))]],
        colWidths=[170 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color),
                              ("TOPPADDING", (0, 0), (-1, -1), 5),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    rows = [
        ["Kategori", f.category],
        ["Risk seviyesi", f.severity.label_tr],
        ["Güven düzeyi", f.confidence.label_tr],
        ["Kanıt", f.evidence],
    ]
    if f.description:
        rows.append(["Açıklama", f.description])
    if f.recommendation:
        rows.append(["Öneri", f.recommendation])
    if f.references:
        rows.append(["Kaynaklar", "\n".join(f.references)])
    body = _grid_table([[_p(k, s["cell_bold"]), _p(v, s["cell"])] for k, v in rows],
                       [32 * mm, 138 * mm], header=False)
    parts = [head, body]
    if f.confidence is Confidence.PROBABLE:
        parts.append(_p("Not: Bu bulgu doğrulanmamıştır ve kesin bir güvenlik açığı olarak "
                        "değerlendirilmemelidir. Manuel doğrulama önerilir.", s["small"]))
    # KeepTogether: bulgunun başlığı bir sayfada, içeriği diğer sayfada kalmasın
    return [KeepTogether(parts), Spacer(1, 5 * mm)]


def _technical_details(scan: ScanResult, s) -> list:
    labels = {
        "tls": {"subject": "Sertifika sahibi", "issuer": "Sertifika sağlayıcı", "not_after": "Bitiş",
                "days_left": "Kalan gün", "key": "Anahtar", "signature_algorithm": "İmza algoritması",
                "protocol": "Anlaşılan protokol", "cipher": "Şifre takımı",
                "legacy_protocols": "Eski protokoller", "san": "Kapsanan adlar"},
        "dns": {"a": "A", "aaaa": "AAAA", "ns": "NS", "mx": "MX", "spf": "SPF", "dmarc": "DMARC",
                "caa": "CAA", "dnssec": "DNSSEC", "failed_queries": "Başarısız sorgular"},
        "ports": {"ip": "Kontrol edilen IP", "ports": "Port durumları"},
    }
    story = [_p("5. Teknik Ayrıntılar", s["h1"])]
    any_details = False
    for check in scan.checks:
        if not check.details or check.check_name not in labels:
            continue
        any_details = True
        story.append(_p(CHECK_LABELS_TR.get(check.check_name, check.check_name), s["h2"]))
        rows = []
        for key, label in labels[check.check_name].items():
            if key in check.details:
                rows.append([_p(label, s["cell_bold"]), _p(_detail_text(check.details[key]), s["cell"])])
        if rows:
            story.append(_grid_table(rows, [45 * mm, 125 * mm], header=False))
    if not any_details:
        story.append(_p("Gösterilecek teknik ayrıntı yok.", s["body"]))
    return story


def _detail_text(value) -> str:
    if value is None:
        return "sorgulanamadı"
    if isinstance(value, bool):
        return "etkin" if value else "etkin değil"
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items()) or "-"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) or "yok"
    return str(value)


def _limitations(s) -> list:
    story = [_p("6. Sınırlamalar ve Yasal Uyarı", s["h1"])]
    for item in LIMITATIONS_TR:
        story.append(_p(f"•  {item}", s["body"]))
        story.append(Spacer(1, 1.5 * mm))
    return story


def _on_page(canvas, doc) -> None:
    """Her sayfaya üst/alt bilgi çizer (kapak hariç)."""
    if doc.page == 1:
        return
    canvas.saveState()
    canvas.setFont(FONT, 7.5)
    canvas.setFillColor(MUTED)
    width, height = A4
    canvas.drawString(20 * mm, height - 12 * mm, f"Sefalet Security Scanner · {doc.sefalet_target}")
    canvas.drawRightString(width - 20 * mm, height - 12 * mm, "GİZLİ: Yalnızca yetkili kişiler içindir")
    canvas.drawString(20 * mm, 10 * mm, f"Tarama kimliği: {doc.sefalet_scan_id}")
    canvas.drawRightString(width - 20 * mm, 10 * mm, f"Sayfa {doc.page}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Ana fonksiyon
# ---------------------------------------------------------------------------


def build_story(scan: ScanResult) -> list:
    """Raporun tüm parçalarını sırayla döndürür."""
    _register_fonts()
    s = _styles()
    findings = scan.all_findings()
    story = _cover(scan, s) + _executive_summary(scan, s) + [Spacer(1, 6 * mm)] + _scope(scan, s)
    story += [PageBreak()] + _findings_overview(findings, s)
    if findings:
        story += [PageBreak(), _p("4. Detaylı Bulgular", s["h1"])]
        for f in findings:
            story += _finding_detail(f, s)
    story += [PageBreak()] + _technical_details(scan, s) + [Spacer(1, 6 * mm)] + _limitations(s)
    return story


def write_pdf(scan: ScanResult, path: Path) -> Path:
    """PDF raporu üretir ve dosya yolunu döndürür (atomik yazma).

    Raises:
        OSError: Dosya yazılamazsa.
        FileNotFoundError: Fontlar bulunamazsa.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_", suffix=".pdf")
    os.close(fd)
    try:
        doc = SimpleDocTemplate(
            tmp_name, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=20 * mm, bottomMargin=18 * mm,
            title=f"Güvenlik Yapılandırma Raporu - {scan.target}",
            author=f"Sefalet Security Scanner {__version__}",
            subject="Güvenlik yapılandırma analizi",
        )
        doc.sefalet_target = scan.target
        doc.sefalet_scan_id = scan.scan_id
        doc.build(build_story(scan), onFirstPage=_on_page, onLaterPages=_on_page)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return path
