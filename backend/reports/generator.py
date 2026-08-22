"""
backend/reports/generator.py
=============================
Post-incident report generation engine for the RDRS system.

This module generates structured post-incident analysis reports in three formats:
  - **JSON** — Machine-readable full report with all event data.
  - **CSV**  — Tabular file event timeline for spreadsheet analysis.
  - **PDF**  — Professional SOC-ready report via Jinja2 → HTML → reportlab.

Report Contents:
  - Executive summary (incident metadata, peak threat score, response mode)
  - File event timeline (paginated in PDF, full in JSON/CSV)
  - Suspect process metadata at incident time
  - Threat score breakdown by detector
  - Remediation recommendations (actionable, tiered by severity)
  - Report integrity SHA-256 hash

Output Location:
    data/reports/<incident_id>/
        ├── report.json
        ├── report.csv
        ├── report.pdf
        └── manifest.json   ← Index file read by GET /reports

Usage:
    generator = ReportGenerator(db=async_session)
    report_out = await generator.generate(
        incident=incident_orm,
        formats=["json", "csv", "pdf"],
        include_event_timeline=True,
        include_process_metadata=True,
        include_remediation=True,
    )
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import ReportOut
from backend.core.logging import audit_log, get_logger
from backend.database.models import FileEvent, Incident, ProcessSnapshot

_log = get_logger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_REPORTS_DIR = _PROJECT_ROOT / "data" / "reports"
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# ---------------------------------------------------------------------------
# Remediation recommendations (severity-tiered)
# ---------------------------------------------------------------------------
_REMEDIATION_STEPS: dict[str, list[str]] = {
    "IMMEDIATE": [
        "ISOLATE the affected host from the network immediately to prevent lateral movement.",
        "PRESERVE volatile evidence: capture memory dump and running process list before rebooting.",
        "IDENTIFY the patient-zero process: review the suspect_process_name field in this report.",
        "REVOKE all active credentials and sessions for users on the affected system.",
        "NOTIFY the incident response team and begin the IR runbook.",
    ],
    "SHORT_TERM": [
        "RESTORE from the most recent clean backup (verify backup integrity before restoration).",
        "SCAN all connected network shares and mapped drives for encrypted file indicators.",
        "REVIEW shadow copy / VSS status — confirm deletion was not completed.",
        "AUDIT Active Directory for unauthorized privilege escalation events.",
        "PATCH all outstanding CVEs on the affected host and network segment.",
    ],
    "LONG_TERM": [
        "IMPLEMENT application allowlisting to prevent unsigned executable execution.",
        "ENFORCE the 3-2-1 backup rule: 3 copies, 2 media types, 1 off-site.",
        "DEPLOY endpoint detection with behavioral analysis on all workstations.",
        "CONDUCT a tabletop exercise simulating a ransomware event within 30 days.",
        "REVIEW and harden email gateway rules to block macro-enabled documents.",
        "TRAIN users on phishing recognition — the primary ransomware delivery vector.",
    ],
}


# ===========================================================================
# Hash Utility
# ===========================================================================


def _sha256_file(path: Path) -> str:
    """
    Compute the SHA-256 hash of a file.

    Args:
        path: File to hash.

    Returns:
        str: Hex digest of the file contents.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ===========================================================================
# Report Generator
# ===========================================================================


class ReportGenerator:
    """
    Generates multi-format post-incident reports from RDRS database records.

    Args:
        db: An open async SQLAlchemy session used to fetch related records.

    Example:
        generator = ReportGenerator(db=session)
        out = await generator.generate(
            incident=incident,
            formats=["json", "csv", "pdf"],
            include_event_timeline=True,
            include_process_metadata=True,
            include_remediation=True,
        )
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def generate(
        self,
        incident: Incident,
        formats: list[str],
        *,
        include_event_timeline: bool = True,
        include_process_metadata: bool = True,
        include_remediation: bool = True,
    ) -> ReportOut:
        """
        Orchestrate report generation for all requested formats.

        Fetches related FileEvent and ProcessSnapshot records, assembles the
        report data dict, and delegates to format-specific render methods.

        Args:
            incident:                 The ORM Incident record to report on.
            formats:                  List of output formats: 'json', 'csv', 'pdf'.
            include_event_timeline:   Include the FileEvent timeline section.
            include_process_metadata: Include ProcessSnapshot data.
            include_remediation:      Append remediation recommendations.

        Returns:
            ReportOut: Metadata of the generated report including file paths and hashes.
        """
        incident_id = str(incident.id)
        incident_dir = _REPORTS_DIR / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)

        # Fetch related records
        file_events: list[FileEvent] = []
        process_snapshots: list[ProcessSnapshot] = []

        if include_event_timeline:
            fe_result = await self._db.execute(
                select(FileEvent)
                .where(FileEvent.timestamp >= incident.timestamp)
                .order_by(FileEvent.timestamp.asc())
                .limit(500)
            )
            file_events = list(fe_result.scalars().all())

        if include_process_metadata and incident.suspect_process_pid:
            ps_result = await self._db.execute(
                select(ProcessSnapshot)
                .where(
                    ProcessSnapshot.pid == incident.suspect_process_pid,
                    ProcessSnapshot.timestamp >= incident.timestamp,
                )
                .order_by(ProcessSnapshot.timestamp.asc())
                .limit(50)
            )
            process_snapshots = list(ps_result.scalars().all())

        # Build report data dict
        report_data = self._build_report_dict(
            incident=incident,
            file_events=file_events,
            process_snapshots=process_snapshots,
            include_remediation=include_remediation,
        )

        # Generate each requested format
        file_paths: dict[str, str] = {}
        hashes: dict[str, str] = {}
        generated_formats: list[str] = []

        for fmt in formats:
            try:
                out_path = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._render_format,
                    fmt,
                    report_data,
                    incident_dir,
                )
                file_paths[fmt] = str(out_path)
                hashes[fmt] = _sha256_file(out_path)
                generated_formats.append(fmt)
                _log.debug(f"Generated {fmt.upper()} report | path={out_path}")
            except Exception as exc:
                _log.error(f"Failed to generate {fmt} report: {exc}")

        # Write manifest.json for the /reports list endpoint
        generated_at = datetime.now(timezone.utc)
        manifest = {
            "incident_id": incident_id,
            "formats_generated": generated_formats,
            "file_paths": file_paths,
            "generated_at": generated_at.isoformat(),
            "sha256_hashes": hashes,
            "incident_summary": {
                "threat_score": incident.threat_score,
                "severity_level": incident.severity_level,
                "timestamp": incident.timestamp.isoformat(),
                "response_mode": incident.response_mode,
            },
        }
        (incident_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        audit_log(
            action="REPORT_GENERATED",
            details={
                "incident_id": incident_id,
                "formats": generated_formats,
                "generated_at": generated_at.isoformat(),
            },
        )

        return ReportOut(
            incident_id=incident_id,
            formats_generated=generated_formats,
            file_paths=file_paths,
            generated_at=generated_at,
            sha256_hashes=hashes,
        )

    def _build_report_dict(
        self,
        incident: Incident,
        file_events: list[FileEvent],
        process_snapshots: list[ProcessSnapshot],
        include_remediation: bool,
    ) -> dict[str, Any]:
        """
        Assemble the complete report data dictionary.

        Args:
            incident:            The Incident ORM object.
            file_events:         Related FileEvent records.
            process_snapshots:   Related ProcessSnapshot records.
            include_remediation: Whether to include the remediation section.

        Returns:
            dict: Fully assembled report data ready for serialization.
        """
        event_timeline = [
            {
                "timestamp": fe.timestamp.isoformat(),
                "event_type": fe.event_type,
                "file_path": fe.file_path,
                "destination_path": fe.destination_path,
                "file_extension": fe.file_extension,
                "entropy_score": fe.entropy_score,
                "file_size_bytes": fe.file_size_bytes,
            }
            for fe in file_events
        ]

        process_data = [
            {
                "timestamp": ps.timestamp.isoformat(),
                "pid": ps.pid,
                "process_name": ps.process_name,
                "cpu_percent": ps.cpu_percent,
                "memory_mb": ps.memory_mb,
                "disk_write_bytes": ps.disk_write_bytes,
                "exe_path": ps.exe_path,
                "parent_pid": ps.parent_pid,
                "parent_name": ps.parent_name,
                "is_flagged": ps.is_flagged,
                "flag_reason": ps.flag_reason,
            }
            for ps in process_snapshots
        ]

        report: dict[str, Any] = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "rdrs_version": "1.0.0",
                "report_type": "POST_INCIDENT_ANALYSIS",
            },
            "executive_summary": {
                "incident_id": str(incident.id),
                "incident_timestamp": incident.timestamp.isoformat(),
                "peak_threat_score": incident.threat_score,
                "severity_level": incident.severity_level,
                "response_mode": incident.response_mode,
                "resolved": incident.resolved,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                "affected_files_count": incident.affected_files_count,
                "affected_extensions": incident.affected_extensions,
                "quarantine_path": incident.quarantine_path,
                "suspect_process_pid": incident.suspect_process_pid,
                "suspect_process_name": incident.suspect_process_name,
                "operator_notes": incident.notes,
            },
            "event_timeline": event_timeline,
            "process_metadata": process_data,
        }

        if include_remediation:
            report["remediation_recommendations"] = _REMEDIATION_STEPS

        return report

    def _render_format(
        self,
        fmt: str,
        data: dict[str, Any],
        out_dir: Path,
    ) -> Path:
        """
        Dispatch rendering to the appropriate format handler.

        Args:
            fmt:     Output format string: 'json', 'csv', or 'pdf'.
            data:    The assembled report data dict.
            out_dir: Directory to write the output file into.

        Returns:
            Path: The path to the rendered output file.

        Raises:
            ValueError: If the format is unsupported.
        """
        if fmt == "json":
            return self._render_json(data, out_dir)
        elif fmt == "csv":
            return self._render_csv(data, out_dir)
        elif fmt == "pdf":
            return self._render_pdf(data, out_dir)
        else:
            raise ValueError(f"Unsupported report format: {fmt}")

    # ------------------------------------------------------------------
    # JSON Renderer
    # ------------------------------------------------------------------

    def _render_json(self, data: dict[str, Any], out_dir: Path) -> Path:
        """
        Serialize the full report data to a pretty-printed JSON file.

        Args:
            data:    Report data dict.
            out_dir: Output directory.

        Returns:
            Path: Path to the generated JSON file.
        """
        out_path = out_dir / "report.json"
        out_path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        return out_path

    # ------------------------------------------------------------------
    # CSV Renderer
    # ------------------------------------------------------------------

    def _render_csv(self, data: dict[str, Any], out_dir: Path) -> Path:
        """
        Write the file event timeline as a CSV file for spreadsheet analysis.

        Args:
            data:    Report data dict.
            out_dir: Output directory.

        Returns:
            Path: Path to the generated CSV file.
        """
        out_path = out_dir / "report.csv"
        timeline: list[dict] = data.get("event_timeline", [])

        if not timeline:
            # Write a header-only CSV if no events
            out_path.write_text(
                "timestamp,event_type,file_path,destination_path,"
                "file_extension,entropy_score,file_size_bytes\n",
                encoding="utf-8",
            )
            return out_path

        fieldnames = [
            "timestamp", "event_type", "file_path", "destination_path",
            "file_extension", "entropy_score", "file_size_bytes",
        ]

        buf = StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(timeline)

        out_path.write_text(buf.getvalue(), encoding="utf-8")
        return out_path

    # ------------------------------------------------------------------
    # PDF Renderer
    # ------------------------------------------------------------------

    def _render_pdf(self, data: dict[str, Any], out_dir: Path) -> Path:
        """
        Generate a professional SOC analyst PDF report using reportlab.

        Layout sections:
          1. Header with RDRS branding and classification banner.
          2. Executive Summary table.
          3. Threat Score Breakdown.
          4. File Event Timeline table (up to 50 rows).
          5. Suspect Process table (if available).
          6. Remediation Recommendations (tiered).
          7. Report integrity hash footer.

        Args:
            data:    Report data dict.
            out_dir: Output directory.

        Returns:
            Path: Path to the generated PDF file.
        """
        out_path = out_dir / "report.pdf"
        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
            title="RDRS Post-Incident Analysis Report",
            author="RDRS Security Engine v1.0.0",
            subject="Ransomware Detection and Response System — Incident Report",
        )

        styles = getSampleStyleSheet()
        story: list = []

        # ---- Custom Styles ----
        title_style = ParagraphStyle(
            "RDRSTitle",
            parent=styles["Title"],
            fontSize=22,
            textColor=colors.HexColor("#0D1B2A"),
            spaceAfter=6,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "RDRSSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#E63946"),
            spaceAfter=2,
            fontName="Helvetica-Bold",
        )
        section_header_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading1"],
            fontSize=13,
            textColor=colors.HexColor("#1D3557"),
            spaceBefore=14,
            spaceAfter=6,
            fontName="Helvetica-Bold",
            borderPad=2,
        )
        body_style = ParagraphStyle(
            "RDRSBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1A1A2E"),
        )
        mono_style = ParagraphStyle(
            "Mono",
            parent=styles["Code"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#2C3E50"),
            backColor=colors.HexColor("#F8F9FA"),
        )
        banner_style = ParagraphStyle(
            "ClassBanner",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        caption_style = ParagraphStyle(
            "Caption",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#6C757D"),
            alignment=TA_CENTER,
        )

        summary = data.get("executive_summary", {})
        meta = data.get("report_metadata", {})
        score = summary.get("peak_threat_score", 0.0)

        # Severity color
        severity_colors = {
            "CRITICAL": colors.HexColor("#DC3545"),
            "HIGH": colors.HexColor("#FD7E14"),
            "MEDIUM": colors.HexColor("#FFC107"),
            "LOW": colors.HexColor("#28A745"),
            "NOMINAL": colors.HexColor("#17A2B8"),
        }
        sev = summary.get("severity_level", "NOMINAL")
        sev_color = severity_colors.get(sev, colors.gray)

        # ---- Classification Banner ----
        banner_data = [
            [Paragraph("⚠ RDRS INCIDENT REPORT — CONFIDENTIAL — INTERNAL USE ONLY ⚠", banner_style)]
        ]
        banner_table = Table(banner_data, colWidths=[doc.width])
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1B2A")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 0.3 * cm))

        # ---- Title Block ----
        story.append(Paragraph("Post-Incident Analysis Report", title_style))
        story.append(Paragraph(
            f"Ransomware Detection and Response System (RDRS) v{meta.get('rdrs_version', '1.0.0')}",
            subtitle_style,
        ))
        story.append(Paragraph(
            f"Generated: {meta.get('generated_at', 'N/A')} UTC",
            body_style,
        ))
        story.append(HRFlowable(
            width="100%", thickness=2, color=colors.HexColor("#E63946"), spaceAfter=8
        ))

        # ---- Executive Summary ----
        story.append(Paragraph("Executive Summary", section_header_style))

        exec_rows = [
            ["Field", "Value"],
            ["Incident ID", str(summary.get("incident_id", "N/A"))],
            ["Incident Timestamp", str(summary.get("incident_timestamp", "N/A"))],
            ["Peak Threat Score", f"{score:.1f} / 100.0"],
            ["Severity Level", sev],
            ["Response Mode", str(summary.get("response_mode", "N/A")).upper()],
            ["Affected Files", str(summary.get("affected_files_count", 0))],
            ["Affected Extensions", ", ".join(summary.get("affected_extensions") or []) or "—"],
            ["Suspect Process", str(summary.get("suspect_process_name") or "Unknown")],
            ["Suspect PID", str(summary.get("suspect_process_pid") or "Unknown")],
            ["Quarantine Path", str(summary.get("quarantine_path") or "N/A (simulation)")],
            ["Resolved", "Yes" if summary.get("resolved") else "No"],
        ]

        exec_table = Table(
            exec_rows,
            colWidths=[5.5 * cm, doc.width - 5.5 * cm],
        )
        exec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D3557")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F3F5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DEE2E6")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            # Highlight severity cell
            ("BACKGROUND", (1, 4), (1, 4), sev_color),
            ("TEXTCOLOR", (1, 4), (1, 4), colors.white),
            ("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"),
        ]))
        story.append(exec_table)

        # ---- File Event Timeline ----
        timeline = data.get("event_timeline", [])
        if timeline:
            story.append(Paragraph("File Event Timeline", section_header_style))
            story.append(Paragraph(
                f"Showing {min(len(timeline), 50)} of {len(timeline)} events captured "
                f"during the incident window.",
                body_style,
            ))
            story.append(Spacer(1, 0.2 * cm))

            tl_rows = [["Timestamp", "Type", "Extension", "Entropy", "Path"]]
            for ev in timeline[:50]:
                tl_rows.append([
                    ev.get("timestamp", "")[:19].replace("T", " "),
                    ev.get("event_type", "").upper(),
                    ev.get("file_extension") or "—",
                    f"{ev.get('entropy_score', 0.0):.2f}" if ev.get("entropy_score") else "—",
                    Paragraph(
                        str(ev.get("file_path", ""))[-60:],
                        ParagraphStyle("TLPath", parent=mono_style, fontSize=7),
                    ),
                ])

            col_widths = [3.8 * cm, 2.2 * cm, 2.0 * cm, 1.8 * cm, doc.width - 9.8 * cm]
            tl_table = Table(tl_rows, colWidths=col_widths, repeatRows=1)
            tl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#457B9D")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(tl_table)

        # ---- Process Metadata ----
        procs = data.get("process_metadata", [])
        if procs:
            story.append(Paragraph("Suspect Process Snapshots", section_header_style))
            proc_rows = [["PID", "Name", "CPU%", "Mem (MB)", "Disk Writes", "Flagged"]]
            for ps in procs[:20]:
                proc_rows.append([
                    str(ps.get("pid", "")),
                    str(ps.get("process_name", "")),
                    f"{ps.get('cpu_percent', 0.0):.1f}",
                    f"{ps.get('memory_mb', 0.0):.1f}",
                    f"{ps.get('disk_write_bytes', 0):,}",
                    "YES" if ps.get("is_flagged") else "no",
                ])

            proc_col_widths = [1.8 * cm, 3.5 * cm, 2.0 * cm, 2.5 * cm, 3.0 * cm, 2.0 * cm]
            proc_table = Table(proc_rows, colWidths=proc_col_widths, repeatRows=1)
            proc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D3557")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FFF3CD")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(proc_table)

        # ---- Remediation Recommendations ----
        if "remediation_recommendations" in data:
            story.append(Paragraph("Remediation Recommendations", section_header_style))
            remed = data["remediation_recommendations"]

            tier_colors = {
                "IMMEDIATE": colors.HexColor("#DC3545"),
                "SHORT_TERM": colors.HexColor("#FD7E14"),
                "LONG_TERM": colors.HexColor("#1D3557"),
            }
            tier_labels = {
                "IMMEDIATE": "🔴 IMMEDIATE ACTIONS (< 1 hour)",
                "SHORT_TERM": "🟠 SHORT-TERM ACTIONS (< 24 hours)",
                "LONG_TERM": "🔵 LONG-TERM HARDENING (< 30 days)",
            }

            for tier_key, tier_label in tier_labels.items():
                steps = remed.get(tier_key, [])
                if not steps:
                    continue

                tier_style = ParagraphStyle(
                    f"Tier_{tier_key}",
                    parent=body_style,
                    textColor=tier_colors.get(tier_key, colors.black),
                    fontName="Helvetica-Bold",
                    fontSize=10,
                    spaceBefore=8,
                    spaceAfter=4,
                )
                story.append(Paragraph(tier_label, tier_style))

                for i, step in enumerate(steps, 1):
                    story.append(Paragraph(
                        f"{i}. {step}",
                        ParagraphStyle("Step", parent=body_style, leftIndent=15, spaceAfter=3),
                    ))

        # ---- Footer ----
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#DEE2E6")))
        story.append(Paragraph(
            f"Generated by RDRS v1.0.0 • {meta.get('generated_at', '')} UTC • "
            f"CONFIDENTIAL — INTERNAL USE ONLY",
            caption_style,
        ))

        doc.build(story)
        return out_path
