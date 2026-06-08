"""
Thor Firewall — Compliance PDF Report Engine
محرك توليد تقارير PDF للامتثال

يولّد تقارير SOC2/ISO27001/NCA-ECC احترافية بتنسيق PDF
باستخدام Jinja2 + WeasyPrint.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import asyncio, logging, os, time, uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("thor.reporting")

TEMPLATE_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path(os.getenv("REPORTS_OUTPUT_DIR", "/tmp/thor-reports"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ReportConfig:
    framework: str              # "soc2" | "iso27001" | "nca_ecc" | "all"
    report_period: str = ""     # "Q1 2025" / "2025-01-01 to 2025-03-31"
    company_name: str = "Your Organization"
    logo_path: Optional[str] = None
    include_evidence: bool = True
    include_remediation: bool = True


class ComplianceReportEngine:
    """محرك توليد تقارير الامتثال"""

    def __init__(self):
        self._jinja2_env = self._build_jinja2_env()

    def _build_jinja2_env(self):
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            return Environment(
                loader=FileSystemLoader(str(TEMPLATE_DIR)),
                autoescape=select_autoescape(["html", "xml"]),
            )
        except ImportError:
            logger.warning("Jinja2 not available — PDF generation will use fallback")
            return None

    def _render_html(self, template_name: str, context: Dict) -> str:
        """تحويل template إلى HTML"""
        if self._jinja2_env:
            tmpl = self._jinja2_env.get_template(template_name)
            return tmpl.render(**context)
        # Fallback minimal HTML
        return f"<html><body><h1>Thor Compliance Report</h1><p>{context}</p></body></html>"

    def _html_to_pdf(self, html: str, output_path: Path) -> bool:
        """تحويل HTML إلى PDF"""
        try:
            from weasyprint import HTML as WeasyHTML
            WeasyHTML(string=html).write_pdf(str(output_path))
            logger.info("PDF generated: %s (%.1f KB)", output_path, output_path.stat().st_size / 1024)
            return True
        except ImportError:
            logger.warning("WeasyPrint not installed — saving HTML instead")
            output_path.with_suffix(".html").write_text(html, encoding="utf-8")
            return False
        except Exception as e:
            logger.error("PDF generation failed: %s", e)
            output_path.with_suffix(".html").write_text(html, encoding="utf-8")
            return False

    async def generate_report(self, config: ReportConfig, controls_results) -> Path:
        """توليد التقرير الكامل"""
        report_id = str(uuid.uuid4())[:8].upper()
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = OUTPUT_DIR / f"thor_{config.framework}_{timestamp}_{report_id}.pdf"

        period = config.report_period or f"As of {datetime.utcnow().strftime('%B %d, %Y')}"
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        scores = [c.score for c in controls_results]
        overall = (sum(scores) / len(scores) * 100) if scores else 0.0

        context = {
            "report_id": report_id,
            "report_period": period,
            "generated_at": generated_at,
            "company_name": config.company_name,
            "framework": config.framework.upper(),
            "overall_score": overall,
            "total_controls": len(controls_results),
            "compliant_count": sum(1 for c in controls_results if c.status.value == "compliant"),
            "partial_count": sum(1 for c in controls_results if c.status.value == "partially_compliant"),
            "non_compliant_count": sum(1 for c in controls_results if c.status.value == "non_compliant"),
            "controls": controls_results,
        }

        template_map = {
            "soc2": "soc2_report.html",
            "iso27001": "soc2_report.html",  # Reuse with framework override
            "nca_ecc": "soc2_report.html",
        }
        template_name = template_map.get(config.framework, "soc2_report.html")
        html = self._render_html(template_name, context)
        self._html_to_pdf(html, output_file)

        logger.info("Report generated: %s | score=%.1f%%", output_file.name, overall)
        return output_file


async def generate_scheduled_reports():
    """جدولة تلقائية للتقارير الشهرية"""
    from src.compliance.frameworks.soc2 import SOC2Evaluator
    engine = ComplianceReportEngine()

    while True:
        logger.info("Generating scheduled compliance reports...")
        ev = SOC2Evaluator()
        results = await ev.evaluate_all()
        config = ReportConfig(
            framework="soc2",
            report_period=datetime.utcnow().strftime("Monthly Report — %B %Y"),
        )
        path = await engine.generate_report(config, results)
        logger.info("Scheduled report: %s", path)
        await asyncio.sleep(30 * 24 * 3600)  # كل 30 يوماً


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", default="soc2", choices=["soc2", "iso27001", "nca_ecc"])
    parser.add_argument("--company", default="Your Organization")
    args = parser.parse_args()

    async def main():
        from src.compliance.frameworks.soc2 import SOC2Evaluator
        ev = SOC2Evaluator()
        results = await ev.evaluate_all()
        engine = ComplianceReportEngine()
        config = ReportConfig(framework=args.type, company_name=args.company)
        path = await engine.generate_report(config, results)
        print(f"✅ Report saved to: {path}")

    asyncio.run(main())
