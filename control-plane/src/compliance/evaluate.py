"""
Thor Firewall — Compliance Evaluation Entry Point
نقطة دخول لتقييم الامتثال عبر جميع الأطر

الاستخدام:
  python -m src.compliance.evaluate --frameworks soc2,iso27001,nca_ecc
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import asyncio, argparse, json, logging, sys
from typing import List

logger = logging.getLogger("thor.compliance")


async def run_evaluation(frameworks: List[str]) -> dict:
    from src.compliance.frameworks.soc2 import SOC2Evaluator
    from src.compliance.frameworks.iso27001 import ISO27001Evaluator
    from src.compliance.frameworks.nca_ecc import NCAECCEvaluator

    results = {}

    if "soc2" in frameworks:
        ev = SOC2Evaluator()
        r = await ev.evaluate_all()
        results["soc2"] = {
            "summary": ev.generate_summary(r),
            "controls": [{"id": c.control_id, "name": c.control_name,
                          "status": c.status.value, "score": c.score} for c in r],
        }
        logger.info("SOC2 score: %.1f%%", results["soc2"]["summary"]["overall_score"])

    if "iso27001" in frameworks:
        ev = ISO27001Evaluator()
        r = await ev.evaluate_all()
        scores = [c.score for c in r]
        avg = sum(scores) / len(scores) * 100 if scores else 0
        results["iso27001"] = {
            "summary": {"overall_score": round(avg, 1), "total_controls": len(r)},
            "controls": [{"id": c.control_id, "name": c.control_name,
                          "status": c.status.value, "score": c.score} for c in r],
        }
        logger.info("ISO27001 score: %.1f%%", avg)

    if "nca_ecc" in frameworks:
        ev = NCAECCEvaluator()
        r = await ev.evaluate_all()
        scores = [c.score for c in r]
        avg = sum(scores) / len(scores) * 100 if scores else 0
        results["nca_ecc"] = {
            "summary": {"overall_score": round(avg, 1), "total_controls": len(r)},
            "controls": [{"id": c.control_id, "name": c.control_name,
                          "status": c.status.value, "score": c.score} for c in r],
        }
        logger.info("NCA-ECC score: %.1f%%", avg)

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--frameworks", default="soc2,iso27001,nca_ecc")
    parser.add_argument("--output", default="compliance_results.json")
    args = parser.parse_args()

    frameworks = [f.strip() for f in args.frameworks.split(",")]
    results = asyncio.run(run_evaluation(frameworks))

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Print summary table
    print("\n" + "="*60)
    print("COMPLIANCE EVALUATION SUMMARY")
    print("="*60)
    for fw, data in results.items():
        score = data["summary"]["overall_score"]
        total = data["summary"]["total_controls"]
        icon = "✅" if score >= 90 else "⚠️" if score >= 70 else "❌"
        print(f"{icon}  {fw.upper():12} {score:5.1f}%  ({total} controls)")
    print("="*60)
