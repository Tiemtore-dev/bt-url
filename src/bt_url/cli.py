"""CLI : bt-url <url> [--json] [--no-ml] | --file urls.txt"""

import argparse
import asyncio
import json
import logging
import sys

from bt_url.analyzer import URLAnalyzer

EXIT_CODES = {"CONFIRMED_MALICIOUS": 2, "HIGH_RISK": 2, "SUSPICIOUS": 1, "CLEAN": 0, "UNKNOWN": 3}


def _print_human(r: dict) -> None:
    risk = r["risk"]
    score = "n/a" if risk["score"] is None else f"{risk['score']:.2f}"
    print(f"\n{r['target']['url']}")
    print(f"  Verdict : {risk['verdict']}   score={score}   confiance={risk['confidence']:.2f}")
    for reason in risk["reasons"]:
        print(f"   - {reason}")
    for s in r["sources"]:
        mark = " (autoritaire)" if s["authoritative"] else ""
        extra = s["error"] or s["detections"] or ""
        print(f"  [{s['verdict']:<10}] {s['name']}{mark} {extra}")
    ml = r["ml"]
    if ml.get("label"):
        print(f"  ML : {ml['label']} ({ml['score']:.2f}, seuil {ml['threshold']:.2f})")
    for note in r.get("notes", []):
        print(f"  ! {note}")


async def _run(urls: list[str], args) -> list[dict]:
    analyzer = URLAnalyzer()
    out = []
    for u in urls:
        try:
            out.append(await analyzer.analyze(u, use_ml=not args.no_ml))
        except ValueError as e:
            print(f"Ignorée : {e}", file=sys.stderr)
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bt-url", description="Analyse d'URL (TI + ML)")
    p.add_argument("url", nargs="?", help="URL à analyser")
    p.add_argument("--file", "-f", help="fichier d'URLs (une par ligne)")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    p.add_argument("--no-ml", action="store_true", help="désactive le modèle ML")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            urls += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not urls:
        p.error("fournir une URL ou --file")

    results = asyncio.run(_run(urls, args))
    if args.json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2, ensure_ascii=False))
    else:
        for r in results:
            _print_human(r)
    return max((EXIT_CODES.get(r["risk"]["verdict"], 0) for r in results), default=0)


if __name__ == "__main__":
    sys.exit(main())
