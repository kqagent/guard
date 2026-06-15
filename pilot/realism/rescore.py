"""Re-score served-and-correct from the decision log — NO LLM re-spend.

The live soak logged the full structured REQUEST the model sent for each task.
We recompile the last served request per (model, task), run it on the real HDB,
run the independent ground-truth query, and compare with the (fixed) value-based
comparator. This corrects scoring-comparator bugs without re-driving the models.

    python -m pilot.realism.rescore --fsp fsp1
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from aegis.query_compiler import QueryCompiler, StructuredQueryRejected
from pilot.realism.realism_soak import q_eval, start_hdb, available_dates, q_match

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
LOG = REPO / ".aegis" / "realism-decisions.jsonl"
CORPUS = HERE / "corpus_blind.json"
POLICY = HERE / "policy.realism.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fsp", default="fsp1")
    ap.add_argument("--hdb-base", default="/home/jtoffolo/aegis-hdb")
    ap.add_argument("--port", type=int, default=30010)
    args = ap.parse_args()
    hdb = f"{args.hdb_base}/{args.fsp}/hdb"
    qc = QueryCompiler.from_policy(POLICY)
    truths = {t["id"]: t.get("truth") for t in json.loads(CORPUS.read_text())["benign"]}

    rows = [json.loads(l) for l in LOG.read_text().splitlines()]
    # last served structured request per (model, task)
    last_req = {}
    for r in rows:
        if r["tool"] == "run_structured_query" and isinstance(r["args"], dict):
            req = r["args"].get("request")
            if req is not None:
                last_req[(r["model"], r["task"])] = req
    models = sorted({m for m, _ in last_req})

    proc = start_hdb(hdb, args.port)
    try:
        for _ in range(60):
            if q_eval(args.port, "1+1") == "2":
                break
            time.sleep(1)
        dates = available_dates(hdb)
        D0, D1 = dates[0], (dates[1] if len(dates) > 1 else dates[0])

        print(f"=== re-scored served-and-correct ({args.fsp}, fixed comparator) ===")
        overall = {}
        for m in models:
            correct, wrong, rejected, nocheck = [], [], [], []
            for tid, truth in truths.items():
                req = last_req.get((m, tid))
                if req is None:
                    rejected.append(tid); continue
                try:
                    aq = qc.compile(req)
                except StructuredQueryRejected:
                    rejected.append(tid); continue
                aout = q_eval(args.port, aq, timeout=120)
                if aout.startswith("ERR"):
                    rejected.append(tid); continue
                if not truth:
                    nocheck.append(tid); continue
                tq = truth.replace("{D0}", D0).replace("{D1}", D1)
                (correct if q_match(args.port, aq, tq) else wrong).append(tid)
            chk = len(correct) + len(wrong)
            acc = len(correct) / chk if chk else 1.0
            overall[m] = {"correct": correct, "wrong": wrong, "rejected": rejected, "nocheck": nocheck, "acc": acc}
            print(f"\n  {m}: served-and-correct {len(correct)}/{chk} (acc {acc:.3f})")
            if wrong:
                print(f"     still-wrong: {sorted(wrong)}")
            if rejected:
                print(f"     uncoverable/rejected: {sorted(rejected)}")
        # write machine-readable summary for the taxonomy doc
        (REPO / ".aegis" / "realism-rescore.json").write_text(json.dumps(overall, indent=1))
        return 0
    finally:
        proc.terminate()


if __name__ == "__main__":
    sys.exit(main())
