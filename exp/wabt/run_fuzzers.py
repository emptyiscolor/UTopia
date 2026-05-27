#!/usr/bin/env python3
"""Run UTopia-generated fuzzers in parallel, save per-fuzzer logs, and collect coverage."""

import argparse
import csv
import io
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


def run_single_fuzzer(fuzzer_path, corpus_dir, log_dir, timeout, max_runs, extra_args):
    """Run a single fuzzer, stream stderr to a log file, return coverage stats."""
    name = Path(fuzzer_path).name
    corpus = Path(corpus_dir) / name
    corpus.mkdir(parents=True, exist_ok=True)

    log_path = Path(log_dir) / name
    log_path.mkdir(parents=True, exist_ok=True)
    fuzz_log = log_path / "fuzz.log"

    cmd = [str(fuzzer_path), str(corpus)]
    if max_runs is not None:
        cmd.append(f"-runs={max_runs}")
    if timeout:
        cmd.append(f"-max_total_time={timeout}")
    cmd.extend(extra_args)

    max_cov = 0
    max_ft = 0
    last_cov = 0
    last_ft = 0
    exit_code = -1
    try:
        with open(fuzz_log, "w") as lf:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,
            )
            for line in proc.stderr:
                lf.write(line)
                m = re.search(r"\bcov:\s*(\d+)", line)
                if m:
                    val = int(m.group(1))
                    max_cov = max(max_cov, val)
                    last_cov = val
                m = re.search(r"\bft:\s*(\d+)", line)
                if m:
                    val = int(m.group(1))
                    max_ft = max(max_ft, val)
                    last_ft = val
            exit_code = proc.wait()
    except Exception as e:
        with open(fuzz_log, "a") as lf:
            lf.write(f"ERROR: {e}\n")

    return {
        "name": name,
        "edge_cov": last_cov,
        "max_edge_cov": max_cov,
        "feature_cov": last_ft,
        "max_feature_cov": max_ft,
        "corpus_size": len(list(corpus.iterdir())) if corpus.exists() else 0,
        "exit_code": exit_code,
        "log_path": str(fuzz_log),
    }


def run_single_coverage(fuzzer_path, corpus_dir, log_dir, extra_args):
    """Run a fuzzer with -print_coverage=1, save output, return parsed results."""
    name = Path(fuzzer_path).name
    corpus = Path(corpus_dir) / name

    log_path = Path(log_dir) / name
    log_path.mkdir(parents=True, exist_ok=True)
    cov_log = log_path / "coverage.log"

    cmd = [str(fuzzer_path), "-print_coverage=1", "-runs=0"]
    if corpus.exists() and any(corpus.iterdir()):
        cmd.append(str(corpus))
    cmd.extend(extra_args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stderr
    except subprocess.TimeoutExpired:
        output = "ERROR: timeout collecting coverage\n"
    except Exception as e:
        output = f"ERROR: {e}\n"

    with open(cov_log, "w") as f:
        f.write(output)

    covered = []
    uncovered = []
    for line in output.splitlines():
        m_cov = re.match(
            r"COVERED_FUNC:\s+hits:\s*(\d+)\s+edges:\s*(\d+)/(\d+)\s+(.*)", line
        )
        m_uncov = re.match(
            r"UNCOVERED_FUNC:\s+hits:\s*(\d+)\s+edges:\s*(\d+)/(\d+)\s+(.*)", line
        )
        if m_cov:
            covered.append({
                "hits": int(m_cov.group(1)),
                "cov_edges": int(m_cov.group(2)),
                "total_edges": int(m_cov.group(3)),
                "func": m_cov.group(4).strip(),
            })
        elif m_uncov:
            uncovered.append({
                "hits": 0,
                "cov_edges": int(m_uncov.group(2)),
                "total_edges": int(m_uncov.group(3)),
                "func": m_uncov.group(4).strip(),
            })

    return {
        "name": name,
        "covered": covered,
        "uncovered": uncovered,
        "log_path": str(cov_log),
    }


def discover_fuzzers(fuzzers_dir):
    """Find all executable fuzzer binaries in the directory."""
    fuzzers = []
    for f in sorted(Path(fuzzers_dir).iterdir()):
        if f.is_file() and os.access(f, os.X_OK):
            fuzzers.append(f)
    return fuzzers


def write_overview_csv(results, cov_results, csv_path):
    """Write overview.csv with per-fuzzer edge coverage and optional function coverage."""
    cov_by_name = {r["name"]: r for r in cov_results} if cov_results else {}

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "fuzzer",
            "edge_cov",
            "max_edge_cov",
            "feature_cov",
            "max_feature_cov",
            "corpus_size",
            "exit_code",
            "covered_funcs",
            "uncovered_funcs",
            "func_cov_pct",
        ])
        for r in sorted(results, key=lambda x: x["name"]):
            cr = cov_by_name.get(r["name"])
            n_cov = len(cr["covered"]) if cr else ""
            n_uncov = len(cr["uncovered"]) if cr else ""
            total = (n_cov + n_uncov) if cr else 0
            pct = f"{n_cov / total * 100:.1f}" if total > 0 else ""
            writer.writerow([
                r["name"],
                r["edge_cov"],
                r["max_edge_cov"],
                r["feature_cov"],
                r["max_feature_cov"],
                r["corpus_size"],
                r["exit_code"],
                n_cov,
                n_uncov,
                pct,
            ])


def print_summary(results):
    """Print a summary table of fuzzing results."""
    print("\n" + "=" * 80)
    print(f"{'FUZZER':<50} {'EDGES':>7} {'FEATURES':>10} {'CORPUS':>8}")
    print("-" * 80)
    total_cov = 0
    for r in sorted(results, key=lambda x: x["name"]):
        print(
            f"{r['name']:<50} {r['edge_cov']:>7} "
            f"{r['feature_cov']:>10} {r['corpus_size']:>8}"
        )
        total_cov += r["edge_cov"]
    print("-" * 80)
    print(f"{'TOTAL (sum of individual edge cov)':<50} {total_cov:>7}")
    print("=" * 80)


def print_func_coverage(cov_results):
    """Print aggregated function coverage across all fuzzers."""
    all_covered = defaultdict(lambda: {"hits": 0, "cov_edges": 0, "total_edges": 0})
    all_uncovered = set()

    for r in cov_results:
        for f in r["covered"]:
            entry = all_covered[f["func"]]
            entry["hits"] += f["hits"]
            entry["cov_edges"] = max(entry["cov_edges"], f["cov_edges"])
            entry["total_edges"] = max(entry["total_edges"], f["total_edges"])
        for f in r["uncovered"]:
            all_uncovered.add(f["func"])

    all_uncovered -= set(all_covered.keys())

    def is_target_func(name):
        skip = [
            "google::protobuf::", "testing::", "std::", "AutoFuzz::",
            "__asan", "__sanitizer", "LLVMFuzzer",
        ]
        return not any(s in name for s in skip)

    target_covered = {k: v for k, v in all_covered.items() if is_target_func(k)}
    target_uncovered = {f for f in all_uncovered if is_target_func(f)}

    print("\n" + "=" * 80)
    print("FUNCTION COVERAGE REPORT")
    print("=" * 80)

    if target_covered:
        print(f"\n  COVERED ({len(target_covered)} target functions):")
        print(f"  {'HITS':>8}  {'EDGES':>8}  FUNCTION")
        print(f"  {'-'*8}  {'-'*8}  {'-'*50}")
        for func in sorted(
            target_covered, key=lambda f: target_covered[f]["hits"], reverse=True
        ):
            info = target_covered[func]
            edges = f"{info['cov_edges']}/{info['total_edges']}"
            print(f"  {info['hits']:>8}  {edges:>8}  {func}")

    if target_uncovered:
        print(f"\n  UNCOVERED ({len(target_uncovered)} target functions):")
        for func in sorted(target_uncovered):
            print(f"    {func}")

    total = len(target_covered) + len(target_uncovered)
    if total > 0:
        pct = len(target_covered) / total * 100
        print(f"\n  Target function coverage: {len(target_covered)}/{total} ({pct:.1f}%)")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Run UTopia-generated fuzzers in parallel, save logs, and collect coverage"
    )
    parser.add_argument(
        "fuzzers_dir",
        nargs="?",
        default="output/fuzzers",
        help="Directory containing fuzzer binaries (default: output/fuzzers)",
    )
    parser.add_argument(
        "--corpus-dir",
        default=None,
        help="Base dir for per-fuzzer corpus (default: <fuzzers_dir>/../corpus)",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help="Base dir for per-fuzzer logs and overview.csv (default: <fuzzers_dir>/../runlogs)",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=4,
        help="Number of fuzzers to run in parallel (default: 4)",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=60,
        help="Max fuzzing time per fuzzer in seconds (default: 60)",
    )
    parser.add_argument(
        "--runs", type=int, default=None,
        help="Max number of runs per fuzzer (default: unlimited, use timeout)",
    )
    parser.add_argument(
        "--print-coverage", action="store_true",
        help="After fuzzing, re-run with -print_coverage=1 to show function coverage",
    )
    parser.add_argument(
        "--coverage-only", action="store_true",
        help="Skip fuzzing, just run -print_coverage=1 on existing corpus",
    )
    parser.add_argument(
        "--filter", type=str, default=None,
        help="Only run fuzzers whose name contains this substring",
    )
    parser.add_argument(
        "extra_args", nargs="*",
        help="Extra arguments passed to each fuzzer (put after --)",
    )

    args = parser.parse_args()

    fuzzers_dir = Path(args.fuzzers_dir).resolve()
    fuzzers = discover_fuzzers(fuzzers_dir)
    if args.filter:
        fuzzers = [f for f in fuzzers if args.filter in f.name]
    if not fuzzers:
        print(f"No fuzzers found in {fuzzers_dir}", file=sys.stderr)
        sys.exit(1)

    # Derive output dirs relative to fuzzers_dir parent (e.g. output/)
    base_dir = fuzzers_dir.parent
    corpus_dir = Path(args.corpus_dir).resolve() if args.corpus_dir else base_dir / "corpus"
    log_dir = Path(args.log_dir).resolve() if args.log_dir else base_dir / "runlogs"
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"Fuzzers dir : {fuzzers_dir}")
    print(f"Corpus dir  : {corpus_dir}")
    print(f"Log dir     : {log_dir}")
    print(f"Found {len(fuzzers)} fuzzers\n")

    results = []
    cov_results = []

    # Phase 1: Fuzzing
    if not args.coverage_only:
        print(f"Fuzzing ({args.jobs} parallel, {args.timeout}s each)...\n")
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(
                    run_single_fuzzer,
                    str(f), str(corpus_dir), str(log_dir),
                    args.timeout, args.runs, args.extra_args,
                ): f
                for f in fuzzers
            }
            for future in as_completed(futures):
                r = future.result()
                status = "OK" if r["exit_code"] == 0 else f"exit={r['exit_code']}"
                print(
                    f"  [{status:>7}] {r['name']:<45} "
                    f"edges={r['edge_cov']:<6} "
                    f"ft={r['feature_cov']:<6} "
                    f"corpus={r['corpus_size']}"
                )
                results.append(r)

        print_summary(results)

    # Phase 2: Function coverage
    if args.print_coverage or args.coverage_only:
        print("\nCollecting function coverage (-print_coverage=1)...\n")
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(
                    run_single_coverage,
                    str(f), str(corpus_dir), str(log_dir), args.extra_args,
                ): f
                for f in fuzzers
            }
            for future in as_completed(futures):
                r = future.result()
                print(
                    f"  {r['name']:<45} "
                    f"covered={len(r['covered']):<4} "
                    f"uncovered={len(r['uncovered'])}"
                )
                cov_results.append(r)

        print_func_coverage(cov_results)

    # Phase 3: Write overview.csv
    if results:
        csv_path = log_dir / "overview.csv"
        write_overview_csv(results, cov_results, csv_path)
        print(f"\nOverview saved to {csv_path}")

    # Print log locations
    print(f"Per-fuzzer logs saved under {log_dir}/")


if __name__ == "__main__":
    main()
