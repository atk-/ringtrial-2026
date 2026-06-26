#!/usr/bin/env python3
"""quarrel.py — distribute sparrow-crack across remote hosts."""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — edit these before use
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent.resolve()
BINARY     = SCRIPT_DIR / "sparrow-crack/target/release/sparrow-crack"

REMOTE_HOSTS: list[tuple[str, str]] = [
    ("k70449@krpnet.lan", "htp0"),
    ("k70449@krpnet.lan", "htp1"),
    ("k70449@krpnet.lan", "htp2"),
    ("k70449@krpnet.lan", "htp3"),
    ("k70449@krpnet.lan", "htp5"),
    ("k70449@krpnet.lan", "htp6"),
    ("k70449@krpnet.lan", "htp8"),
]
# REMOTE_HOSTS = [("rtl", "127.0.0.1")]

REMOTE_DIR = "~/sparrow"
REMOTE_BIN = f"{REMOTE_DIR}/sparrow-crack"
REMOTE_WL  = f"{REMOTE_DIR}/sparrow.txt"
REMOTE_LOG = f"{REMOTE_DIR}/crack.log"

STATE_FILE    = SCRIPT_DIR / ".quarrel.json"
QUARREL_LOG   = SCRIPT_DIR / ".quarrel.log"
BENCH_SAMPLES = 50

# ---------------------------------------------------------------------------
# SSH / SCP
# ---------------------------------------------------------------------------

def ssh(login: str, host: str, cmd: str, *, capture: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    args = ["ssh", "-l", login, host, cmd]
    if capture:
        return subprocess.run(args, capture_output=True, text=True, check=check)
    return subprocess.run(args, check=check)


def scp(src, login: str, host: str, remote_path: str) -> None:
    subprocess.run(["scp", "-q", str(src), f"{login}@{host}:{remote_path}"], check=True)

# ---------------------------------------------------------------------------
# JSON state
# ---------------------------------------------------------------------------

def load_json() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_json(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")


def update_json(**keys) -> dict:
    state = load_json()
    state.update(keys)
    save_json(state)
    return state

# ---------------------------------------------------------------------------
# State accessors
# ---------------------------------------------------------------------------

def load_run_state() -> tuple[str, str, str, list[tuple[int, int]]]:
    state = load_json()
    run = state.get("run")
    if not run:
        sys.exit("ERROR: no active run — call 'run' first")
    ranges = [tuple(r) for r in run.get("ranges", [])]
    return run["tag"], run["wordlist"], run.get("eta", "unknown"), ranges


def load_hash() -> tuple[str, str]:
    """Return (hash_string, source_description) or exit."""
    state = load_json()
    h = state.get("hash")
    if not h:
        sys.exit("ERROR: no hash set — run 'set-hash <string|file>' first")
    return h, state.get("hash_source", "unknown")


def cmd_set_hash(value: str) -> None:
    path = Path(value)
    if path.is_file():
        raw = path.read_text().strip().splitlines()[0]
        source = str(path.resolve())
        print(f"==> Hash read from file: {source}")
    else:
        raw = value
        source = "raw string"
        print("==> Hash set from raw string")
    if not raw.startswith("$"):
        print(f"  WARNING: hash does not start with '$' — double-check the value")
    update_json(hash=raw, hash_source=source)
    print(f"==> Stored: {raw}")


def load_deployed_wordlist() -> Path:
    state = load_json()
    wl = state.get("deployed_wordlist")
    if not wl:
        sys.exit("ERROR: no deployed wordlist — run 'deploy' first")
    return Path(wl)


def record_deploy(files: list[str]) -> None:
    ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    hosts = " ".join(h for _, h in REMOTE_HOSTS)
    with QUARREL_LOG.open("a") as f:
        for path in files:
            entry = f"{ts}  [DEPLOY]  {path}  →  {hosts}"
            f.write(entry + "\n")
            print(f"==> Logged: {entry}")


def record_completion(tag: str, wordlist: str, eta: str, found_line: str = "") -> None:
    ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    if found_line:
        entry = f"{ts}  [{tag}]  {found_line}  est={eta}  {wordlist}"
    else:
        entry = f"{ts}  [{tag}]  EXHAUSTED  est={eta}  {wordlist}"
    with QUARREL_LOG.open("a") as f:
        f.write(entry + "\n")
    print(f"==> Logged: {entry}")

# ---------------------------------------------------------------------------
# Ranges / ETA
# ---------------------------------------------------------------------------

def count_lines(path: Path) -> int:
    n = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            n += chunk.count(b"\n")
    return n


def compute_ranges(wordlist: Path) -> list[tuple[int, int]]:
    total = count_lines(wordlist)
    n     = len(REMOTE_HOSTS)

    # Load per-host speeds from the most recent benchmark.
    cpm_map: dict[str, int] = (load_json().get("benchmark") or {}).get("results", {})
    raw     = [cpm_map.get(h, 0) for _, h in REMOTE_HOSTS]
    known   = [c for c in raw if c > 0]
    mean    = sum(known) // len(known) if known else 0
    speeds  = [c if c > 0 else mean for c in raw]

    if not any(speeds):
        # No benchmark at all — equal weighting.
        speeds = [1] * n

    total_speed = sum(speeds)
    allocs = [total * s // total_speed for s in speeds]
    allocs[-1] = total - sum(allocs[:-1])   # absorb rounding remainder

    ranges: list[tuple[int, int]] = []
    pos = 0
    for alloc in allocs:
        ranges.append((pos, pos + alloc))
        pos += alloc

    weighted = any(s != speeds[0] for s in speeds)
    print(f"==> Wordlist: {total} lines across {n} machines"
          f"  ({'speed-weighted' if weighted else 'equal chunks'})")
    for (_, host), (skip, end), speed, raw_c in zip(REMOTE_HOSTS, ranges, speeds, raw):
        note = "" if raw_c > 0 else "  [mean]"
        print(f"    {host}  skip={skip}  end={end}  count={end-skip}  cpm={speed}{note}")
    return ranges


def compute_eta(ranges: list[tuple[int, int]]) -> str:
    state = load_json()
    benchmark = state.get("benchmark")
    if not benchmark:
        print("  (no benchmark data — run 'benchmark' first)")
        return "unknown"
    cpm_map: dict[str, int] = benchmark.get("results", {})
    max_min = 0
    for (_, host), (skip, end) in zip(REMOTE_HOSTS, ranges):
        cpm = cpm_map.get(host, 0)
        if cpm:
            max_min = max(max_min, (end - skip) // cpm)
    h, m = divmod(max_min, 60)
    eta = f"{h}h{m}m" if h else f"{m}m"
    print(f"==> Estimated duration: {eta}")
    return eta

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_deploy(wordlist: Path) -> None:
    _, source = load_hash()
    print(f"==> Hash origin: {source}")
    compute_ranges(wordlist)
    local_lines = count_lines(wordlist)
    update_json(deployed_wordlist=str(wordlist.resolve()))
    print(f"==> Deploying to {len(REMOTE_HOSTS)} remote hosts in parallel...")

    def deploy_one(login: str, host: str) -> None:
        print(f"[{host}] deploying...")
        ssh(login, host, f"mkdir -p {REMOTE_DIR}", check=True)
        scp(BINARY,   login, host, REMOTE_BIN)
        scp(wordlist, login, host, REMOTE_WL)
        ssh(login, host, f"chmod +x {REMOTE_BIN}", check=True)
        result = ssh(login, host, f"wc -l < {REMOTE_WL}", capture=True, check=True)
        remote_lines = int(result.stdout.strip())
        if remote_lines != local_lines:
            raise RuntimeError(
                f"[{host}] wordlist line count mismatch: local={local_lines} remote={remote_lines}"
            )
        print(f"[{host}] done ({remote_lines} lines)")

    with ThreadPoolExecutor(max_workers=len(REMOTE_HOSTS)) as ex:
        for fut in as_completed([ex.submit(deploy_one, lg, h) for lg, h in REMOTE_HOSTS]):
            fut.result()
    print("==> Deploy complete.")
    record_deploy([str(wordlist.resolve())])


def cmd_benchmark() -> None:
    hash_str, source = load_hash()
    print(f"==> Hash origin: {source}")
    print(f"==> Benchmarking {len(REMOTE_HOSTS)} hosts ({BENCH_SAMPLES} candidates each)...")
    results: dict[str, int] = {}

    def bench_one(login: str, host: str) -> tuple[str, int]:
        t0 = time.monotonic()
        ssh(login, host,
            f"{REMOTE_BIN} -H '{hash_str}' -w {REMOTE_WL}"
            f" --limit {BENCH_SAMPLES} --progress-file /dev/null",
            capture=True)
        elapsed = max(1, time.monotonic() - t0)
        cpm = round(BENCH_SAMPLES * 60 // elapsed)
        print(f"  [{host}] {elapsed}s → {cpm} cpm")
        return host, cpm

    with ThreadPoolExecutor(max_workers=len(REMOTE_HOSTS)) as ex:
        for fut in as_completed([ex.submit(bench_one, lg, h) for lg, h in REMOTE_HOSTS]):
            host, cpm = fut.result()
            results[host] = cpm

    ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    update_json(benchmark={"timestamp": ts, "samples": BENCH_SAMPLES, "results": results})
    print(f"==> Saved to {STATE_FILE}")


def cmd_run(wordlist: Path, *, log_deploy: bool = False) -> None:
    if log_deploy:
        record_deploy([str(wordlist.resolve())])
    hash_str, source = load_hash()
    print(f"==> Hash origin: {source}")
    print(f"==> Wordlist for ranges: {wordlist.resolve()}")
    ranges  = compute_ranges(wordlist)
    eta     = compute_eta(ranges)
    tag     = os.urandom(4).hex()
    started = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    update_json(run={"tag": tag, "wordlist": str(wordlist.resolve()), "eta": eta, "ranges": ranges})
    print(f"==> Deployment tag: {tag}")
    print("==> Launching remote jobs...")

    def run_one(login: str, host: str, skip: int, end: int) -> None:
        print(f"[{host}] launching --skip {skip} --limit {end}  [tag={tag}]")
        ssh(login, host,
            f"prev=$(sed -n '1s/^# tag=\\([^ ]*\\).*/\\1/p' {REMOTE_LOG} 2>/dev/null); "
            f"[ -n \"$prev\" ] && mv {REMOTE_LOG} {REMOTE_DIR}/crack-$prev.log; "
            f"echo '# tag={tag}  started={started}' > {REMOTE_LOG}; "
            f"nohup {REMOTE_BIN}"
            f" -H '{hash_str}'"
            f" -w {REMOTE_WL}"
            f" --skip {skip}"
            f" --limit {end}"
            f" --progress-file {REMOTE_DIR}/.sparrow-index"
            f" >> {REMOTE_LOG} 2>&1 &",
            check=True)

    with ThreadPoolExecutor(max_workers=len(REMOTE_HOSTS)) as ex:
        futs = [ex.submit(run_one, lg, h, s, e) for (lg, h), (s, e) in zip(REMOTE_HOSTS, ranges)]
        for fut in as_completed(futs):
            fut.result()
    print("==> All remote jobs started.")


def cmd_status() -> None:
    tag, wordlist, eta, ranges = load_run_state()
    print(f"==> Tag: {tag}  Wordlist: {wordlist}")
    all_done   = True
    found_line = ""
    for (login, host), (skip, end) in zip(REMOTE_HOSTS, ranges or [(0, 0)] * len(REMOTE_HOSTS)):
        count = end - skip
        print(f"  [{host}]")
        result = ssh(login, host,
            f"{{ head -1 {REMOTE_LOG}; tail -1 {REMOTE_LOG}; }} 2>/dev/null"
            f" || echo '(no log yet)'",
            capture=True)
        lines = result.stdout.splitlines()
        for line in lines:
            print(f"    {line}")
        last = lines[-1] if lines else ""
        if last.startswith("Found:"):
            found_line = last
        elif "Not found after" in last:
            pass
        else:
            all_done = False
            if count > 0:
                idx_result = ssh(login, host,
                    f"cat {REMOTE_DIR}/.sparrow-index 2>/dev/null",
                    capture=True)
                idx_str = idx_result.stdout.strip()
                if idx_str:
                    try:
                        done = max(0, int(idx_str) - skip)
                        pct  = done * 100 // count
                        print(f"    progress: {done}/{count} ({pct}%)")
                    except ValueError:
                        pass
    if all_done:
        ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        result = found_line if found_line else "EXHAUSTED"
        entry = f"{ts}  [STATUS {tag}]  {result}  est={eta}  {wordlist}"
        with QUARREL_LOG.open("a") as f:
            f.write(entry + "\n")
        print(f"==> Logged: {entry}")


def cmd_kill() -> None:
    print("==> Stopping remote sparrow-crack processes...")

    def kill_one(login: str, host: str) -> None:
        result = ssh(login, host,
            "pkill -f sparrow-crack 2>/dev/null && echo 'killed' || echo 'not running'",
            capture=True)
        print(f"  [{host}] {result.stdout.strip()}")

    with ThreadPoolExecutor(max_workers=len(REMOTE_HOSTS)) as ex:
        for fut in as_completed([ex.submit(kill_one, lg, h) for lg, h in REMOTE_HOSTS]):
            fut.result()


def cmd_collect() -> None:
    tag, _, _, _ = load_run_state()
    print(f"==> Tag: {tag}")
    found = False
    for login, host in REMOTE_HOSTS:
        result = ssh(login, host, f"grep '^Found:' {REMOTE_LOG} 2>/dev/null", capture=True)
        if result.stdout.strip():
            print(f"  [{host}] {result.stdout.strip()}")
            found = True
    if not found:
        print("No password found on any remote host yet.")


def cmd_done() -> None:
    tag, wordlist, eta, _ = load_run_state()
    print(f"==> Marking run [{tag}] as complete...")
    found_line = ""
    for login, host in REMOTE_HOSTS:
        result = ssh(login, host, f"tail -1 {REMOTE_LOG} 2>/dev/null", capture=True)
        last = result.stdout.strip()
        if last.startswith("Found:"):
            found_line = last
    record_completion(tag, wordlist, eta, found_line)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="quarrel.py",
        description="Distribute sparrow-crack across remote hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "commands:\n"
            "  set-hash  <hash|file>  Store hash string (or read from file) in .quarrel.json\n"
            "  deploy    <wordlist>   Push binary + wordlist to all remote hosts\n"
            "  benchmark              Time a short job on each host; save cpm to .quarrel.json\n"
            "  run      [wordlist]    Start remote jobs; uses deployed wordlist if omitted\n"
            "  status                 Show remote log tails; auto-logs completion\n"
            "  kill                   Stop sparrow-crack on all remote hosts\n"
            "  collect                Print any 'Found:' lines from remote logs\n"
            "  done                   Manually record current run as complete in .quarrel.log\n"
        ),
    )
    parser.add_argument("command",
        choices=["set-hash", "deploy", "benchmark", "run", "status", "kill", "collect", "done"])
    parser.add_argument("value", nargs="?",
        help="Hash string/file (set-hash), or wordlist path (deploy/run)")
    args = parser.parse_args()

    if args.command == "set-hash":
        if not args.value:
            parser.error("'set-hash' requires a hash string or file path")
        cmd_set_hash(args.value)
        return

    wordlist = None
    if args.command == "deploy":
        if not args.value:
            parser.error("'deploy' requires a wordlist argument")
        wordlist = Path(args.value)
        if not wordlist.exists():
            parser.error(f"wordlist not found: {wordlist}")
    elif args.command == "run":
        wordlist = Path(args.value) if args.value else load_deployed_wordlist()
        if not wordlist.exists():
            parser.error(f"wordlist not found: {wordlist}")

    match args.command:
        case "deploy":    cmd_deploy(wordlist)
        case "benchmark": cmd_benchmark()
        case "run":       cmd_run(wordlist, log_deploy=bool(args.value))
        case "status":    cmd_status()
        case "kill":      cmd_kill()
        case "collect":   cmd_collect()
        case "done":      cmd_done()


if __name__ == "__main__":
    main()
