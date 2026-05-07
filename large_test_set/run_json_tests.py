"""
run_json_tests.py — Runner for run_all_commands.json
=====================================================
Reads the JSON test suite and executes every test case against the live API.
Produces the same coloured pass/fail output as run_all_commands.sh.

Usage:
    python large_test_set/run_json_tests.py
    python large_test_set/run_json_tests.py --url http://localhost:8000/analyze
    python large_test_set/run_json_tests.py --section area_5c
    python large_test_set/run_json_tests.py --list-sections
"""

import json
import sys
import os
import argparse
import urllib.request
import urllib.error

# ── ANSI colours ─────────────────────────────────────────────────────────────
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
BLUE   = "\033[0;34m"
CYAN   = "\033[0;36m"
RESET  = "\033[0m"

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_FILE  = os.path.join(SCRIPT_DIR, "run_all_commands.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_suite(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def call_api(api_url: str, command: str, timeout: int = 8) -> dict | None:
    payload = json.dumps({"command": command}).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "classification": "ERROR"}
    except Exception:
        return None


def check_backend(api_url: str) -> bool:
    base = api_url.replace("/analyze", "/")
    try:
        urllib.request.urlopen(base, timeout=4)
        return True
    except Exception:
        return False


def section_header(title: str):
    bar = "─" * 51
    print(f"\n{BLUE}{bar}{RESET}")
    print(f"{BLUE}  {title}{RESET}")
    print(f"{BLUE}{bar}{RESET}")


def run_section(section: dict, api_url: str) -> tuple[int, int]:
    """Run all tests in one section. Returns (passed, failed)."""
    section_header(section["title"])
    if "description" in section:
        print(f"  {CYAN}{section['description']}{RESET}")
    if "tip" in section:
        print(f"  {YELLOW}TIP: {section['tip']}{RESET}")

    passed = failed = 0

    for test in section["tests"]:
        cmd      = test["command"]
        expected = test["expected"]
        desc     = test["description"]

        result = call_api(api_url, cmd)

        if result is None:
            print(f"  {RED}✗{RESET}  {desc}")
            print(f"      → No response from {api_url}. Is the backend running?")
            failed += 1
            continue

        actual = result.get("classification", "ERROR")

        if actual == expected:
            print(f"  {GREEN}✓{RESET}  {desc}")
            passed += 1
        else:
            score = result.get("risk_score", "?")
            rules = result.get("matched_rules", [])
            print(f"  {RED}✗{RESET}  {desc}")
            print(f"      cmd:      {YELLOW}{cmd}{RESET}")
            print(f"      expected: {GREEN}{expected}{RESET}   got: {RED}{actual}{RESET}"
                  f"   score={score}   rules={rules}")
            failed += 1

    return passed, failed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run AI Bouncer test suite from run_all_commands.json"
    )
    parser.add_argument(
        "--url", default="http://localhost:8000/analyze",
        help="API URL (default: http://localhost:8000/analyze)"
    )
    parser.add_argument(
        "--section", default=None,
        help="Run only a specific section by its id (e.g. area_5c)"
    )
    parser.add_argument(
        "--list-sections", action="store_true",
        help="List all section IDs and titles, then exit"
    )
    args = parser.parse_args()

    suite = load_suite(JSON_FILE)
    meta  = suite["_meta"]

    # ── List sections ──────────────────────────────────────────────────────
    if args.list_sections:
        print(f"\n{CYAN}{meta['title']}{RESET}")
        print(f"{meta['description']}\n")
        print(f"{'Section ID':<15}  {'Title'}")
        print("─" * 70)
        for s in suite["sections"]:
            print(f"{s['id']:<15}  {s['title']}")
        sys.exit(0)

    # ── Header ─────────────────────────────────────────────────────────────
    print(f"\n{CYAN}{'═' * 55}{RESET}")
    print(f"{CYAN}  {meta['title']}{RESET}")
    print(f"{CYAN}  API: {args.url}{RESET}")
    print(f"{CYAN}{'═' * 55}{RESET}")

    # ── Backend check ──────────────────────────────────────────────────────
    print(f"\n{CYAN}🔍 Checking backend...{RESET}")
    if not check_backend(args.url):
        print(f"{RED}❌  Cannot reach {args.url.replace('/analyze','/')}{RESET}")
        print("    Start with:  uvicorn backend.app:app --host 0.0.0.0 --port 8000")
        sys.exit(1)
    print(f"{GREEN}✓  Backend reachable — starting tests...{RESET}")

    # ── Filter sections ────────────────────────────────────────────────────
    sections = suite["sections"]
    if args.section:
        sections = [s for s in sections if s["id"] == args.section]
        if not sections:
            print(f"{RED}Section '{args.section}' not found. "
                  f"Use --list-sections to see all IDs.{RESET}")
            sys.exit(1)

    # ── Run ────────────────────────────────────────────────────────────────
    total_passed = total_failed = 0
    for section in sections:
        p, f = run_section(section, args.url)
        total_passed += p
        total_failed += f

    total = total_passed + total_failed

    # ── Summary ────────────────────────────────────────────────────────────
    bar = "─" * 51
    print(f"\n{BLUE}{bar}{RESET}")
    print(f"{BLUE}  FINAL RESULTS{RESET}")
    print(f"{BLUE}{bar}{RESET}")
    print(f"\n  Total tests :  {total}")
    print(f"  {GREEN}Passed      :  {total_passed}{RESET}")
    print(f"  {RED}Failed      :  {total_failed}{RESET}\n")

    if total_failed == 0:
        print(f"{GREEN}✅  All {total} tests passed!{RESET}")
        print(f"\n  Next steps:")
        print(f"  - Open http://localhost:5173 to view the live dashboard")
        print(f"  - Run Python unit tests:  pytest large_test_set/ -v")
        sys.exit(0)
    else:
        pct = int((total_passed / total) * 100) if total else 0
        print(f"{RED}❌  {total_failed}/{total} tests failed  ({pct}% pass rate){RESET}")
        print(f"\n  Troubleshooting:")
        print(f"  - Is the ML model trained?  python backend/models/train_model.py")
        print(f"  - Check backend terminal for errors")
        sys.exit(1)


if __name__ == "__main__":
    main()
