#!/usr/bin/env bash
# End-to-end case-study driver.
#
# Runs the whole angelia pipeline against every vuln variant, produces
# per-crash triage artifacts, feeds them into the eval harness and the
# incident-report tool, and stages the outputs under case_study/.
#
# Not committed as generated data — case_study/ is gitignored.
#
# Usage:
#   bash tools/case_study/run.sh [--repo PATH]
# Each invocation writes to a new directory so old crash artifacts cannot
# silently affect evaluation or reports.
set -euo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ "${1:-}" == "--repo" ]]; then REPO="$2"; shift 2; fi
cd "$REPO"
BIN="$REPO/build/default/bin"
ANGELIA="$BIN/angelia.exe"
OUT="$REPO/case_study/$(date -u +%Y%m%dT%H%M%SZ)-$$"
[[ -f "$ANGELIA" ]] || { echo "missing $ANGELIA; build first" >&2; exit 1; }
mkdir -p "$OUT/triage" "$OUT/reports"

echo "== case_study — outputs going to $OUT"

# 1. capture + analyze + classify every vuln variant --------------------
for v in stack_off stack_gs stack_full heap_off heap_gs heap_full; do
    echo ""
    echo "-- $v --"
    tri="$OUT/triage/$v"
    mkdir -p "$tri"
    "$ANGELIA" capture --binary "$BIN/vuln_$v.exe" \
        --gen-pattern 256 --out "$tri"
    json=$(find "$tri" -maxdepth 1 -name "vuln_${v}.*.json" -print -quit)
    [[ -n "$json" ]] || { echo "no crash artifact for $v" >&2; exit 1; }
    "$ANGELIA" analyze  "$json" >/dev/null
    "$ANGELIA" classify "$json" | grep -E "bucket|confidence" | sed 's/^/   /'
done

# 2. run the eval harness with the triage corpus we just built ----------
echo ""
echo "== eval (with triage augmentation)"
"$ANGELIA" eval \
    --corpus  "$REPO/configs/eval_corpus.json" \
    --triage-dir "$OUT/triage" \
    --out-dir "$OUT/eval" \
    2>&1 | tail -40

# 3. build one hero incident report on vuln_stack_off -------------------
echo ""
echo "== report (hero case: vuln_stack_off)"
hero_json=$(ls "$OUT/triage/stack_off"/vuln_stack_off.*.json | head -1)
smoke_arg=()
if [[ -f "$REPO/stage1_smoke.db" ]]; then
    smoke_arg=(--timeline "$REPO/stage1_smoke.db")
fi
"$ANGELIA" report \
    --out "$OUT/reports/hero.html" \
    --binary "$BIN/vuln_stack_off.exe" \
    --triage "$hero_json" \
    "${smoke_arg[@]}" \
    --title "Angelia case study — vuln_stack_off"

# 4. one comparison report showing all three stack variants side by side
echo ""
echo "== report (three-variant comparison)"
"$ANGELIA" report \
    --out "$OUT/reports/stack_variants.html" \
    --triage "$(ls "$OUT/triage/stack_off"/*.json | head -1)" \
    --triage "$(ls "$OUT/triage/stack_gs"/*.json | head -1)" \
    --triage "$(ls "$OUT/triage/stack_full"/*.json | head -1)" \
    --title "Same bug, three mitigation levels — stack strcpy"

echo ""
echo "== done. outputs:"
ls -la "$OUT/eval/" "$OUT/reports/" 2>/dev/null
