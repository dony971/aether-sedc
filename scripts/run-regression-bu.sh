#!/usr/bin/env bash
# BU — regression: the 30 suites of BQ/BR/BS, the BT suite, the BU suite, and the
# three cargo checks required by mission BU §9. No test is skipped, filtered or
# removed.
#
# Usage:
#   scripts/run-regression-bu.sh            # everything (about 15 minutes)
#   scripts/run-regression-bu.sh SUITE ...  # the named suites only, appending to
#                                           # the same log (for chunked runs)
set -u
cd "$(dirname "$0")/.." || exit 1
export PATH="/c/msys64/ucrt64/bin:/c/Users/Shadow/.rustup/toolchains/stable-x86_64-pc-windows-gnu/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained:$PATH:/c/Users/Shadow/.cargo/bin"
OUT=../a066bu-bft-api-hardening/logs
LOG="$OUT/regression.txt"
mkdir -p "$OUT/suites"
[ $# -eq 0 ] && : > "$LOG"

CHECKS="--lib --tests --all-targets"

SUITES="phase4bq_two_process phase4bp_generation_installation phase4bo_inter_node_validation \
phase4bn_final_hardening_tests phase4bm_safety_correction_tests phase4df_bk_security_fixes \
phase4de_bootstrap_sync_tests phase4dd_generation_integration_tests \
phase4dc_validator_generation_tests phase4cy_l2_restore_safety_tests \
phase4bi_persistent_restart_tests phase4cn_l2_foundations_tests phase4co_l2_crypto_tests \
phase4cp_l2_persistence_tests phase4cq_l2_bft_tests phase4cx_l2_lock_normative_tests \
phase4db_l2_end_to_end_tests phase4bn_proposer_tests phase4bo_round_persistence_tests \
phase4bp_roundchange_safety_tests phase4bq_partition_recovery_tests \
phase4br_connection_limits_tests phase4bj_network_sim_tests \
phase4bk_roundchange_liveness_tests phase4bl_partial_sync_tests \
phase4bm_global_limits_tests phase4bh_end_to_end_tests phase4bg_network_hardening_tests \
phase4bf_p2p_network_tests phase4br_distributed_network phase4bt_lock_pol_security \
phase4bu_api_hardening"

if [ $# -eq 0 ]; then
  for check in $CHECKS; do
    out=$(cargo check $check 2>&1)
    rc=$?
    printf '%s\n' "$out" > "$OUT/check${check//-/}.txt"
    echo "cargo check $check rc=$rc $(printf '%s\n' "$out" | grep -cE '^error') errors" >> "$LOG"
  done
  SUITES_TO_RUN="$SUITES"
else
  SUITES_TO_RUN="$*"
fi

for name in $SUITES_TO_RUN; do
  out=$(timeout 900 cargo test --test "$name" 2>&1)
  rc=$?
  printf '%s\n' "$out" > "$OUT/suites/$name.txt"
  line=$(printf '%s\n' "$out" | grep -E "^test result:" | tail -1)
  echo "$name rc=$rc $line" >> "$LOG"
  echo "$name rc=$rc $line"
done

if [ $# -eq 0 ]; then
  passed=$(grep -oE "[0-9]+ passed" "$LOG" | awk '{s+=$1} END {print s+0}')
  failed=$(grep -oE "[0-9]+ failed" "$LOG" | awk '{s+=$1} END {print s+0}')
  echo "TOTAL passed=$passed failed=$failed" | tee -a "$LOG"
fi
