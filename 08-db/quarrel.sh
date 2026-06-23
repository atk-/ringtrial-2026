#!/usr/bin/env bash
# quarrel.sh — distribute sparrow-crack across REMOTE_HOSTS + this machine
# Usage: ./quarrel.sh [deploy|run|status|kill|collect]
#   deploy  — push binary + wordlist to all remote hosts
#   run     — launch cracking jobs (local range runs in foreground)
#   status  — tail last line of each remote crack.log
#   kill    — stop all remote sparrow-crack processes
#   collect — print any "Found:" lines from remote logs

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — edit these before use
# ---------------------------------------------------------------------------

BINARY="$(dirname "$0")/sparrow-crack/target/release/sparrow-crack"
WORDLIST=""   # set by 'deploy' and 'run' subcommands

HASH='$sprw1$9b68ff93ef35c261$5f136c0164452b966e2ccf2aa4b10f0f$fb62a413ea22ab5a333fd5ed400910c8'
#HASH='$sprw1$853efffddff07a3d$618291f3d09ebabe054d554abc2a9583$f3c67a4ec3b9a4ad004516454e33c82e'

REMOTE_USER="k70449@krpnet.lan"        # login account on every remote host
SSH="ssh -l $REMOTE_USER"
SCP="scp -q"

REMOTE_HOSTS=(
    htp0
    htp1
    htp2
    htp3
    htp5
    htp6
    htp8
)

REMOTE_DIR="~/sparrow"   # directory created on each remote host
REMOTE_BIN="$REMOTE_DIR/sparrow-crack"
REMOTE_WL="$REMOTE_DIR/sparrow.txt"
REMOTE_LOG="$REMOTE_DIR/crack.log"

# Deployment state — tag + wordlist path, written on 'run', read by status/collect/done.
DEPLOY_STATE_FILE="$(dirname "$0")/.deploy_state"
QUARREL_LOG="$(dirname "$0")/.quarrel.log"
DEPLOY_TAG=""
DEPLOY_WORDLIST=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

n_remote=${#REMOTE_HOSTS[@]}

_generate_tag() {
    DEPLOY_TAG=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
    DEPLOY_WORDLIST=$(realpath "$WORDLIST")
    printf '%s\n%s\n' "$DEPLOY_TAG" "$DEPLOY_WORDLIST" > "$DEPLOY_STATE_FILE"
    echo "==> Deployment tag: $DEPLOY_TAG"
}

_load_tag() {
    if [[ ! -f "$DEPLOY_STATE_FILE" ]]; then
        echo "ERROR: no active deployment — run 'run' first" >&2
        exit 1
    fi
    DEPLOY_TAG=$(sed -n '1p' "$DEPLOY_STATE_FILE")
    DEPLOY_WORDLIST=$(sed -n '2p' "$DEPLOY_STATE_FILE")
}

_record_completion() {
    local found_line="$1"
    local ts entry
    ts=$(date -Iseconds)
    if [[ -n "$found_line" ]]; then
        entry="$ts  [${DEPLOY_TAG}]  $found_line  $DEPLOY_WORDLIST"
    else
        entry="$ts  [${DEPLOY_TAG}]  EXHAUSTED  $DEPLOY_WORDLIST"
    fi
    echo "$entry" >> "$QUARREL_LOG"
    echo "==> Logged: $entry"
}

# Computed at runtime by _compute_ranges — do not set manually.
REMOTE_SKIPS=(); REMOTE_LIMITS=()

_compute_ranges() {
    local total chunk
    total=$(wc -l < "$WORDLIST")
    chunk=$(( total / n_remote ))

    REMOTE_SKIPS=()
    REMOTE_LIMITS=()
    for (( i = 0; i < n_remote; i++ )); do
        local skip=$(( i * chunk ))
        if (( i == n_remote - 1 )); then
            # Last machine gets the remainder so no candidates are missed.
            REMOTE_LIMITS+=("$(( total - skip ))")
        else
            REMOTE_LIMITS+=("$chunk")
        fi
        REMOTE_SKIPS+=("$skip")
    done

    echo "==> Wordlist: $total lines across $n_remote machines (chunk=$chunk)"
    for i in "${!REMOTE_HOSTS[@]}"; do
        echo "    ${REMOTE_HOSTS[$i]}  skip=${REMOTE_SKIPS[$i]}  limit=${REMOTE_LIMITS[$i]}"
    done
}

_deploy_one() {
    local host=$1
    echo "[$host] deploying..."
    $SSH "$host" "mkdir -p $REMOTE_DIR"
    $SCP "$BINARY"   "$REMOTE_USER@$host:$REMOTE_BIN"
    $SCP "$WORDLIST" "$REMOTE_USER@$host:$REMOTE_WL"
    $SSH "$host" "chmod +x $REMOTE_BIN"
    echo "[$host] done"
}

_run_one() {
    local host=$1 skip=$2 limit=$3
    local started
    started=$(date -Iseconds)
    echo "[$host] launching --skip $skip --limit $limit  [tag=$DEPLOY_TAG]"
    $SSH "$host" "echo '# tag=$DEPLOY_TAG  started=$started' > $REMOTE_LOG
        nohup $REMOTE_BIN \
            -H '$HASH' \
            -w $REMOTE_WL \
            --skip  $skip \
            --limit $limit \
            --progress-file $REMOTE_DIR/.sparrow-index \
            >> $REMOTE_LOG 2>&1 &"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_deploy() {
    _compute_ranges
    echo "==> Deploying to ${n_remote} remote hosts in parallel..."
    for host in "${REMOTE_HOSTS[@]}"; do
        _deploy_one "$host" &
    done
    wait
    echo "==> Deploy complete."
}

cmd_run() {
    _generate_tag
    _compute_ranges
    echo "==> Launching remote jobs..."
    for i in "${!REMOTE_HOSTS[@]}"; do
        _run_one "${REMOTE_HOSTS[$i]}" "${REMOTE_SKIPS[$i]}" "${REMOTE_LIMITS[$i]}" &
    done
    wait
    echo "==> All remote jobs started."
}

cmd_status() {
    _load_tag
    echo "==> Tag: $DEPLOY_TAG  Wordlist: $DEPLOY_WORDLIST"
    local all_done=1 found_line=""
    for host in "${REMOTE_HOSTS[@]}"; do
        echo "  [$host]"
        local out
        out=$($SSH "$host" "{ head -1 $REMOTE_LOG; tail -1 $REMOTE_LOG; } 2>/dev/null \
            || echo '(no log yet)'")
        echo "$out" | sed 's/^/    /'
        local last
        last=$(echo "$out" | tail -1)
        if   echo "$last" | grep -q '^Found:';         then found_line="$last"
        elif echo "$last" | grep -q 'Not found after'; then :
        else all_done=0
        fi
    done
    if [[ $all_done -eq 1 ]]; then
        _record_completion "$found_line"
    fi
}

cmd_kill() {
    echo "==> Stopping remote sparrow-crack processes..."
    for host in "${REMOTE_HOSTS[@]}"; do
        $SSH "$host" "pkill -f sparrow-crack 2>/dev/null && echo '[$host] killed' || echo '[$host] not running'"
    done
}

cmd_done() {
    _load_tag
    echo "==> Marking run [${DEPLOY_TAG}] as complete..."
    local found_line=""
    for host in "${REMOTE_HOSTS[@]}"; do
        local last
        last=$($SSH "$host" "tail -1 $REMOTE_LOG 2>/dev/null" || true)
        if echo "$last" | grep -q '^Found:'; then found_line="$last"; fi
    done
    _record_completion "$found_line"
}

cmd_collect() {
    _load_tag
    echo "==> Tag: $DEPLOY_TAG"
    local found=0
    for host in "${REMOTE_HOSTS[@]}"; do
        result=$($SSH "$host" "grep '^Found:' $REMOTE_LOG 2>/dev/null" || true)
        if [[ -n "$result" ]]; then
            echo "[$host] $result"
            found=1
        fi
    done
    [[ $found -eq 0 ]] && echo "No password found on any remote host yet."
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

case "${1:-}" in
    deploy)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 deploy <wordlist>"; exit 1; }
        WORDLIST="$2"
        cmd_deploy
        ;;
    run)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 run <wordlist>"; exit 1; }
        WORDLIST="$2"
        cmd_run
        ;;
    status)  cmd_status  ;;
    kill)    cmd_kill    ;;
    collect) cmd_collect ;;
    done)    cmd_done    ;;
    *)
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "  deploy <wordlist>   Push binary + wordlist to all remote hosts"
        echo "  run    <wordlist>   Start remote jobs (fires nohup on all remotes)"
        echo "  status              Show remote log tails; auto-logs completion"
        echo "  kill                Stop sparrow-crack on all remote hosts"
        echo "  collect             Print any 'Found:' lines from remote logs"
        echo "  done                Manually record current run as complete in .quarrel.log"
        exit 1
        ;;
esac
