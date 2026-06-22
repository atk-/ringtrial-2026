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
WORDLIST="$(dirname "$0")/../scrapers/res/comp/rt-all-0521.txt"

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

# Deployment tag — generated fresh on each 'run', persisted locally so
# 'status'/'collect' can reference the same tag without regenerating it.
DEPLOY_TAG_FILE="$(dirname "$0")/.deploy_tag"
DEPLOY_TAG=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

n_remote=${#REMOTE_HOSTS[@]}

_generate_tag() {
    DEPLOY_TAG=$(tr -dc 'a-f0-9' < /dev/urandom | head -c8)
    echo "$DEPLOY_TAG" > "$DEPLOY_TAG_FILE"
    echo "==> Deployment tag: $DEPLOY_TAG"
}

_load_tag() {
    if [[ ! -f "$DEPLOY_TAG_FILE" ]]; then
        echo "ERROR: no active deployment — run 'run' first" >&2
        exit 1
    fi
    DEPLOY_TAG=$(< "$DEPLOY_TAG_FILE")
}

# Computed at runtime by _compute_ranges — do not set manually.
LOCAL_SKIP=0; LOCAL_LIMIT=0
REMOTE_SKIPS=(); REMOTE_LIMITS=()

_compute_ranges() {
    local total chunk n_total last_limit
    total=$(wc -l < "$WORDLIST")
    n_total=$(( n_remote + 1 ))
    chunk=$(( total / n_total ))

    LOCAL_SKIP=0
    LOCAL_LIMIT=$chunk

    REMOTE_SKIPS=()
    REMOTE_LIMITS=()
    for (( i = 0; i < n_remote; i++ )); do
        local skip=$(( (i + 1) * chunk ))
        if (( i == n_remote - 1 )); then
            # Last machine gets the remainder so no candidates are missed.
            REMOTE_LIMITS+=("$(( total - skip ))")
        else
            REMOTE_LIMITS+=("$chunk")
        fi
        REMOTE_SKIPS+=("$skip")
    done

    echo "==> Wordlist: $total lines across $n_total machines (chunk=$chunk)"
    echo "    local       skip=$LOCAL_SKIP  limit=$LOCAL_LIMIT"
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
            --progress-file $REMOTE_DIR/pp.save \
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

    echo "==> Remote jobs started. Running local range (skip=$LOCAL_SKIP limit=$LOCAL_LIMIT)..."
    exec "$BINARY" \
        -H "$HASH" \
        -w "$WORDLIST" \
        --skip  "$LOCAL_SKIP" \
        --limit "$LOCAL_LIMIT"
}

cmd_status() {
    _load_tag
    echo "==> Tag: $DEPLOY_TAG"
    for host in "${REMOTE_HOSTS[@]}"; do
        echo "  [$host]"
        $SSH "$host" "{ head -1 $REMOTE_LOG; tail -1 $REMOTE_LOG; } 2>/dev/null \
            || echo '    (no log yet)'" | sed 's/^/    /'
    done
}

cmd_kill() {
    echo "==> Stopping remote sparrow-crack processes..."
    for host in "${REMOTE_HOSTS[@]}"; do
        $SSH "$host" "pkill -f sparrow-crack 2>/dev/null && echo '[$host] killed' || echo '[$host] not running'"
    done
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
    deploy)  cmd_deploy  ;;
    run)     cmd_run     ;;
    status)  cmd_status  ;;
    kill)    cmd_kill    ;;
    collect) cmd_collect ;;
    *)
        echo "Usage: $0 {deploy|run|status|kill|collect}"
        echo ""
        echo "  deploy   Push binary + wordlist to all remote hosts"
        echo "  run      Start remote jobs then run local range in foreground"
        echo "  status   Show last log line from each remote host"
        echo "  kill     Stop sparrow-crack on all remote hosts"
        echo "  collect  Print any 'Found:' lines from remote logs"
        exit 1
        ;;
esac
