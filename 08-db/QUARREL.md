# quarrel.py

Distributes `sparrow-crack` across a set of remote hosts over SSH, splitting a
wordlist into non-overlapping ranges so all machines search in parallel without
duplication.

## Prerequisites

- `sparrow-crack` built locally at `sparrow-crack/target/release/sparrow-crack`
- Passwordless SSH access to all hosts in `REMOTE_HOSTS`
- Python 3.10+

## Configuration

Edit the constants at the top of `quarrel.py`:

| Variable | Description |
|---|---|
| `REMOTE_HOSTS` | List of `(login, host)` pairs — one per remote machine |
| `REMOTE_DIR` | Working directory created on each remote (default `~/sparrow`) |
| `BENCH_SAMPLES` | Candidates timed per host during `benchmark` (default 10) |

`REMOTE_HOSTS` entries use separate login and hostname so each machine can have
a different SSH account:

```python
REMOTE_HOSTS = [
    ("alice@jumphost.lan", "worker0"),
    ("bob@jumphost.lan",   "worker1"),
]
```

## Typical workflow

```
# 1. Point quarrel at the hash to crack
./quarrel.py set-hash db.hash

# 2. Deploy binary + wordlist to all remotes (verifies line count on each)
./quarrel.py deploy sparrow.txt

# 3. (Optional) Measure throughput so ETA is shown on future runs
./quarrel.py benchmark

# 4. Start cracking
./quarrel.py run

# 5. Check progress
./quarrel.py status

# 6. If found, collect the result
./quarrel.py collect
```

## Commands

### `set-hash <hash|file>`

Store the target hash in `.quarrel.json`. Accepts either a raw hash string or a
path to a file containing one (first non-blank line is used).

```
./quarrel.py set-hash '$sprw1$9b68ff93...$...$...'
./quarrel.py set-hash db.hash
```

Must be called before `deploy` or `run`. The origin (file path or "raw string")
is printed and stored so subsequent commands can confirm which hash is in use.

### `deploy <wordlist>`

Push the binary and wordlist to all remote hosts in parallel, then verify the
remote line count matches the local file. Fails loudly if any host receives the
wrong number of lines.

Stores the wordlist path in `.quarrel.json` so `run` can use it without an
explicit argument.

### `benchmark`

Run a short timed job (`BENCH_SAMPLES` candidates) on each host in parallel and
compute candidates-per-minute (cpm). Results are saved to `.quarrel.json` and
used by `run` to estimate completion time.

Requires `deploy` to have been run first (binary and wordlist must be present on
remotes).

### `run [wordlist]`

Split the wordlist into equal ranges, assign one range per host, and launch
`sparrow-crack` as a background `nohup` job on each. Generates a random 4-byte
hex tag that appears in every remote log for traceability.

If `wordlist` is omitted, uses the path stored by the most recent `deploy`.

Each remote log (`~/sparrow/crack.log`) opens with:
```
# tag=a3f2b1c4  started=2026-06-23T14:01:05+02:00
```
followed by the binary's own startup lines (thread count, wordlist path, skip,
end index).

### `status`

Poll every host and show the first and last lines of its log. For hosts still
running, also reads the `.sparrow-index` progress file and prints
`progress: N/total (pct%)`.

If all hosts report either `Found:` or `Not found after …`, automatically
appends a completion entry to `.quarrel.log`.

### `kill`

Send `pkill -f sparrow-crack` to every host in parallel.

### `collect`

Grep every host's log for `Found:` lines and print any matches. Use after
`status` reports completion, or at any point to check for a hit.

### `done`

Manually mark the current run as complete in `.quarrel.log` (same entry
`status` would write automatically). Useful if you stopped polling before
`status` had a chance to detect completion.

## State files

All state is kept in the script directory:

| File | Contents |
|---|---|
| `.quarrel.json` | Hash, deployed wordlist path, benchmark results, active run metadata (tag, ranges, ETA) |
| `.quarrel.log` | Append-only completion log — one line per finished run |

`.quarrel.json` structure:

```json
{
  "hash": "$sprw1$...",
  "hash_source": "/abs/path/db.hash",
  "deployed_wordlist": "/abs/path/sparrow.txt",
  "benchmark": {
    "timestamp": "2026-06-23T14:01:05+02:00",
    "samples": 10,
    "results": {"worker0": 42, "worker1": 41}
  },
  "run": {
    "tag": "a3f2b1c4",
    "wordlist": "/abs/path/sparrow.txt",
    "eta": "3h12m",
    "ranges": [[0, 17883], [17883, 35766], ...]
  }
}
```

`.quarrel.log` entries:

```
2026-06-23T20:14:55+02:00  [a3f2b1c4]  EXHAUSTED  est=3h12m  /abs/path/sparrow.txt
2026-06-24T09:03:11+02:00  [b7f10ac2]  Found: Geriatrix  est=2h04m  /abs/path/sparrow2.txt
```

## Remote layout

Each host gets these files under `REMOTE_DIR` (`~/sparrow` by default):

| Path | Description |
|---|---|
| `sparrow-crack` | The cracker binary |
| `sparrow.txt` | The wordlist slice (full file; each host uses its own `--skip`/`--limit`) |
| `crack.log` | Job output — header line, then binary stdout/stderr |
| `.sparrow-index` | Periodic progress checkpoint (absolute line index); deleted on clean exit |
