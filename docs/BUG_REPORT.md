# Bug & Performance Report — ws/wss, wsmux/wssmux, `mux_stripe`

Scan focus: correctness and efficiency of WebSocket transports, with extra
attention on `mux_stripe` (flow striping across pooled wsmux/wssmux sessions).

## Verdict

`mux_stripe` suspicion was justified. The striping package still had a
**critical CPU busy-spin** after the END marker arrived, plus several
admission/restart bugs on the server striped dispatcher that could stall pool
growth or wedge the tunnel after a restart. Plain `ws`/`wss`/`wsmux` also had
smaller reliability and efficiency issues (control-channel panics, blocking
requeues, compression negotiation, session leaks).

Fixes for the highest-severity items are included in this branch; remaining
items are documented below as follow-ups.

---

## Critical — `mux_stripe` / striping

### 1. Read busy-spins after END marker (CPU burn + stallTimeout defeated)

**Where:** `internal/utils/striping/striping.go` — `Read`

**Bug:** `totalKnown` is closed when the first END marker arrives and stays
permanently selectable. After that, if Read is still waiting for a missing
sequence number (common: END rides a fast leg while data chunks are still in
flight on slower legs), the `select` immediately wakes on `<-c.totalKnown`
every loop iteration. Effects:

- One core pegged for the rest of the transfer
- `stallTimeout` never fires (`timer.C` loses to the closed channel)
- Under concurrent striped flows, this can starve the whole process

**Repro:** `TestReadDoesNotBusySpinWhenEndArrivesEarly`

**Fix:** only include `totalKnown` in the `select` while `haveTotal == 0`
(nil channel afterward never selects).

### 2. `stripedFlows` not reset on server `Restart`

**Where:** `internal/server/transport/wsmux.go` — `Restart`

**Bug:** `streamCounter` / `sessionCounter` / `sessions` were cleared, but
`stripedFlows` was left at its old value. After restart, `acquireStripedSlot`
could see `active*StripeFactor > budget` forever on a fresh empty pool and
busy-wait until leftover goroutines from the previous generation happened to
decrement it (or hang indefinitely).

**Fix:** reset `stripedFlows = 0` in `Restart`.

### 3. Striped pool never grows from stream pressure

**Where:** `acceptLocalConn` + `acquireStripedSlot`

**Bug:** Pool growth is normally triggered by
`streamCounter >= sessionCounter*MuxCon`. With `mux_stripe = N`, each logical
flow already consumes **N** smux streams, and `acquireStripedSlot` caps
in-flight flows at `sessions*MuxCon/N`. `streamCounter` only counts logical
flows, so under striping it often never reaches the growth threshold. The
pool stayed undersized; new flows blocked in `acquireStripedSlot`.

**Fix:** when `acquireStripedSlot` is at budget, also enqueue `reqNewConnChan`
so the client dials another pool session.

### 4. Failed striped setup held admission slots and wasted requeues

**Where:** `dispatchStriped` / `requeueOrDrop`

**Bugs:**

- On `openStripedLegs` failure, the code slept 100ms **while still holding**
  a `stripedFlows` slot, shrinking capacity for everyone else.
- Requeued connections kept their original `timeCreated`, so the next attempt
  almost always hit the 3s setup timeout and was dropped — the “retry” was
  effectively dead.

**Fix:** release the slot before sleep/requeue; refresh `timeCreated` on
requeue after setup failure.

### 5. Unbounded chunk length allocation (DoS / OOM)

**Where:** `readLeg`

**Bug:** payload length from the 4-byte header was allocated with no cap.
A corrupt or hostile peer could request a multi-GB buffer.

**Fix:** reject `length > chunkSize` before allocating.

---

## High — wsmux/wssmux reliability

### 6. `handleSession` / `handleSessionError` could block forever on `localChannel`

**Where:** server `wsmux.go`

**Bug:** failed address send / session error did `localChannel <- conn` with
no `select`/`default`. A full channel blocked the session goroutine forever
and permanently leaked its `MuxCon` counter slot — one dead session after
another until the tunnel wedged.

**Fix:** non-blocking send; on failure close the conn and decrement
`streamCounter`.

### 7. Discarded tunnel session leaked smux state

**Where:** tunnel listener when `tunnelChannel` is full

**Bug:** `smux.Client` was created, then only `conn.Close()` was called —
session not closed.

**Fix:** `session.Close()` before discarding.

### 8. Empty control-channel message panics (`msg[0]`)

**Where:** client/server `ws.go` and `wsmux.go` control readers

**Bug:** `msg[0]` with no length check. An empty binary frame (or a peer
sending only padding-less empty payload) panics the read goroutine and takes
down the control path via restart races.

**Fix:** skip empty messages.

---

## Performance / efficiency findings

### 9. Striping wrote header and payload as two `Write`s

**Where:** `writeChunk`

Each chunk was two smux frames (header, then body). Combined into a single
buffer/`Write` so the leg transport sees one frame per chunk.

### 10. Client dialer offered WebSocket permessage-deflate

**Where:** `internal/utils/network/ws_dialer.go` — `EnableCompression: true`

Tunnel traffic is smux/TLS binary. Compression burns CPU and, if ever
negotiated, adds latency. Server upgrader did not enable it (so it usually
stayed off), but the client still offered the extension.

**Fix:** `EnableCompression: false`.

### 11. `wsmux`/`wssmux` use `websocket.Conn.NetConn()` (raw underlying conn)

After the HTTP/WS handshake, smux runs on the **raw** TCP/TLS socket, not on
WebSocket frames. That is a large throughput win versus plain `ws`/`wss`
(no per-message framing, masking, or gorilla buffer copies on the data path).

Caveats:

- Gorilla documents that using the underlying conn “corrupts” the WebSocket
  session — both ends must agree to speak smux raw after upgrade (they do).
- CDNs that only splice bytes after upgrade (Cloudflare et al.) usually work;
  anything that re-frames or inspects WS data frames may not.
- README’s claim that wsmux is “still just WebSocket-over-TLS” is true for
  the handshake/path/SNI story, but the data plane is raw multiplexed bytes.

### 12. Plain `ws`/`wss` data path is inherently heavier

- Every TCP segment becomes a WS binary message (`WriteMessage` /
  `ReadMessage`), with masking on the client and an allocation per read.
- `transferWebSocketToTCP` cannot use the 64KB buffer pool (gorilla allocates).
- TCP→WS side already pools a 64KB buffer (good).
- No splice path (unlike raw TCP forwarding).

For throughput-bound workloads prefer `wsmux`/`wssmux` over `ws`/`wss`.

### 13. Striping CPU / memory overhead (inherent)

Per logical flow with factor N:

- N smux streams + N read workers + N write workers
- Extra 8-byte header per chunk (`DefaultChunkSize` = 16KiB → ~0.05% wire)
- Reassembly `pending` map and an extra copy into the write queue
- Head-of-line blocking on the slowest leg for that one flow (documented)

`mux_stripe` helps **one fat flow** on a lossy/high-RTT link. For many short
connections keep `mux_stripe = 1`.

### 14. Docs mismatch: `mux_streambuffer`

Config comments/README say “256 KB”; actual default is `65536` (**64 KB**)
in `cmd/defaults.go`. Misleading when tuning for performance.

---

## Medium / lower

| Issue | Notes |
| --- | --- |
| No leg-failure recovery under striping | Documented; one dead pool conn resets the flow (loud, not silent). |
| `pending` map unbounded | Hostile peer could send high seqs and grow memory; length cap helps but seq window is still open. |
| StripeFactor mismatch client/server | If only one side has `mux_stripe > 1`, headers vs address framing disagree and flows fail. No handshake negotiation. |
| `openStripedLegs` silently uses fewer legs than configured when the pool is small | Functionally OK (header `total` matches) but striping silently degrades until the pool grows. |
| Server `handleLoop` capped at 4 | Fine for non-stripe; striped path uses a dedicated dispatch loop. |
| Control channel writes unsynchronized with gorilla | Currently serialized on one goroutine per side — OK today; don’t add concurrent writers without a mutex. |

---

## What this branch changed

1. Fixed striping Read busy-spin after END marker (+ regression test)
2. Capped inbound chunk length
3. Single `Write` per striped chunk
4. Reset `stripedFlows` on server restart
5. Request pool growth from `acquireStripedSlot` under striping saturation
6. Don’t hold admission slots across failed open; refresh requeue timestamps
7. Non-blocking localChannel requeue on session errors
8. Close discarded smux sessions
9. Guard empty control messages
10. Disable WS compression on the dialer

## Suggested follow-ups (not in this branch)

- Negotiate or advertise `mux_stripe` on the control channel so mismatches fail fast
- Bound striping `pending` by a max reorder window
- Consider `mux_streambuffer` default/docs alignment (64KB vs 256KB)
- Optional: expose metrics for striped HOL stalls / busy admission waits
- Plain `ws`: NextWriter streaming to cut per-message overhead if ws must stay
