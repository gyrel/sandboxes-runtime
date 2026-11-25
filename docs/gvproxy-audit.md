# gvproxy egress audit — schema v2 and fail-closed guarantees

Scope: the `gvproxy-egress-policy` patch (`build/patches/gvproxy-egress-policy-v2.patch`,
upstream pin `0b0819c174331f5b86d96db3ab7aad7dd126078e`). The gateway decision audit log is
the evidence contract for policy enforcement: if a decision cannot be recorded, the decision
is converted to a deny.

## Log format

Append-only JSONL, one object per line, at the `auditLog` path configured in the egress
policy. Written with the file or directory created `0600`.

### Decision records (`event: rheic.egress.decision`)

| Field | Type | When |
| --- | --- | --- |
| `schema_version` | int | always `2` |
| `event` | string | always `"rheic.egress.decision"` |
| `component` | string | always `"gateway"` |
| `time` | string | RFC3339Nano UTC, stamped at record time |
| `outcome` | string | `"ok"` for allow, `"denied"` for deny |
| `action` | string | `"allow"` or `"deny"` |
| `reason` | string | lower enum: `flow-allowed`, `host-services-denied`, `no-matching-rule`, `denied-by-rule`, `tls-hello-invalid`, `tls-name-denied`, `policy-changed`, `dns-allowed`, `dns-name-denied`, `audit_write_failed`, and coalescing markers |
| `protocol` | string | `"tcp"`, `"udp"`, `"quic"`, or `"dns"` (TLS-over-UDP classified flows record `quic`) |
| `destination` | string | guest-visible IP literal, or normalized (lowercase, dot-stripped) DNS name for `protocol: dns` |
| `port` | number | guest-visible destination port |
| `sandboxId` | string, optional | legacy field: policy `sandboxID` when provisioned |
| `sandbox_id` | string, optional | schema v2 correlation field, validated (see below) |
| `revision` | string | policy revision in effect at decision time (`"0"` when unset) |
| `policy_generation` | string, optional | validated provisioning correlation token |
| `op_id` | string, optional | validated operation correlation ID |
| `req_id` | string, optional | validated request correlation ID |
| `rule` | string, optional | matched rule ID or rule expression; `revoke:<rule>` for policy-revision revocations |
| `count` | number, optional | only on coalesced deny lines: merged repeats inside the window |

### Telemetry records (`event: rheic.egress.telemetry`)

Same envelope. Used for the queue-full and size-cap markers (`action: "audit-incomplete"`)
and flow-revocation records. `reason` carries `size-limit` or `queue-full: dropped N`.

## Guarantees

- **Fail-closed decisions.** Decision records are written and flushed synchronously at the
  decision site. If the record cannot be persisted, the decision is converted to a deny with
  `reason: "audit_write_failed"` and that conversion is itself recorded (best effort). This
  applies to TCP (both the pre-dial direct path and the post-SNI TLS path), UDP/QUIC, the
  domain authorization path, and DNS answer gating.
- **Audit before tracking.** The allow record for a TCP flow is written before the outbound
  dial and before flow tracking begins, so a refused connection never reaches the network.
- **No payload capture.** Audit records contain no request/response bodies, no headers, no
  credentials, and no hostnames beyond what the policy or DNS query already exposed.
- **Correlation IDs are not authorization.** `opID`, `reqID`, `policyGeneration`, and
  `sandboxID` are validated against `^[A-Za-z0-9_-]{1,64}$` at provisioning; invalid values
  are treated as absent and only ever appear as evidence. Nothing in the decision path reads
  them.
- **Coalescing is deny-only and loss-bounded.** Repeated deny decisions for the same
  `(host, port, protocol, action, reason)` inside a 1-second window merge into a single line
  with `count`. The first deny of every window is always written immediately. Allow lines are
  never coalesced. The coalescing map is capped at 1024 entries; the oldest window is evicted
  on overflow, and its pending merged line is flushed before eviction, so the first deny
  record of an untracked key is never dropped.
- **Bounded log.** The audit file is capped at 16 MiB. When the cap is reached, a
  `size-limit` telemetry marker is written once and the log stops accepting records.
- **Revocation closes flows.** A policy `Update` re-evaluates every tracked flow and closes
  (and records, as `revoke:*`) any flow no longer allowed.
- **Nil holder is permissive only when unrequired.** Without a policy and without
  `require-egress-policy`, upstream forwarding behavior is preserved; with the flag set,
  startup fails closed instead.

## Limits of this verification

Verified by unit tests in the gvproxy packages (fail-closed writer injection, schema golden
comparison, correlation validation table, fake-clock coalescing with cap eviction, TCP
audit-before-dial ordering) and by rebuilding the patched tree from the regenerated patch
and re-running those tests. Live egress re-verification (a real guest exercising allow/deny
against the running binary, including the `audit_write_failed` flip under a full disk)
remains an architect step.
