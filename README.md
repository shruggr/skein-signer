# skein-signer

Who may sign what in a skein, as an app.

The kernel keeps raw signing: the key never enters the skein, and the raw `wallet` import is served only to an
app holding the granted kernel service `signer`. This app holds it. Every other program calls this app with the
kernel's NAMED in-VM call (`callAs`); the kernel checks the name against the names root approved for the caller
and puts the checked name in this program's input as the top-level `as`. This app never learns who called; the
kernel never learns what a name means.

## The rule (all of it)

| request | served when |
|---|---|
| level 0 | always (open, no name) |
| level 1 | called as `1/<protocol>` |
| level 2 | called as `2/<protocol>/<counterparty>` |
| any (admin) | called as `*` |
| the identity key | always (no name) |
| `privileged` | never |

- The request's protocol (and, at level 2, its counterparty) must be the name's; otherwise a plain refusal.
- `<protocol>` is written as the derivation reads it (BRC-43: trimmed, lower case).
- `<counterparty>` is `self`, `anyone`, or the compressed key in hex (66 digits). `self` and `anyone` are specific
  counterparties. Wire code 11 and the instance's identity key are `self`; code 12 and 1·G are `anyone`; an
  absent counterparty is the call's default (createSignature: `anyone`; every other call: `self`).
- No `as`: level 0 and the identity key only. Only the kernel-written `as` counts; nothing in the argument
  widens it.
- Not a named call (a launched thread, a message, an `on` handler, a filter call): nothing is signed.
- No prompting: served or refused.

## Calling it

`fn wallet`, argument dag-cbor `{frame: bytes}` — a BRC-100 request frame for the calls the raw signer serves
programs: 8 getPublicKey, 11 encrypt, 12 decrypt, 13 createHmac, 14 verifyHmac, 15 createSignature, 16
verifySignature. Answer `{frame: bytes}` (the raw signer's result frame; a wallet error is its error frame) or
`{error: text}` (refused).

The frame is decoded strictly and handed to the raw signer re-encoded from what was checked (protocol as the
derivation reads it, counterparty written out), so the raw signer signs exactly the derivation the rule allowed.

Programs use the SDK's `signer` module (skein-sdk `lib/signer.zig`):

- `signer.request(a, in, frame)` — the drop-in for `sk.wallet(a, frame)`: computes the name from the frame;
- `signer.requestAny(a, frame)` — the same under `*`;
- `signer.requestAs(a, name, frame)`; `signer.nameFor`, `signer.level1`, `signer.level2`.

A caller's manifest declares the names (`"calls": {"signer": ["1/amm pool", "2/skein instance/self"]}` or
`"*"`); root approves them at install.

## Build

    zig build test   the rule, the names, every call (natively, the raw signer mocked)
    zig build bin    bin/signer.wasm

## End to end

`test/e2e.ts` runs this app on a real kernel (shruggr/skein branch `call-permissions`): copy it into a skein
checkout's `kernel-zig/equiv/` and run it with `SIGNER_APP=<this repo>` (`SKEIN_EQUIV_STORE=rocksdb|wasm` for the
other stores). An installed instance and an image instance, a probe app approved for `1/amm pool` and
`2/skein instance/self`: the approved names sign, an unapproved name is refused by the kernel, a request that is
not its name's is refused by this app, the probe's own raw signer use is refused, both stores replay exactly.
