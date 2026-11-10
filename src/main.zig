//! signer: who may sign what in a skein, as an app (shruggr/skein-signer).
//!
//! The kernel keeps raw signing (the key never enters the skein) and serves
//! the raw `wallet` import only to an app holding the granted kernel service
//! `signer`. This app holds it. Every other program calls it with the
//! kernel's NAMED in-VM call; the kernel checks the name against the caller's
//! root-approved names and puts the checked name in this program's input as
//! the top-level `as` (plans/research/kernel-permissions-contract-2026-11-09.md
//! §1). This app never learns who called; the kernel never learns what a name
//! means.
//!
//! The rule, all of it:
//!   level 0     open: served with no name;
//!   level 1     served only under `1/<protocol>`;
//!   level 2     served only under `2/<protocol>/<counterparty>` (`self`,
//!               `anyone`, or the 66-hex key; code 11 and the identity key are
//!               `self`, code 12 and 1·G are `anyone`);
//!   admin       a caller approved for any name calls under `*`: any derivation.
//! The identity key needs no name. A privileged request is refused. Nothing
//! prompts: a request is served or refused.
//!
//! Called: fn `wallet`, argument dag-cbor `{frame: bytes}` (a BRC-100 request
//! frame: 8, 11-16) → `{frame: bytes}` (the raw signer's result frame, a
//! wallet error frame included) or `{error: text}` (refused). The frame is
//! decoded strictly, checked, and handed to the raw signer RE-ENCODED from
//! what was checked (protocol as the derivation reads it, counterparty written
//! out), so the raw signer signs exactly the derivation the rule allowed.
//! Only the kernel-written `as` counts; nothing in the argument widens it. A
//! thread step (launched, a message, an `on` handler) and a filter call sign
//! nothing.
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");
const signer = @import("signer");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const NAME = "signer";

pub fn main() u8 {
    return sk.main(NAME, run);
}

fn run(a: Allocator) !void {
    const in = try sk.input(a);
    try sk.answer(a, try serve(a, in, rawWallet));
}

/// The raw signer (the kernel's `wallet` import): a frame → its result frame.
pub const Raw = *const fn (Allocator, []const u8) anyerror![]u8;

fn rawWallet(a: Allocator, frame: []const u8) anyerror![]u8 {
    return sk.wallet(a, frame) catch |e| return sk.plain(e);
}

/// The instance's identity key: the input's `self.identity`, else asked of the raw signer once.
const Identity = struct {
    in: Value,
    raw: Raw,
    key: ?[33]u8 = null,
    asked: bool = false,

    fn get(id: *Identity, a: Allocator) !?[33]u8 {
        if (id.asked) return id.key;
        id.asked = true;
        id.key = signer.identityOf(a, id.in) catch null;
        if (id.key == null) {
            const r = try id.raw(a, &.{ 8, 0, 1, 0, 0xff, 0 });
            if (r.len == 34 and r[0] == 0 and (r[1] == 2 or r[1] == 3)) id.key = r[1..34].*;
        }
        return id.key;
    }
};

pub const Verdict = union(enum) { serve, refuse: []const u8 };

/// The four lines: whether `q`, called under `as` (the kernel's checked name; null: none), is served.
pub fn decide(a: Allocator, q: signer.Request, as: ?[]const u8, id: *Identity) !Verdict {
    if (q.privileged == true) return .{ .refuse = "privileged requests are refused" };
    if (signer.open(q)) return .serve;
    if (as) |n| if (eql(u8, n, signer.ANY)) return .serve;
    const ident: ?[33]u8 = if (q.level == 2) try id.get(a) else null;
    const want = (try signer.nameFor(a, q, ident)).?;
    const name = as orelse return .{ .refuse = try std.fmt.allocPrint(a, "level {d} is served only under a name: this request needs \"{s}\"", .{ q.level, want }) };
    const got = (try signer.normalName(a, name, ident)) orelse
        return .{ .refuse = try std.fmt.allocPrint(a, "called as \"{s}\", which is no signer name", .{name}) };
    if (eql(u8, got, want)) return .serve;
    return .{ .refuse = try std.fmt.allocPrint(a, "called as \"{s}\": this request needs \"{s}\"", .{ name, want }) };
}

fn refused(a: Allocator, msg: []const u8) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put("error", cbor.string(msg));
    return m.value();
}

/// One call: the answer to write.
pub fn serve(a: Allocator, in: Value, raw: Raw) !Value {
    if (!eql(u8, Value.str(in.get("kind")) orelse "", "call"))
        return sk.report("the signer app is called (fn wallet) and signs nothing otherwise");
    if (in.get("filter")) |f| if (f == .bool and f.bool) return sk.report("the signer app is no filter and signs nothing as one");
    if (!eql(u8, Value.str(in.get("fn")) orelse "", signer.FN)) return sk.report("the signer app answers the fn wallet");
    const arg = cbor.decode(a, Value.bytesOf(in.get("arg")) orelse "") catch return refused(a, "the argument is not dag-cbor {frame: bytes}");
    const frame = Value.bytesOf(arg.get("frame")) orelse return refused(a, "the argument is not dag-cbor {frame: bytes}");
    const q = signer.decode(frame) catch |e| return refused(a, switch (e) {
        error.UnknownCall => "the frame's call is not served (8, 11-16 only)",
        error.BadFrame => "the request frame does not decode",
    });
    // Only the kernel writes the top-level `as` (a text); anything else is no name.
    const as: ?[]const u8 = Value.str(in.get("as"));
    var id: Identity = .{ .in = in, .raw = raw };
    switch (try decide(a, q, as, &id)) {
        .refuse => |msg| return refused(a, msg),
        .serve => {},
    }
    const out = try raw(a, try signer.encode(a, try signer.normalized(a, q, if (id.asked) id.key else (signer.identityOf(a, in) catch null))));
    var m = cbor.MapBuilder.init(a);
    try m.put("frame", .{ .bytes = out });
    return m.value();
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const ID: [33]u8 = hexT("03efe24af16da45a3e3ce3503b7b7172d64b16b28922011f8df970dd5bf6cc6be7");
const OTHER: [33]u8 = hexT("025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e");
const THIRD: [33]u8 = hexT("02ad6efffb187ed2fb6f3b8ceba06ed8160774666f9f2dff8e720154a90f8c8d87");

fn hexT(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// The mock raw signer: records what reached it; answers 0 ‖ ID for the identity key, else 0 ‖ "ok".
var seen: std.ArrayList([]const u8) = .empty;
var seen_alloc: Allocator = undefined;
fn mockRaw(a: Allocator, frame: []const u8) anyerror![]u8 {
    try seen.append(seen_alloc, try seen_alloc.dupe(u8, frame));
    if (eql(u8, frame, &.{ 8, 0, 1, 0, 0xff, 0 })) return a.dupe(u8, &([_]u8{0} ++ ID));
    return a.dupe(u8, &.{ 0, 'o', 'k' });
}

const T = struct {
    arena: std.heap.ArenaAllocator,
    fn init() T {
        return .{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(t: *T) void {
        seen = .empty;
        t.arena.deinit();
    }
    fn a(t: *T) Allocator {
        return t.arena.allocator();
    }
    /// A call input: kind, fn, arg {frame}, self.identity (if given), as (if given), extra fields.
    const In = struct { kind: []const u8 = "call", func: []const u8 = "wallet", frame: []const u8, as: ?[]const u8 = null, identity: bool = true, filter: bool = false, arg_as: bool = false };
    fn input(t: *T, opts: In) !Value {
        const al = t.a();
        var arg = cbor.MapBuilder.init(al);
        try arg.put("frame", .{ .bytes = opts.frame });
        if (opts.arg_as) try arg.put("as", cbor.string("*"));
        var m = cbor.MapBuilder.init(al);
        try m.put("kind", cbor.string(opts.kind));
        try m.put("fn", cbor.string(opts.func));
        try m.put("arg", .{ .bytes = try cbor.encode(al, arg.value()) });
        var self = cbor.MapBuilder.init(al);
        if (opts.identity) try self.put("identity", .{ .bytes = &ID });
        try m.put("self", self.value());
        if (opts.as) |n| try m.put("as", cbor.string(n));
        if (opts.filter) try m.put("filter", .{ .bool = true });
        // A round trip through dag-cbor, as the kernel hands it over.
        return cbor.decode(al, try cbor.encode(al, m.value()));
    }
    fn run(t: *T, opts: In) !Value {
        seen_alloc = t.a();
        return serve(t.a(), try t.input(opts), mockRaw);
    }
    fn frame(t: *T, q: signer.Request) ![]u8 {
        return signer.encode(t.a(), q);
    }
};

fn expectServed(v: Value) !void {
    if (Value.str(v.get("error"))) |e| {
        std.debug.print("refused: {s}\n", .{e});
        return error.TestUnexpectedRefusal;
    }
    try testing.expectEqualSlices(u8, &.{ 0, 'o', 'k' }, Value.bytesOf(v.get("frame")).?);
}
fn expectRefused(v: Value) !void {
    try testing.expect(Value.str(v.get("error")) != null);
    try testing.expect(v.get("frame") == null);
}

fn sig(level: u8, protocol: []const u8, cp: signer.Counterparty) signer.Request {
    return .{ .op = .create_signature, .level = level, .protocol = protocol, .key_id = "k", .counterparty = cp, .privileged = false, .hash = [_]u8{1} ** 32, .seek_permission = false };
}

test "level 0 is open: served with no name, and under any name" {
    var t = T.init();
    defer t.deinit();
    const f = try t.frame(sig(0, "open stuff", .anyone));
    try expectServed(try t.run(.{ .frame = f }));
    try expectServed(try t.run(.{ .frame = f, .as = "1/whatever" }));
    try testing.expectEqual(@as(usize, 2), seen.items.len);
}

test "the identity key needs no name; a privileged identity key is refused" {
    var t = T.init();
    defer t.deinit();
    const v = try t.run(.{ .frame = &.{ 8, 0, 1, 0, 0xff, 0 } });
    try testing.expectEqualSlices(u8, &([_]u8{0} ++ ID), Value.bytesOf(v.get("frame")).?);
    try expectRefused(try t.run(.{ .frame = &.{ 8, 0, 1, 1, 0xff, 0 }, .as = "*" }));
}

test "level 1: only under 1/<protocol>" {
    var t = T.init();
    defer t.deinit();
    const f = try t.frame(sig(1, "amm pool", .anyone));
    try expectRefused(try t.run(.{ .frame = f }));
    try testing.expectEqual(@as(usize, 0), seen.items.len);
    try expectServed(try t.run(.{ .frame = f, .as = "1/amm pool" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "1/amm commission" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/amm pool/anyone" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "amm pool" }));
    // Any counterparty at level 1.
    try expectServed(try t.run(.{ .frame = try t.frame(sig(1, "amm pool", .{ .key = OTHER })), .as = "1/amm pool" }));
    try testing.expectEqual(@as(usize, 2), seen.items.len);
}

test "level 1: the protocol as the derivation reads it; the raw signer gets that form" {
    var t = T.init();
    defer t.deinit();
    try expectServed(try t.run(.{ .frame = try t.frame(sig(1, " AMM Pool", .anyone)), .as = "1/amm pool" }));
    const got = try signer.decode(seen.items[0]);
    try testing.expectEqualStrings("amm pool", got.protocol);
}

test "level 2: only under 2/<protocol>/<that counterparty>; self/anyone normalized" {
    var t = T.init();
    defer t.deinit();
    const name = "2/skein instance/self";
    for ([_]signer.Counterparty{ .self, .{ .key = ID }, .none }) |cp| {
        const q: signer.Request = .{ .op = .get_public_key, .level = 2, .protocol = "skein instance", .key_id = "libp2p:x", .counterparty = cp, .for_self = null };
        try expectServed(try t.run(.{ .frame = try t.frame(q), .as = name }));
        try expectServed(try t.run(.{ .frame = try t.frame(q), .as = "2/skein instance/03efe24af16da45a3e3ce3503b7b7172d64b16b28922011f8df970dd5bf6cc6be7" }));
        try expectRefused(try t.run(.{ .frame = try t.frame(q) }));
        try expectRefused(try t.run(.{ .frame = try t.frame(q), .as = "2/skein instance/anyone" }));
        try expectRefused(try t.run(.{ .frame = try t.frame(q), .as = "1/skein instance" }));
    }
    // anyone: code 12, 1·G, and createSignature's default.
    for ([_]signer.Counterparty{ .anyone, .{ .key = signer.ANYONE }, .none }) |cp| {
        const f = try t.frame(sig(2, "metanet handles envelope", cp));
        try expectServed(try t.run(.{ .frame = f, .as = "2/metanet handles envelope/anyone" }));
        try expectRefused(try t.run(.{ .frame = f, .as = "2/metanet handles envelope/self" }));
    }
    // A third party's key.
    const f = try t.frame(sig(2, "auth message signature", .{ .key = OTHER }));
    try expectServed(try t.run(.{ .frame = f, .as = "2/auth message signature/025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e" }));
    try expectServed(try t.run(.{ .frame = f, .as = "2/auth message signature/025E941CF6293FC6EF61A841166A3DC3F402E4728CF7E9AACE1A530A954DBDCE9E" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/auth message signature/02ad6efffb187ed2fb6f3b8ceba06ed8160774666f9f2dff8e720154a90f8c8d87" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/auth message signature/self" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/auth message signature/anyone" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/other protocol/025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e" }));
}

test "level 2: the raw signer gets the counterparty written out" {
    var t = T.init();
    defer t.deinit();
    try expectServed(try t.run(.{ .frame = try t.frame(sig(2, "m h e x", .none)), .as = "2/m h e x/anyone" }));
    try expectServed(try t.run(.{ .frame = try t.frame(sig(2, "m h e x", .{ .key = ID })), .as = "2/m h e x/self" }));
    try testing.expectEqual(signer.Counterparty.anyone, (try signer.decode(seen.items[0])).counterparty);
    try testing.expectEqual(signer.Counterparty.self, (try signer.decode(seen.items[1])).counterparty);
}

test "level 2 with no identity in the input: asked of the raw signer" {
    var t = T.init();
    defer t.deinit();
    const f = try t.frame(sig(2, "m h e x", .{ .key = ID }));
    try expectServed(try t.run(.{ .frame = f, .as = "2/m h e x/self", .identity = false }));
    try testing.expectEqual(@as(usize, 2), seen.items.len);
    try testing.expectEqualSlices(u8, &.{ 8, 0, 1, 0, 0xff, 0 }, seen.items[0]);
}

test "admin: `*` serves any derivation, never a privileged one" {
    var t = T.init();
    defer t.deinit();
    for ([_]signer.Request{ sig(1, "amm pool", .anyone), sig(2, "auth message signature", .{ .key = THIRD }), sig(2, "server hmac", .self) }) |q| {
        try expectServed(try t.run(.{ .frame = try t.frame(q), .as = "*" }));
    }
    var p = sig(2, "auth message signature", .{ .key = THIRD });
    p.privileged = true;
    try expectRefused(try t.run(.{ .frame = try t.frame(p), .as = "*" }));
    var l1 = sig(1, "amm pool", .anyone);
    l1.privileged = true;
    try expectRefused(try t.run(.{ .frame = try t.frame(l1), .as = "1/amm pool" }));
}

test "every call the raw signer serves is gated the same way" {
    var t = T.init();
    defer t.deinit();
    const ops = [_]signer.Request{
        .{ .op = .get_public_key, .level = 1, .protocol = "amm commission", .key_id = "relay", .counterparty = .anyone, .for_self = true },
        .{ .op = .encrypt, .level = 1, .protocol = "amm commission", .key_id = "k", .counterparty = .self, .data = "p" },
        .{ .op = .decrypt, .level = 1, .protocol = "amm commission", .key_id = "k", .counterparty = .self, .data = "c" },
        .{ .op = .create_hmac, .level = 1, .protocol = "amm commission", .key_id = "k", .counterparty = .self, .data = "d" },
        .{ .op = .verify_hmac, .level = 1, .protocol = "amm commission", .key_id = "k", .counterparty = .self, .hmac = [_]u8{3} ** 32, .data = "d" },
        sig(1, "amm commission", .anyone),
        .{ .op = .verify_signature, .level = 1, .protocol = "amm commission", .key_id = "k", .counterparty = .self, .for_self = false, .signature = "\x30\x06abcdef", .data = "d" },
    };
    for (ops) |q| {
        const f = try t.frame(q);
        try expectRefused(try t.run(.{ .frame = f }));
        try expectRefused(try t.run(.{ .frame = f, .as = "1/amm pool" }));
        try expectServed(try t.run(.{ .frame = f, .as = "1/amm commission" }));
    }
    try testing.expectEqual(ops.len, seen.items.len);
    for (seen.items, ops) |s, q| try testing.expectEqual(q.op, (try signer.decode(s)).op);
}

test "a name in the argument is not a name" {
    var t = T.init();
    defer t.deinit();
    try expectRefused(try t.run(.{ .frame = try t.frame(sig(1, "amm pool", .anyone)), .arg_as = true }));
    try testing.expectEqual(@as(usize, 0), seen.items.len);
}

test "not a named call: a step or a filter signs nothing" {
    var t = T.init();
    defer t.deinit();
    const f = try t.frame(sig(1, "amm pool", .anyone));
    try testing.expectError(error.Reported, t.run(.{ .kind = "step", .frame = f, .as = "1/amm pool" }));
    try testing.expectError(error.Reported, t.run(.{ .kind = "step", .frame = try t.frame(sig(0, "open stuff", .anyone)) }));
    try testing.expectError(error.Reported, t.run(.{ .frame = f, .as = "1/amm pool", .filter = true }));
    try testing.expectError(error.Reported, t.run(.{ .func = "sign", .frame = f, .as = "1/amm pool" }));
    try testing.expectEqual(@as(usize, 0), seen.items.len);
}

test "frames it does not serve, and names that are no names" {
    var t = T.init();
    defer t.deinit();
    try expectRefused(try t.run(.{ .frame = &.{ 9, 0 }, .as = "*" })); // revealCounterpartyKeyLinkage
    try expectRefused(try t.run(.{ .frame = &.{ 1, 0, 0 }, .as = "*" })); // createAction
    try expectRefused(try t.run(.{ .frame = &.{ 15, 0, 1 }, .as = "*" })); // short
    const f = try t.frame(sig(2, "x proto", .self));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/x proto" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "2/x proto/nobody" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "" }));
    try expectRefused(try t.run(.{ .frame = f, .as = "**" }));
    try testing.expectEqual(@as(usize, 0), seen.items.len);
}
