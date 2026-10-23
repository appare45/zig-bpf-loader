const std = @import("std");
const btf_mod = @import("./btf.zig");
const Btf = btf_mod.Btf;
const VarSecInfo = btf_mod.BtfTypeBody.VarSecInfo;
const BPF = std.os.linux.BPF;
const elf = @import("./elf.zig");
const utils = @import("./utils.zig");

/// One map declared in the `.maps` section, e.g.
///
///     struct {
///         __uint(type, BPF_MAP_TYPE_ARRAY);
///         __uint(max_entries, 1);
///         __type(key, __u32);
///         __type(value, __u64);
///     } pkt_count SEC(".maps");
///
/// The values are not stored in the section bytes (they are all zero) but encoded in BTF:
/// `__uint(name, val)` becomes `int (*name)[val]`, `__type(name, T)` becomes `T *name`.
pub const MapDef = struct {
    /// Borrowed from the `Btf` this was read from.
    name: []const u8,
    map_type: u32,
    key_size: u32 = 0,
    value_size: u32 = 0,
    max_entries: u32 = 0,
    /// BTF type ids of key/value, 0 if declared with `key_size`/`value_size`.
    key_type_id: u32 = 0,
    value_type_id: u32 = 0,
    /// Offset in the `.maps` section. The BTF DATASEC records 0 for it in an unlinked `.o`, so the
    /// caller fills in the real offset from `.symtab` (`st_value`), which program relocations refer to.
    sec_offset: u32,

    pub const Error = error{
        MapDefNotVar,
        MapDefNotStruct,
        MapDefNotUint,
        MapDefNotPtr,
        MapDefNoName,
        MapDefNoType,
        UnsupportedMapField,
    } || Btf.TypeError || Btf.DatasecError || std.mem.Allocator.Error;

    /// Member names of the map definition struct that are understood.
    const Field = enum { type, max_entries, key_size, value_size, key, value };

    /// Reads every map out of the `.maps` DATASEC. Caller owns the returned slice.
    pub fn fromBtf(gpa: std.mem.Allocator, btf: *const Btf) Error![]MapDef {
        const vars = try btf.findDatasec(".maps");
        const defs = try gpa.alloc(MapDef, vars.len);
        errdefer gpa.free(defs);
        for (vars, defs) |v, *def| def.* = try fromVar(btf, v);
        return defs;
    }

    fn fromVar(btf: *const Btf, v: VarSecInfo) Error!MapDef {
        const var_t = btf.get(v.type) orelse return error.BtfBadTypeId;
        if (var_t.info.kind != .@"var") return error.MapDefNotVar;
        const name = try btf.strings.get(var_t.name_off);
        if (name.len == 0) return error.MapDefNoName;

        const st = try btf.skipModifiers(var_t.size_or_type);
        if (st.info.kind != .@"struct") return error.MapDefNotStruct;

        var def: MapDef = .{ .name = name, .map_type = 0, .sec_offset = v.offset };
        for (st.body.member) |m| {
            const field = try btf.strings.get(m.name_off);
            if (field.len == 0) continue;
            // pinning, values (map-in-map), map_extra, numa_node, ... are not in `Field`.
            const kind = std.meta.stringToEnum(Field, field) orelse {
                std.log.err("map '{s}': unsupported field '{s}'", .{ name, field });
                return error.UnsupportedMapField;
            };
            switch (kind) {
                .type => def.map_type = try uintOf(btf, m.type),
                .max_entries => def.max_entries = try uintOf(btf, m.type),
                .key_size => def.key_size = try uintOf(btf, m.type),
                .value_size => def.value_size = try uintOf(btf, m.type),
                .key => {
                    def.key_type_id = try pointeeOf(btf, m.type);
                    def.key_size = try btf.sizeOf(def.key_type_id);
                },
                .value => {
                    def.value_type_id = try pointeeOf(btf, m.type);
                    def.value_size = try btf.sizeOf(def.value_type_id);
                },
            }
        }
        if (def.map_type == 0) return error.MapDefNoType;
        return def;
    }

    /// Type id `T` of a member declared as `T *name`.
    fn pointeeOf(btf: *const Btf, member_type: u32) Error!u32 {
        const ptr = try btf.skipModifiers(member_type);
        if (ptr.info.kind != .ptr) return error.MapDefNotPtr;
        return ptr.size_or_type;
    }

    /// Value `N` of a member declared with `__uint(name, N)`, i.e. `int (*name)[N]`.
    fn uintOf(btf: *const Btf, member_type: u32) Error!u32 {
        const arr = try btf.skipModifiers(try pointeeOf(btf, member_type));
        if (arr.info.kind != .array) return error.MapDefNotUint;
        return arr.body.array.nelems;
    }

    /// Issues `BPF_MAP_CREATE` and returns the map fd. The caller closes it.
    pub fn create(self: MapDef) !i32 {
        var attr: BPF.Attr = .{ .map_create = std.mem.zeroes(BPF.MapCreateAttr) };
        const c = &attr.map_create;
        c.map_type = self.map_type;
        c.key_size = self.key_size;
        c.value_size = self.value_size;
        c.max_entries = self.max_entries;
        const n = @min(self.name.len, c.map_name.len - 1);
        @memcpy(c.map_name[0..n], self.name[0..n]);
        // TODO: BTFをカーネルに渡して btf_fd / btf_key_type_id / btf_value_type_id を設定する

        const rc = std.os.linux.bpf(.map_create, &attr, @sizeOf(BPF.MapCreateAttr));
        const errno = std.posix.errno(rc);
        if (errno != .SUCCESS) {
            std.log.err("BPF_MAP_CREATE '{s}' failed: {s}", .{ self.name, @tagName(errno) });
            return error.MapCreateFailed;
        }
        return @intCast(rc);
    }

    pub fn format(self: MapDef, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print(
            "'{s}' type={d} key_size={d} value_size={d} max_entries={d} sec_offset={d}",
            .{ self.name, self.map_type, self.key_size, self.value_size, self.max_entries, self.sec_offset },
        );
    }
};

/// A map that has been created in the kernel. The owner closes `fd`.
pub const CreatedMap = struct {
    def: MapDef,
    fd: i32,
};

/// Created maps by their offset in the `.maps` section, which is what a program relocation's symbol
/// (`st_value`) refers to.
pub const CreatedMaps = std.AutoHashMapUnmanaged(u32, CreatedMap);

/// Closes every fd and frees the table.
pub fn deinitCreated(maps: *CreatedMaps, gpa: std.mem.Allocator) void {
    var it = maps.valueIterator();
    while (it.next()) |m| _ = std.os.linux.close(m.fd);
    maps.deinit(gpa);
}

/// Creates (and pins) every map declared in the `.maps` section. `sec_offset` of each def is
/// resolved from `.symtab` via `e`. The caller owns the fds in the result (`deinitCreated`).
pub fn createAll(gpa: std.mem.Allocator, e: *const elf.Elf, btf: *const Btf, maps_idx: usize) !CreatedMaps {
    const maps = try MapDef.fromBtf(gpa, btf);
    defer gpa.free(maps); // nameはbtfを借りているのでスライスだけ解放してよい
    for (maps) |*m| m.sec_offset = std.math.cast(u32, try e.symbolOffset(m.name, maps_idx)) orelse return error.MapOffsetTooLarge;

    var created: CreatedMaps = .empty;
    errdefer deinitCreated(&created, gpa);
    for (maps) |m| {
        std.log.info("map {f}", .{m});
        const map_fd = try m.create();
        errdefer _ = std.os.linux.close(map_fd);
        try created.put(gpa, m.sec_offset, .{ .def = m, .fd = map_fd });
        std.log.info("created map '{s}' fd={d}", .{ m.name, map_fd });
        try utils.pinObject(map_fd, m.name);
    }
    return created;
}
