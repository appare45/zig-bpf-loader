const std = @import("std");
const Io = std.Io;
const StringTable = @import("utils.zig").StringTable;

pub const BtfHeader = extern struct {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,

    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
    layout_off: u32,
    layout_len: u32,

    pub fn format(self: BtfHeader, w: *Io.Writer) Io.Writer.Error!void {
        try w.print(
            "magic=0x{X} version={d} flags={d} hdr_len={d} type=[off={d} len={d}] str=[off={d} len={d}]",
            .{ self.magic, self.version, self.flags, self.hdr_len, self.type_off, self.type_len, self.str_off, self.str_len },
        );
    }
};

pub const BtfType = struct {
    info: BtfTypeHead.Info,
    /// Offset into the string table, resolve with `Btf.strings.get`.
    name_off: u32,
    /// `size` for int/struct/union/enum/enum64/float, otherwise the referenced type id.
    size_or_type: u32,
    body: BtfTypeBody,
};

pub const BtfTypeBody = union(enum) {
    zero,
    int: u32,
    array: Array,
    member: []Member,
    @"enum": []Enum,
    param: []Param,
    @"var": Var,
    var_sec_info: []VarSecInfo,
    decl_tag: DeclTag,
    enum64: []Enum64,
    loc_param: LocParam,
    loc_proto: []u32,
    loc_sec: []Loc,

    pub fn format(self: BtfTypeBody, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{any}", .{self});
    }

    pub fn deinit(self: BtfTypeBody, gpa: std.mem.Allocator) void {
        switch (self) {
            .zero, .int, .array, .@"var", .decl_tag => {},
            .loc_param => |p| gpa.free(p.values),
            inline else => |s| gpa.free(s),
        }
    }

    pub const VarSecInfo = extern struct { type: u32, offset: u32, size: u32 };
    pub const Array = extern struct { type: u32, index_type: u32, nelems: u32 };
    pub const Member = extern struct { name_off: u32, type: u32, offset: u32 };
    const Enum = extern struct { name_off: u32, val: i32 };
    const Enum64 = extern struct { name_off: u32, val_lo32: u32, val_hi32: u32 };
    const Param = extern struct { name_off: u32, type: u32 };

    const Var = extern struct {
        linkage: Linkage,

        const Linkage = enum(u32) {
            static = 0,
            global_allocated = 1,
            global_extern = 2,
            _,
        };
    };

    const DeclTag = extern struct { component_idx: i32 };

    const LocParam = struct { flags: u32, values: []u32 };

    const Loc = extern struct { func: u32, loc_proto: u32, offset: u32 };
};

pub const BtfTypeHead = extern struct {
    name_off: u32,
    info: Info,
    size_or_type: extern union {
        size: u32,
        type: u32,
    },

    const Info = packed struct(u32) {
        vlen: u24,
        kind: BtfKind,
        kind_flag: bool,

        pub fn format(self: Info, w: *Io.Writer) Io.Writer.Error!void {
            try w.print("{t} vlen={d} kind_flag={}", .{ self.kind, self.vlen, self.kind_flag });
        }

        const BtfKind = enum(u7) {
            unkn = 0,
            int = 1,
            ptr = 2,
            array = 3,
            @"struct" = 4,
            @"union" = 5,
            @"enum" = 6,
            fwd = 7,
            typedef = 8,
            @"volatile" = 9,
            @"const" = 10,
            restrict = 11,
            func = 12,
            func_proto = 13,
            @"var" = 14,
            float = 16,
            decl_tag = 17,
            type_tag = 18,
            enum64 = 19,
            datasec = 15,
            loc_param = 20,
            loc_proto = 21,
            locsec = 22,
            _,
        };
    };
};

pub const Btf = struct {
    header: BtfHeader,
    /// `types[i]` has BTF type id `i + 1` (id 0 is the implicit `void`).
    types: []BtfType,
    /// Copy of the string table, query it with `strings.get`.
    strings: StringTable,

    pub const Error = error{ BtfBadMagic, BtfTruncated, BtfUnknownKind } || std.mem.Allocator.Error || StringTable.Error || Io.Reader.Error;

    /// Parses a whole `.BTF` section. The result does not borrow from `data`.
    pub fn init(gpa: std.mem.Allocator, data: []const u8, endian: std.builtin.Endian) Error!Btf {
        var r: Io.Reader = .fixed(data);
        const header = try r.takeStruct(BtfHeader, endian);
        if (header.magic != 0xEB9F) return error.BtfBadMagic;

        const str_start = @as(usize, header.hdr_len) + header.str_off;
        const str_end = str_start + header.str_len;
        if (str_end > data.len) return error.BtfTruncated;
        const strs: StringTable = try .init(gpa, data[str_start..str_end]);
        errdefer strs.deinit(gpa);

        const type_start = @as(usize, header.hdr_len) + header.type_off;
        const type_end = type_start + header.type_len;
        if (type_end > data.len) return error.BtfTruncated;
        var tr: Io.Reader = .fixed(data[type_start..type_end]);

        var types: std.ArrayList(BtfType) = .empty;
        errdefer {
            for (types.items) |t| t.body.deinit(gpa);
            types.deinit(gpa);
        }
        while (tr.seek < tr.end) {
            const head = try tr.takeStruct(BtfTypeHead, endian);
            const n: usize = head.info.vlen;
            const body: BtfTypeBody = switch (head.info.kind) {
                .unkn, .ptr, .fwd, .typedef, .@"volatile", .@"const", .restrict, .func, .float, .type_tag => .zero,
                .int => .{ .int = try tr.takeInt(u32, endian) },
                .array => .{ .array = try tr.takeStruct(BtfTypeBody.Array, endian) },
                .@"var" => .{ .@"var" = try tr.takeStruct(BtfTypeBody.Var, endian) },
                .decl_tag => .{ .decl_tag = try tr.takeStruct(BtfTypeBody.DeclTag, endian) },
                .@"struct", .@"union" => .{ .member = try tr.readSliceEndianAlloc(gpa, BtfTypeBody.Member, n, endian) },
                .@"enum" => .{ .@"enum" = try tr.readSliceEndianAlloc(gpa, BtfTypeBody.Enum, n, endian) },
                .enum64 => .{ .enum64 = try tr.readSliceEndianAlloc(gpa, BtfTypeBody.Enum64, n, endian) },
                .func_proto => .{ .param = try tr.readSliceEndianAlloc(gpa, BtfTypeBody.Param, n, endian) },
                .datasec => .{ .var_sec_info = try tr.readSliceEndianAlloc(gpa, BtfTypeBody.VarSecInfo, n, endian) },
                .loc_param => blk: {
                    const flags = try tr.takeInt(u32, endian);
                    break :blk .{ .loc_param = .{
                        .flags = flags,
                        .values = try tr.readSliceEndianAlloc(gpa, u32, n, endian),
                    } };
                },
                .loc_proto => .{ .loc_proto = try tr.readSliceEndianAlloc(gpa, u32, n, endian) },
                .locsec => .{ .loc_sec = try tr.readSliceEndianAlloc(gpa, BtfTypeBody.Loc, n, endian) },
                _ => return error.BtfUnknownKind,
            };
            errdefer body.deinit(gpa);
            try types.append(gpa, .{ .info = head.info, .name_off = head.name_off, .size_or_type = head.size_or_type.size, .body = body });
        }
        return .{ .header = header, .types = try types.toOwnedSlice(gpa), .strings = strs };
    }

    pub const DatasecError = error{BtfDatasecNotFound} || StringTable.Error;

    /// Finds the DATASEC named `name` (e.g. `.maps`) and returns its variables.
    /// もしかしたらセクション名＋nameで検索できたほうが嬉しいのかもしれない
    pub fn findDatasec(self: *const Btf, name: []const u8) DatasecError![]const BtfTypeBody.VarSecInfo {
        for (self.types) |t| {
            if (t.body != .var_sec_info) continue;
            if (std.mem.eql(u8, try self.strings.get(t.name_off), name)) return t.body.var_sec_info;
        }
        return error.BtfDatasecNotFound;
    }

    pub const TypeError = error{ BtfBadTypeId, BtfNoSize, BtfTooDeep };

    /// Returns the type with BTF type id `id`. Id 0 (`void`) has no entry and gives null.
    pub fn get(self: *const Btf, id: u32) ?*const BtfType {
        if (id == 0 or id > self.types.len) return null;
        return &self.types[id - 1];
    }

    /// Follows typedef/const/volatile/restrict/type_tag until a concrete type is reached.
    pub fn skipModifiers(self: *const Btf, id: u32) TypeError!*const BtfType {
        var cur = id;
        for (0..max_depth) |_| {
            const t = self.get(cur) orelse return error.BtfBadTypeId;
            switch (t.info.kind) {
                .typedef, .@"volatile", .@"const", .restrict, .type_tag => cur = t.size_or_type,
                else => return t,
            }
        }
        return error.BtfTooDeep;
    }

    /// Size in bytes of type `id`, like `sizeof` in C.
    pub fn sizeOf(self: *const Btf, id: u32) TypeError!u32 {
        return self.sizeOfDepth(id, 0);
    }

    const max_depth = 32;

    fn sizeOfDepth(self: *const Btf, id: u32, depth: u32) TypeError!u32 {
        if (depth > max_depth) return error.BtfTooDeep;
        const t = try self.skipModifiers(id);
        return switch (t.info.kind) {
            .int, .@"struct", .@"union", .@"enum", .enum64, .float => t.size_or_type,
            .ptr => 8, // TODO: ターゲットのポインタ幅(64bit固定)
            .array => blk: {
                const a = t.body.array;
                break :blk std.math.mul(u32, a.nelems, try self.sizeOfDepth(a.type, depth + 1)) catch error.BtfNoSize;
            },
            else => error.BtfNoSize,
        };
    }

    pub fn format(self: Btf, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("BTF {f}\n", .{self.header});
        for (self.types, 1..) |t, id| {
            try w.print("[{d}] {f}", .{ id, t.info });
            if (self.strings.get(t.name_off)) |n| {
                if (n.len != 0) try w.print(" '{s}'", .{n});
            } else |_| try w.print(" <bad name_off={d}>", .{t.name_off});
            try w.print(" size_or_type={d} {f}\n", .{ t.size_or_type, t.body });
        }
    }

    pub fn deinit(self: *Btf, gpa: std.mem.Allocator) void {
        for (self.types) |t| t.body.deinit(gpa);
        gpa.free(self.types);
        self.strings.deinit(gpa);
        self.* = undefined;
    }
};

comptime {
    std.debug.assert(@sizeOf(BtfHeader) == 32);
}
