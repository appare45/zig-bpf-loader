const std = @import("std");
const Io = std.Io;

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
    name: ?[]const u8,
    body: BtfTypeBody,

    pub fn format(self: BtfType, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{f}", .{self.info});
        if (self.name) |n| try w.print(" '{s}'", .{n});
        try w.print(" {f}", .{self.body});
    }
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

    const VarSecInfo = extern struct { type: u32, offset: u32, size: u32 };
    const Array = extern struct { type: u32, index_type: u32, nelems: u32 };
    const Member = extern struct { name_off: u32, type: u32, offset: u32 };
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

    const VarSecinfo = extern struct { type: u32, offset: u32, size: u32 };
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
    /// Copy of the string table; `BtfType.name` slices point into this.
    strings: []u8,

    pub const Error = error{ BtfBadMagic, BtfTruncated, BtfUnknownKind } || std.mem.Allocator.Error || Io.Reader.Error;

    /// Parses a whole `.BTF` section. The result does not borrow from `data`.
    pub fn init(gpa: std.mem.Allocator, data: []const u8, endian: std.builtin.Endian) Error!Btf {
        var r: Io.Reader = .fixed(data);
        const header = try r.takeStruct(BtfHeader, endian);
        if (header.magic != 0xEB9F) return error.BtfBadMagic;

        const str_start = @as(usize, header.hdr_len) + header.str_off;
        const str_end = str_start + header.str_len;
        if (str_end > data.len) return error.BtfTruncated;
        const str = try gpa.dupe(u8, data[str_start..str_end]);
        errdefer gpa.free(str);

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
            const name: ?[]const u8 = if (head.name_off != 0) std.mem.sliceTo(str[head.name_off..], 0) else null;
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
            try types.append(gpa, .{ .info = head.info, .name = name, .body = body });
        }
        return .{ .header = header, .types = try types.toOwnedSlice(gpa), .strings = str };
    }

    pub fn format(self: Btf, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("BTF {f}\n", .{self.header});
        for (self.types, 1..) |t, id| {
            try w.print("[{d}] {f}\n", .{ id, t });
        }
    }

    pub fn deinit(self: *Btf, gpa: std.mem.Allocator) void {
        for (self.types) |t| t.body.deinit(gpa);
        gpa.free(self.types);
        gpa.free(self.strings);
        self.* = undefined;
    }
};

comptime {
    std.debug.assert(@sizeOf(BtfHeader) == 32);
}
