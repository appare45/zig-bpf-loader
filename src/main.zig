const std = @import("std");

const btf_mod = @import("./btf.zig");
const Btf = btf_mod.Btf;
const map_mod = @import("./map.zig");
const CreatedMaps = map_mod.CreatedMaps;
const Program = @import("./program.zig").Program;
const elf = @import("./elf.zig");
const utils = @import("./utils.zig");

// const BPF_PROG_TYPE_XDP = 1;
const Bpf_Sections = enum {
    license,
    @".maps",
    @".BTF",
};

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 2) {
        utils.fatal("Usage: {s} <filename>", .{args[0]});
    }
    const filename = args[1];

    const io = init.io;
    const gpa = init.gpa;

    const file = try std.Io.Dir.cwd().openFile(io, filename, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &buf);
    var e = try elf.Elf.init(gpa, &file_reader);
    defer e.deinit(gpa);
    if (e.header.machine != std.elf.EM.BPF) {
        utils.fatal("Expected ELF type is  BPF but got {t}", .{e.header.machine});
    }
    if (!e.header.is_64) {
        utils.fatal("Expect 64bit but got 32bit", .{});
    }

    var progs: std.ArrayList(Program) = .empty;
    defer {
        for (progs.items) |p| p.deinit(gpa);
        progs.deinit(gpa);
    }
    var btf: ?Btf = null;
    defer if (btf) |*b| b.deinit(gpa);
    var maps_idx: ?usize = null;
    var license: ?[]u8 = null;
    defer if (license) |p| gpa.free(p);
    for (e.sections, 0..) |sec, idx| {
        if (std.meta.stringToEnum(Bpf_Sections, sec.name)) |cmd| switch (cmd) {
            .license => {
                license = try sec.read(gpa, &file_reader);
                continue;
            },
            .@".maps" => {
                maps_idx = idx;
                continue;
            },
            .@".BTF" => {
                const data = try sec.read(gpa, &file_reader);
                defer gpa.free(data);
                btf = try Btf.init(gpa, data, sec.endian);
                continue;
            },
        };
        if (Program.isProgSection(sec)) {
            try progs.append(gpa, .{ .idx = idx, .sec = sec });
        }
    }
    try Program.attachRelocations(gpa, &file_reader, &e, progs.items);
    if (progs.items.len == 0) {
        return error.ProgramNotFound;
    }

    var created_maps: CreatedMaps = .empty;
    defer map_mod.deinitCreated(&created_maps, gpa);
    if (maps_idx) |idx| {
        std.log.info("Map section found", .{});
        const b = &(btf orelse return error.BTFNotFound);
        created_maps = try map_mod.createAll(gpa, &e, b, idx);
        std.log.debug("BTF Dump: {f}", .{b.*}); // TODO: BtfHeader.sizeを読んで無効な値を使えなくする
    }

    const license_buf = license orelse return error.LicenseNotFound;
    for (progs.items) |prog| {
        const fd = try prog.load(gpa, &file_reader, &e, &created_maps, license_buf);
        defer _ = std.os.linux.close(fd);
        const name = prog.objName(&e);
        try utils.pinObject(fd, std.mem.sliceTo(&name, 0));
    }
}
