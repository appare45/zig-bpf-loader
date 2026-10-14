const std = @import("std");
const Io = std.Io;
const BPF = std.os.linux.BPF;

const btf_mod = @import("./btf.zig");
const Btf = btf_mod.Btf;
const MapDef = @import("./map.zig").MapDef;
const elf = @import("./elf.zig");
const utils = @import("./utils.zig");

// const BPF_PROG_TYPE_XDP = 1;
const Bpf_Sections = enum {
    license,
    @".maps",
    @".BTF",
};

const BPF_LICENSE = enum {
    GPL,
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
    var prog_sec: ?elf.Section = null;
    var btf: ?Btf = null;
    defer if (btf) |*b| b.deinit(gpa);
    var maps_sec: ?elf.Section = null;
    // TODO: プログラム内の &map リロケーションにfdを書き込む
    var map_fds: std.ArrayList(i32) = .empty; // 型として独立させてもいいかも
    defer {
        for (map_fds.items) |fd| _ = std.os.linux.close(fd);
        map_fds.deinit(gpa);
    }
    var license: ?[]u8 = null;
    defer if (license) |p| gpa.free(p);
    for (e.sections) |sec| {
        if (std.meta.stringToEnum(Bpf_Sections, sec.name)) |cmd| switch (cmd) {
            .license => {
                license = try sec.read(gpa, &file_reader);
                continue;
            },
            .@".maps" => {
                maps_sec = sec;
                continue;
            },
            .@".BTF" => {
                const data = try sec.read(gpa, &file_reader);
                defer gpa.free(data);
                btf = try Btf.init(gpa, data, sec.endian);
                continue;
            },
        };
        if (sec.shdr.sh_type == std.elf.SHT_PROGBITS and
            !std.mem.eql(u8, sec.name, ".text") and
            sec.shdr.sh_size > 0 and
            (sec.shdr.sh_flags & std.elf.SHF_EXECINSTR != 0))
        { // TODO: 複数の.textセクションを扱えるようにする
            prog_sec = sec;
        }
    }
    if (prog_sec == null) {
        return error.ProgramNotFound;
    }
    if (maps_sec != null) {
        std.log.info("Map section found", .{});
        if (btf == null) {
            return error.BTFNotFound;
        }
        const maps = try MapDef.fromBtf(gpa, &btf.?);
        defer gpa.free(maps);
        for (maps) |m| std.log.info("map {f}", .{m});
        for (maps) |m| {
            const map_fd = try m.create();
            try map_fds.append(gpa, map_fd);
            std.log.info("created map '{s}' fd={d}", .{ m.name, map_fd });
        }
        std.log.debug("BTF Dump: {f}", .{btf.?}); // TODO: BtfHeader.sizeを読んで無効な値を使えなくする
    }
    const license_buf = license orelse return error.LicenseNotFound;
    try loadProgram(gpa, &file_reader, prog_sec.?, license_buf);
}

fn loadProgram(gpa: std.mem.Allocator, file_reader: *Io.File.Reader, prog_sec: elf.Section, license: []const u8) !void {
    const prog: []const u8 = try prog_sec.read(gpa, file_reader); // TODO: 複数のprogセクションを扱えるようにする
    defer gpa.free(prog);

    var prog_name: [16]u8 = @splat(0);
    const s = prog_sec.name;
    const n = @min(prog_name.len, s.len);
    @memcpy(prog_name[0..n], s[0..n]);
    const insn_cnt = prog.len / @sizeOf(BPF.Insn);
    const log_size = 4096;
    var log_buf: [log_size]u8 = @splat(0);
    var attr = BPF.Attr{ .prog_load = std.mem.zeroes(BPF.ProgLoadAttr) };
    const pl = &attr.prog_load;
    pl.prog_type = @intFromEnum(BPF.ProgType.xdp); // TODO: ちゃんとELFファイルのセクション名をパースする
    pl.insn_cnt = std.math.cast(u32, insn_cnt) orelse return error.TooManyInstructions;
    pl.insns = @intFromPtr(prog.ptr);
    pl.license = @intFromPtr(license.ptr);
    pl.log_level = 3;
    pl.log_size = log_size;
    pl.log_buf = @intFromPtr(&log_buf);
    pl.prog_name = prog_name;
    pl.expected_attach_type = @intFromEnum(BPF.AttachType.xdp);
    const rc = std.os.linux.bpf(.prog_load, &attr, @sizeOf(BPF.ProgLoadAttr));
    std.log.info("log from kernel:\n{s}", .{log_buf});
    if (std.posix.errno(rc) != .SUCCESS) {
        std.log.err("Failed to load {s}", .{@tagName(std.posix.errno(rc))});
        return error.ProgLoadFailed;
    }
    std.log.info("Successfully loaded fd: {d}", .{rc});
}
