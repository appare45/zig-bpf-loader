const std = @import("std");
const elf = @import("./elf.zig");
const Io = std.Io;
const utils = @import("./utils.zig");
const BPF = std.os.linux.BPF;

// const BPF_PROG_TYPE_XDP = 1;
const Bpf_Sections = enum {
    license,
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
    var symtab: ?[]const u8 = null;
    defer if (symtab) |p| gpa.free(p);
    var prog_sec: ?elf.Section = null;
    var license: ?[]u8 = null;
    defer if (license) |p| gpa.free(p);
    for (e.sections) |sec| {
        if (sec.shdr.sh_type == std.elf.SHT_SYMTAB) {
            if (symtab != null) {
                utils.fatal("Duplicate symbol tables", .{});
            }
            symtab = try sec.read(gpa, &file_reader);
        }
        if (std.meta.stringToEnum(Bpf_Sections, sec.name)) |cmd| switch (cmd) {
            .license => {
                license = try sec.read(gpa, &file_reader);
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
    if (symtab == null) {
        utils.fatal("Symbol table not found", .{});
    }
    if (prog_sec == null) {
        utils.fatal("Program not found", .{});
    }
    const prog: []const u8 = try prog_sec.?.read(gpa, &file_reader); // TODO: 複数のprogセクションを扱えるようにする
    defer gpa.free(prog);

    var prog_name: [16]u8 = @splat(0);
    const s = prog_sec.?.name;
    const n = @min(prog_name.len, s.len);
    @memcpy(prog_name[0..n], s[0..n]);
    const insn_cnt = prog.len / @sizeOf(BPF.Insn);
    const log_size = 4096;
    var log_buf: [log_size]u8 = @splat(0);
    var attr = BPF.Attr{
        .prog_load = .{
            .prog_type = @intFromEnum(BPF.ProgType.xdp),
            .insn_cnt = std.math.cast(u32, insn_cnt) orelse return,
            .insns = @intFromPtr(prog.ptr),
            .license = @intFromPtr(license.?.ptr),
            .log_level = 3,
            .log_size = log_size,
            .log_buf = @intFromPtr(&log_buf),
            // BTFになってからは使ってないらしい
            .kern_version = 0,
            .prog_flags = 0,
            .prog_name = prog_name[0..16].*,
            .prog_ifindex = 0,
            .expected_attach_type = @intFromEnum(BPF.AttachType.xdp),
            // TODO: BTF対応
            .prog_btf_fd = -1,
            .func_info_rec_size = 0,
            .func_info = 0,
            .func_info_cnt = 0,
            .line_info_rec_size = 0,
            .line_info = 0,
            .line_info_cnt = 0,
            .attact_btf_id = 0,
            .attach_prog_id = 0,
        },
    };
    const fd = std.os.linux.bpf(.prog_load, &attr, @sizeOf(@TypeOf(attr)));
    std.log.info("log from kernel:\n{s}", .{log_buf});
    if (fd < 0) {
        utils.fatal("Failed to load {s}", .{@tagName(std.posix.errno(fd))});
    }
    std.log.info("Successfully loaded fd: {d}", .{fd});
}
