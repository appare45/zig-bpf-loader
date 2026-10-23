const std = @import("std");
const Io = std.Io;
const BPF = std.os.linux.BPF;

const btf_mod = @import("./btf.zig");
const Btf = btf_mod.Btf;
const map_mod = @import("./map.zig");
const MapDef = map_mod.MapDef;
const CreatedMaps = map_mod.CreatedMaps;
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
    var progs: std.ArrayList(Program) = .empty;
    defer {
        for (progs.items) |p| gpa.free(p.relocs);
        progs.deinit(gpa);
    }
    var btf: ?Btf = null;
    defer if (btf) |*b| b.deinit(gpa);
    var maps_sec: ?elf.Section = null;
    var maps_idx: usize = 0;
    var created_maps: CreatedMaps = .empty;
    defer {
        var it = created_maps.valueIterator();
        while (it.next()) |m| _ = std.os.linux.close(m.fd);
        created_maps.deinit(gpa);
    }
    var license: ?[]u8 = null;
    defer if (license) |p| gpa.free(p);
    for (e.sections, 0..) |sec, idx| {
        if (std.meta.stringToEnum(Bpf_Sections, sec.name)) |cmd| switch (cmd) {
            .license => {
                license = try sec.read(gpa, &file_reader);
                continue;
            },
            .@".maps" => {
                maps_sec = sec;
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
        if (isProgSection(sec)) {
            try progs.append(gpa, .{ .idx = idx, .sec = sec });
        }
    }
    // プログラムセクションに対するリロケーション(.relXXX)を、sh_infoが指すプログラムに紐づける
    for (e.sections) |sec| {
        if (sec.shdr.sh_type != std.elf.SHT_REL) continue;
        for (progs.items) |*p| {
            if (p.idx != sec.shdr.sh_info) continue;
            p.relocs = try sec.readRelocations(gpa, &file_reader);
            for (p.relocs) |r| {
                std.log.debug("reloc in {s}: offset={d} sym={d} type={d}", .{ sec.name, r.r_offset, r.r_sym(), r.r_type() });
            }
            break;
        }
    }
    if (progs.items.len == 0) {
        return error.ProgramNotFound;
    }
    if (maps_sec != null) {
        std.log.info("Map section found", .{});
        if (btf == null) {
            return error.BTFNotFound;
        }
        const maps = try MapDef.fromBtf(gpa, &btf.?);
        defer gpa.free(maps); // nameはbtfを借りているのでスライスだけ解放してよい
        for (maps) |*m| m.sec_offset = std.math.cast(u32, try e.symbolOffset(m.name, maps_idx)) orelse return error.MapOffsetTooLarge;
        for (maps) |m| std.log.info("map {f}", .{m});
        for (maps) |m| {
            const map_fd = try m.create();
            errdefer _ = std.os.linux.close(map_fd);
            try created_maps.put(gpa, m.sec_offset, .{ .def = m, .fd = map_fd });
            std.log.info("created map '{s}' fd={d}", .{ m.name, map_fd });
            try pinObject(map_fd, m.name);
        }
        std.log.debug("BTF Dump: {f}", .{btf.?}); // TODO: BtfHeader.sizeを読んで無効な値を使えなくする
    }
    const license_buf = license orelse return error.LicenseNotFound;
    for (progs.items) |prog| {
        const fd: i32 = @intCast(try loadProgram(gpa, &file_reader, &e, prog, &created_maps, license_buf));
        defer _ = std.os.linux.close(fd); // pinすればカーネル側で生き続ける
        const name = objName(&e, prog);
        try pinObject(fd, std.mem.sliceTo(&name, 0));
    }
}

const Program = struct {
    /// ELFのセクションindex。`.relXXX`の`sh_info`が指す
    idx: usize,
    sec: elf.Section,
    relocs: []std.elf.Elf64_Rel = &.{},
};

fn isProgSection(sec: elf.Section) bool {
    // TODO: 複数の.textセクション(サブプログラム)を扱えるようにする
    return sec.shdr.sh_type == std.elf.SHT_PROGBITS and
        !std.mem.eql(u8, sec.name, ".text") and
        sec.shdr.sh_size > 0 and
        (sec.shdr.sh_flags & std.elf.SHF_EXECINSTR != 0);
}

/// R_BPF_64_64: a `BPF_LD | BPF_IMM | BPF_DW` instruction referring to a symbol. Not in `std.elf`.
const R_BPF_64_64 = 1;

fn relocateMaps(e: *const elf.Elf, insns: []u8, relocs: []const std.elf.Elf64_Rel, maps: *const CreatedMaps) !void {
    if (e.header.endian != .little) return error.UnsupportedEndian;
    const insn_size = @sizeOf(BPF.Insn);
    for (relocs) |r| {
        if (r.r_type() != R_BPF_64_64) return error.UnsupportedRelocation;
        if (r.r_sym() >= e.symbols.len) return error.InvalidRelocationSymbol;
        const sym = e.symbols[r.r_sym()];
        if (sym.st_shndx >= e.sections.len or !std.mem.eql(u8, e.sections[sym.st_shndx].name, ".maps")) {
            return error.UnsupportedRelocation;
        }
        const m = maps.get(std.math.cast(u32, sym.st_value) orelse return error.MapNotFound) orelse return error.MapNotFound;

        if (r.r_offset % insn_size != 0 or r.r_offset + 2 * insn_size > insns.len) return error.InvalidRelocationOffset; // ld_imm64 は2スロット
        const insn = &std.mem.bytesAsSlice(BPF.Insn, insns)[r.r_offset / insn_size];
        if (insn.code != BPF.LD | BPF.IMM | BPF.DW) return error.InvalidRelocationInsn;
        insn.src = @intCast(BPF.PSEUDO_MAP_FD);
        insn.imm = m.fd;
        std.log.info("relocated '{s}' at insn {d} -> fd={d}", .{ m.def.name, r.r_offset / insn_size, m.fd });
    }
}

/// bpffs (`mount -t bpf`) の通常のマウント先。ここにpinしたオブジェクトはプロセスが終わっても残る。
const pin_dir = "/sys/fs/bpf";

/// カーネルに渡すプログラム名。名前に使えるのは [A-Za-z0-9._] だけで、NUL終端のため15文字まで。
/// セクション名("xdp/filter"など)は使えないので、libbpfと同様に関数名を使う。pinのファイル名にも使う。
fn objName(e: *const elf.Elf, program: Program) [16]u8 {
    var name: [16]u8 = @splat(0);
    const s = e.funcName(program.idx) orelse program.sec.name;
    const n = @min(name.len - 1, s.len);
    for (name[0..n], s[0..n]) |*d, c| d.* = if (std.ascii.isAlphanumeric(c) or c == '.' or c == '_') c else '_';
    return name;
}

/// `BPF_OBJ_PIN`: bpffsの`pin_dir/name`にfdのオブジェクト(プログラム/マップ)を固定する。
fn pinObject(fd: i32, name: []const u8) !void {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintSentinel(&path_buf, "{s}/{s}", .{ pin_dir, name }, 0);
    var attr: BPF.Attr = .{ .obj = std.mem.zeroes(BPF.ObjAttr) };
    attr.obj.pathname = @intFromPtr(path.ptr);
    attr.obj.bpf_fd = fd;
    const rc = std.os.linux.bpf(.obj_pin, &attr, @sizeOf(BPF.ObjAttr));
    const errno = std.posix.errno(rc);
    if (errno != .SUCCESS) {
        std.log.err("BPF_OBJ_PIN '{s}' failed: {s}", .{ path, @tagName(errno) });
        return error.ObjPinFailed;
    }
    std.log.info("pinned fd={d} at {s}", .{ fd, path });
}

fn loadProgram(
    gpa: std.mem.Allocator,
    file_reader: *Io.File.Reader,
    e: *const elf.Elf,
    program: Program,
    maps: *const CreatedMaps,
    license: []const u8,
) !u64 {
    const prog_sec = program.sec;
    const prog: []u8 = try prog_sec.read(gpa, file_reader);
    defer gpa.free(prog);
    try relocateMaps(e, prog, program.relocs, maps);

    const prog_name = objName(e, program);
    const insn_cnt = prog.len / @sizeOf(BPF.Insn);
    // log_level 3 のログは大きく、足りないとENOSPCで失敗する(プログラム自体が不正なわけではない)
    const log_size = 16 * 1024 * 1024;
    const log_buf = try gpa.alloc(u8, log_size);
    defer gpa.free(log_buf);
    @memset(log_buf, 0);
    var attr = BPF.Attr{ .prog_load = std.mem.zeroes(BPF.ProgLoadAttr) };
    const pl = &attr.prog_load;
    pl.prog_type = @intFromEnum(BPF.ProgType.xdp); // TODO: ちゃんとELFファイルのセクション名をパースする
    pl.insn_cnt = std.math.cast(u32, insn_cnt) orelse return error.TooManyInstructions;
    pl.insns = @intFromPtr(prog.ptr);
    pl.license = @intFromPtr(license.ptr);
    pl.log_level = 3;
    pl.log_size = log_size;
    pl.log_buf = @intFromPtr(log_buf.ptr);
    pl.prog_name = prog_name;
    pl.expected_attach_type = @intFromEnum(BPF.AttachType.xdp);
    const rc = std.os.linux.bpf(.prog_load, &attr, @sizeOf(BPF.ProgLoadAttr));
    std.log.info("log from kernel:\n{s}", .{std.mem.sliceTo(log_buf, 0)});
    if (std.posix.errno(rc) != .SUCCESS) {
        std.log.err("Failed to load {s}", .{@tagName(std.posix.errno(rc))});
        return error.ProgLoadFailed;
    }
    return rc;
}
