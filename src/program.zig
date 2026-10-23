const std = @import("std");
const Io = std.Io;
const BPF = std.os.linux.BPF;

const elf = @import("./elf.zig");
const map_mod = @import("./map.zig");
const CreatedMaps = map_mod.CreatedMaps;

/// One loadable program section of the ELF.
pub const Program = struct {
    /// ELFのセクションindex。`.relXXX`の`sh_info`が指す
    idx: usize,
    sec: elf.Section,
    relocs: []std.elf.Elf64_Rel = &.{},

    /// R_BPF_64_64: a `BPF_LD | BPF_IMM | BPF_DW` instruction referring to a symbol. Not in `std.elf`.
    const R_BPF_64_64 = 1;

    pub fn deinit(self: Program, gpa: std.mem.Allocator) void {
        gpa.free(self.relocs);
    }

    pub fn isProgSection(sec: elf.Section) bool {
        // TODO: 複数の.textセクション(サブプログラム)を扱えるようにする
        return sec.shdr.sh_type == std.elf.SHT_PROGBITS and
            !std.mem.eql(u8, sec.name, ".text") and
            sec.shdr.sh_size > 0 and
            (sec.shdr.sh_flags & std.elf.SHF_EXECINSTR != 0);
    }

    /// プログラムセクションに対するリロケーション(.relXXX)を、sh_infoが指すプログラムに紐づける
    pub fn attachRelocations(
        gpa: std.mem.Allocator,
        file_reader: *Io.File.Reader,
        e: *const elf.Elf,
        progs: []Program,
    ) !void {
        for (e.sections) |sec| {
            if (sec.shdr.sh_type != std.elf.SHT_REL) continue;
            for (progs) |*p| {
                if (p.idx != sec.shdr.sh_info) continue;
                p.relocs = try sec.readRelocations(gpa, file_reader);
                for (p.relocs) |r| {
                    std.log.debug("reloc in {s}: offset={d} sym={d} type={d}", .{ sec.name, r.r_offset, r.r_sym(), r.r_type() });
                }
                break;
            }
        }
    }

    /// カーネルに渡すプログラム名。名前に使えるのは [A-Za-z0-9._] だけで、NUL終端のため15文字まで。
    /// セクション名("xdp/filter"など)は使えないので、libbpfと同様に関数名を使う。pinのファイル名にも使う。
    pub fn objName(self: Program, e: *const elf.Elf) [16]u8 {
        var name: [16]u8 = @splat(0);
        const s = e.funcName(self.idx) orelse self.sec.name;
        const n = @min(name.len - 1, s.len);
        for (name[0..n], s[0..n]) |*d, c| d.* = if (std.ascii.isAlphanumeric(c) or c == '.' or c == '_') c else '_';
        return name;
    }

    /// Issues `BPF_PROG_LOAD` and returns the program fd. The caller closes it.
    pub fn load(
        self: Program,
        gpa: std.mem.Allocator,
        file_reader: *Io.File.Reader,
        e: *const elf.Elf,
        maps: *const CreatedMaps,
        license: []const u8,
    ) !i32 {
        const prog: []u8 = try self.sec.read(gpa, file_reader);
        defer gpa.free(prog);
        try self.relocateMaps(e, prog, maps);

        const prog_name = self.objName(e);
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
        return @intCast(rc);
    }

    /// `.maps`のシンボルを参照するld_imm64命令に、作成済みマップのfdを書き込む。
    fn relocateMaps(self: Program, e: *const elf.Elf, insns: []u8, maps: *const CreatedMaps) !void {
        if (e.header.endian != .little) return error.UnsupportedEndian;
        const insn_size = @sizeOf(BPF.Insn);
        for (self.relocs) |r| {
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
};
