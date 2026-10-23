const std = @import("std");
const elf = std.elf;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const StringTable = @import("utils.zig").StringTable;

pub const Section = struct {
    name: []const u8,
    shdr: elf.Elf64_Shdr,
    endian: std.builtin.Endian,

    /// Reads the whole section into a newly allocated buffer. Caller owns the result.
    pub fn read(self: Section, gpa: Allocator, file_reader: *Io.File.Reader) ![]u8 {
        try file_reader.seekTo(self.shdr.sh_offset);
        return file_reader.interface.readAlloc(gpa, @intCast(self.shdr.sh_size));
    }

    /// Reads a `SHT_REL` section into relocation entries. Caller owns the result.
    pub fn readRelocations(self: Section, gpa: Allocator, file_reader: *Io.File.Reader) ![]elf.Elf64_Rel {
        if (self.shdr.sh_type != elf.SHT_REL) return error.NotRelocationSection;
        const entry_size = @sizeOf(elf.Elf64_Rel);
        if (self.shdr.sh_size % entry_size != 0) return error.InvalidRelocationSection;
        try file_reader.seekTo(self.shdr.sh_offset);
        return file_reader.interface.readSliceEndianAlloc(gpa, elf.Elf64_Rel, self.shdr.sh_size / entry_size, self.endian);
    }

    /// Reads a `T` from the start of the section, without allocating.
    pub fn readAs(self: Section, comptime T: type, file_reader: *Io.File.Reader, offset: usize) !T {
        if (@sizeOf(T) > self.shdr.sh_size) return error.SectionTooSmall;
        try file_reader.seekTo(self.shdr.sh_offset + offset);
        return file_reader.interface.takeStruct(T, self.endian);
    }
};

pub const Elf = struct {
    header: elf.Header,
    /// Section names, pointed to by `e_shstrndx`.
    shstrtab: StringTable,
    /// Symbol names, pointed to by the `sh_link` of `.symtab`. Null if there is no `.symtab`.
    strtab: ?StringTable,
    /// Entries of `.symtab`, which is what `Elf64_Rel.r_sym()` indexes. Empty if there is none.
    symbols: []elf.Elf64_Sym,
    sections: []Section,

    pub const InitError = error{
        NoSectionNameTable,
        InvalidSymtabLink,
    } || StringTable.Error || Allocator.Error || elf.Header.ReadError || Io.Reader.Error || Io.File.Reader.SeekError;

    pub fn init(gpa: Allocator, file_reader: *Io.File.Reader) InitError!Elf {
        const header = try elf.Header.read(&file_reader.interface);

        if (header.shstrndx == elf.SHN_UNDEF or header.shstrndx >= header.shnum) {
            return error.NoSectionNameTable;
        }

        const sections = try gpa.alloc(Section, header.shnum);
        errdefer gpa.free(sections);

        var it = header.iterateSectionHeaders(file_reader);
        var n: usize = 0;
        while (try it.next()) |shdr| : (n += 1) {
            sections[n] = .{ .name = "", .shdr = shdr, .endian = header.endian };
        }

        const shstrtab = try readStringTable(gpa, file_reader, sections[header.shstrndx]);
        errdefer shstrtab.deinit(gpa);

        for (sections) |*sec| {
            sec.name = try shstrtab.get(sec.shdr.sh_name);
        }

        var strtab: ?StringTable = null;
        errdefer if (strtab) |t| t.deinit(gpa);
        var symbols: []elf.Elf64_Sym = &.{};
        errdefer gpa.free(symbols);
        for (sections) |sec| {
            if (sec.shdr.sh_type != elf.SHT_SYMTAB) continue;
            if (sec.shdr.sh_link == elf.SHN_UNDEF or sec.shdr.sh_link >= sections.len) {
                return error.InvalidSymtabLink;
            }
            strtab = try readStringTable(gpa, file_reader, sections[sec.shdr.sh_link]);
            try file_reader.seekTo(sec.shdr.sh_offset);
            symbols = try file_reader.interface.readSliceEndianAlloc(gpa, elf.Elf64_Sym, sec.shdr.sh_size / @sizeOf(elf.Elf64_Sym), header.endian);
            break;
        }

        return .{ .header = header, .shstrtab = shstrtab, .strtab = strtab, .symbols = symbols, .sections = sections };
    }

    fn readStringTable(gpa: Allocator, file_reader: *Io.File.Reader, sec: Section) !StringTable {
        return .{ .data = try sec.read(gpa, file_reader) };
    }

    /// Name of a symbol (`Elf64_Sym.st_name`), like libbpf's `elf_sym_str`.
    pub fn symName(self: *const Elf, st_name: u32) ![]const u8 {
        const strtab = self.strtab orelse return error.NoSymbolNameTable;
        return strtab.get(st_name);
    }

    /// `st_value` of the symbol `name` defined in section `shndx`, i.e. its offset inside that section.
    pub fn symbolOffset(self: *const Elf, name: []const u8, shndx: usize) !u64 {
        for (self.symbols) |sym| {
            if (sym.st_shndx != shndx) continue;
            if (std.mem.eql(u8, try self.symName(sym.st_name), name)) return sym.st_value;
        }
        return error.SymbolNotFound;
    }

    /// Name of the function symbol defined in section `shndx`, like the program name libbpf uses.
    pub fn funcName(self: *const Elf, shndx: usize) ?[]const u8 {
        for (self.symbols) |sym| {
            if (sym.st_shndx != shndx or (sym.st_info & 0xf) != elf.STT_FUNC) continue;
            return self.symName(sym.st_name) catch null;
        }
        return null;
    }

    pub fn deinit(self: *Elf, gpa: Allocator) void {
        gpa.free(self.sections);
        gpa.free(self.symbols);
        self.shstrtab.deinit(gpa);
        if (self.strtab) |t| t.deinit(gpa);
        self.* = undefined;
    }
};
