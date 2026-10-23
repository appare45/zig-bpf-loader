const std = @import("std");

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

/// bpffs (`mount -t bpf`) の通常のマウント先。ここにpinしたオブジェクトはプロセスが終わっても残る。
const pin_dir = "/sys/fs/bpf";

/// `BPF_OBJ_PIN`: bpffsの`pin_dir/name`にfdのオブジェクト(プログラム/マップ)を固定する。
pub fn pinObject(fd: i32, name: []const u8) !void {
    const BPF = std.os.linux.BPF;
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

/// NUL-terminated strings packed back to back (.shstrtab / .strtab).
pub const StringTable = struct {
    data: []u8,

    pub const Error = error{ StringOutOfRange, StringNotTerminated };

    /// Copies `bytes` into a new table.
    pub fn init(gpa: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!StringTable {
        return .{ .data = try gpa.dupe(u8, bytes) };
    }

    /// Frees `data`, so the table must own it.
    pub fn deinit(self: StringTable, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }

    /// Returns the string starting at `offset`, borrowed from `data`.
    pub fn get(self: StringTable, offset: u32) Error![]const u8 {
        if (offset >= self.data.len) return error.StringOutOfRange;
        const end = std.mem.indexOfScalarPos(u8, self.data, offset, 0) orelse
            return error.StringNotTerminated;
        return self.data[offset..end];
    }
};
