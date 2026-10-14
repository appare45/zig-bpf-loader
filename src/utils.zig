const std = @import("std");

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
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
