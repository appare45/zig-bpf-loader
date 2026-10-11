const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module, exposed to consumers of this package.
    const mod = b.addModule("zig_bpf_loader", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // CLI executable built on top of the library module.
    const exe = b.addExecutable(.{
        .name = "zig_bpf_loader",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_bpf_loader", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const io = b.graph.io;
    const arena = b.graph.arena;

    const testdir_path = b.path("testdata");
    const testdata_dir = try b.root.openDir(io, "testdata/", .{ .iterate = true });
    defer testdata_dir.close(io);

    var walker = try testdata_dir.walk(arena);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, "bpf.c")) continue; // zigでもビルドできるようにするる?
        const basename = std.mem.cutSuffix(u8, entry.basename, ".bpf.c") orelse continue;
        addBpfProgram(b, testdir_path.path(b, entry.basename), basename);
    }

    // `zig build run -- <args>`
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the app").dependOn(&run_cmd.step);

    // `zig build test`: run tests of both the library and the executable.
    const test_step = b.step("test", "Run tests");
    inline for (.{ mod, exe.root_module }) |m| {
        const t = b.addTest(.{ .root_module = m });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // `zig build check`: compile only, useful for editor integration (ZLS).
    b.step("check", "Check if the app compiles").dependOn(&exe.step);
}

/// Builds one eBPF C source with both zig cc and clang, and installs the
/// results as `<name>.bpf.o` and `<name>.clang.o`.
fn addBpfProgram(b: *std.Build, src: std.Build.LazyPath, name: []const u8) void {
    const ebpf_mod = b.createModule(.{
        .target = b.resolveTargetQuery(.{ .cpu_arch = .bpfel }),
        .optimize = .debug,
        .link_libc = false,
    });
    ebpf_mod.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
    ebpf_mod.addCSourceFile(.{ .file = src });
    const bpf_obj = b.addObject(.{
        .name = name,
        .root_module = ebpf_mod,
    });
    const install_bpf = b.addInstallFile(bpf_obj.getEmittedBin(), b.fmt("{s}.bpf.o", .{name}));
    b.getInstallStep().dependOn(&install_bpf.step);

    const clang_build = b.addSystemCommand(&.{ "clang", "-g", "-O2", "-Wall", "-target", "bpf", "-D__TARGET_ARCH_x64" });
    clang_build.addArg("-c");
    clang_build.addFileArg(src);
    clang_build.addArg("-o");
    const out = clang_build.addOutputFileArg("bpf_tmp");
    const install_bpf_clang = b.addInstallFile(out, b.fmt("{s}.clang.o", .{name}));
    b.getInstallStep().dependOn(&install_bpf_clang.step);
}
