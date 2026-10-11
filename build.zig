const std = @import("std");

pub fn build(b: *std.Build) void {
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

    const ebpf_mod = b.createModule(.{
        .target = b.resolveTargetQuery(.{ .cpu_arch = .bpfel }),
        .optimize = .debug,
        .link_libc = false,
    });
    ebpf_mod.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
    ebpf_mod.addCSourceFile(.{ .file = b.path("./testdata/simple.bpf.c") });
    const bpf_obj = b.addObject(.{
        .name = "simple",
        .root_module = ebpf_mod,
    });
    const install_bpf = b.addInstallFile(bpf_obj.getEmittedBin(), "simple.bpf.o");
    b.getInstallStep().dependOn(&install_bpf.step);

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
