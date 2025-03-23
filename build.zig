const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "server",
        .target = target,
        .optimize = optimize,
    });

    exe.addCSourceFile(.{
        .file = b.path("src/main.c"),
        .flags = &.{"--std=gnu23"},
    });

    exe.linkLibC();
    exe.linkSystemLibrary("c");

    b.installArtifact(exe);
}
