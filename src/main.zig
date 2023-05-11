const std = @import("std");
const builtin = @import("builtin");
// const clap = @import("clap");
const clap = @import("../libs/zig-clap/clap.zig"); // For ZLS completions, not allowed when building

pub fn main() !void {
    // On Windows, set the console code page to UTF-8
    if (builtin.os.tag == .windows) {
        const windows = @cImport({
            @cInclude("windows.h");
        });
        const res = windows.SetConsoleOutputCP(65001);
        if (res == 0) {
            std.debug.print("Błąd w ustawianiu strony kodowania", .{});
        }
    }

    const params = comptime clap.parseParamsComptime(
        \\-h, --help    Wyświetl tę pomoc i wyjdź.
        \\<str>         Ścieżka do przeszukania.
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help)
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});

    try std.io.getStdOut().writer().print("Witaj, świecie!\n", .{});
}
