const std = @import("std");
const builtin = @import("builtin");
const clap = @import("clap");
// const clap = @import("../libs/zig-clap/clap.zig"); // For ZLS completions, not allowed when building

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
        \\<path>...     Ścieżki do przeszukania.
    );
    const parsers = comptime .{
        .path = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help)
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});

    var path_count: usize = 0;
    // TODO: change to an array that has "." if there are none
    // TODO: error on duplicate directories (also when absolute and relative paths given)
    for (res.positionals) |path| {
        path_count += 1;

        // TODO: see IterableDir.walk()
        var iter = (try std.fs.cwd().openIterableDir(path, .{})).iterate();

        while (try iter.next()) |entry| {
            const prefix: u8 = if (entry.kind == .Directory) 'd' else ' ';
            std.debug.print("{c} {s}\n", .{ prefix, entry.name });
        }
    }

    if (path_count == 0) {
        std.debug.print("Użycie:\n", .{});
        return clap.usage(std.io.getStdErr().writer(), clap.Help, &params);
    }
}
