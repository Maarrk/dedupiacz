const std = @import("std");
const builtin = @import("builtin");
const clap = @import("clap");
// const clap = @import("../libs/zig-clap/clap.zig"); // For ZLS completions, not allowed when building

const MAX_PATH_LEN: comptime_int = 256;
const HASH_LEN: comptime_int = 16;

const FileInfo = struct {
    full_path: [MAX_PATH_LEN]u8 = [_]u8{0} ** MAX_PATH_LEN,
    size: u64,
    hash: ?[HASH_LEN]u8 = null,

    fn size_desc(context: void, a: FileInfo, b: FileInfo) bool {
        _ = context;
        return a.size > b.size;
    }
};

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
        return;
    };
    defer res.deinit();

    if (res.args.help) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var realpath_set = std.StringHashMap(void).init(alloc);
    defer realpath_set.deinit();
    const realpath_buf: []u8 = try alloc.alloc(u8, MAX_PATH_LEN);
    defer alloc.free(realpath_buf);

    var file_count: u64 = 0;
    var file_list = std.ArrayList(FileInfo).init(alloc);
    defer file_list.deinit();

    // to match the types, cast array literal to "[]T - pointer to runtime-known number of items", hence the need for &
    var search_paths = if (res.positionals.len > 0) res.positionals else @as([]const []const u8, &[_][]const u8{"."});
    for (search_paths) |path| {
        const realpath = try std.fs.cwd().realpath(path, realpath_buf);
        // FIXME: Doesn't detect duplication if one contains the other
        if (realpath_set.contains(realpath)) {
            std.debug.print("Błąd: ścieżka '{s}' podana wielokrotnie (argument: '{s}')", .{ realpath, path });
            return;
        }
        try realpath_set.put(realpath, {});

        var walker = try (try std.fs.cwd().openIterableDir(path, .{})).walk(alloc);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind != .File) continue;
            file_count += 1;

            const stat = try entry.dir.statFile(entry.basename);
            const file_realpath = try entry.dir.realpath(entry.basename, realpath_buf);
            var info = FileInfo{
                .size = stat.size,
            };
            std.mem.copy(u8, &info.full_path, file_realpath);
            try file_list.append(info);
        }
    }

    std.sort.sort(FileInfo, file_list.items, {}, FileInfo.size_desc);
    for (file_list.items) |info| {
        std.debug.print("{d}\t{s}\n", .{info.size, info.full_path});
    }
}
