const std = @import("std");
const builtin = @import("builtin");
const clap = @import("clap");
// const clap = @import("../libs/zig-clap/clap.zig"); // For ZLS completions, not allowed when building

const MAX_PATH_LEN: comptime_int = 256;
const HASH_LEN: comptime_int = 16;

const FileInfo = struct {
    full_path: [MAX_PATH_LEN]u8 = [_]u8{0} ** MAX_PATH_LEN,
    size: u64,
    duplicate_size: bool = false,
    hash: ?[HASH_LEN]u8 = null,
    duplicate_hash: bool = false,

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

    var total_size: u64 = 0;
    for (file_list.items) |info| {
        total_size += info.size;
    }
    std.debug.print("Znaleziono {d} plików, całkowity rozmiar {s}\n", .{ file_list.items.len, format_size(total_size) });

    std.sort.sort(FileInfo, file_list.items, {}, FileInfo.size_desc);
    const files = file_list.items; // Only edit specific fields from now on

    var same_size_count: u64 = 0;
    {
        // Check with either neighbor (to correctly count two and three consecutive files correctly, you have to check three per iteration)
        var i: usize = 0;
        while (i < files.len) : (i += 1) {
            const size = files[i].size;
            if (i > 0) {
                if (files[i - 1].size == size) {
                    same_size_count += 1;
                    files[i].duplicate_size = true;
                    continue; // Don't count the middle file twice
                }
            }
            if (i < files.len - 1) {
                if (files[i + 1].size == size) {
                    same_size_count += 1;
                    files[i].duplicate_size = true;
                }
            }
        }
    }
    std.debug.print("{d} plików ma ten sam rozmiar\n", .{same_size_count});

    var done_hashes_count: u64 = 0;
    for (files) |info, i| {
        if (info.duplicate_size) {
            var hash = std.crypto.hash.Md5.init(.{});
            var file = try std.fs.openFileAbsoluteZ(@ptrCast([*:0]const u8, &info.full_path), .{});
            defer file.close();
            var buf_reader = std.io.bufferedReader(file.reader());
            var in_stream = buf_reader.reader();

            var buf: [1024]u8 = undefined;
            while (try in_stream.read(&buf) > 0) {
                hash.update(&buf);
            }
            var hash_buf: [16]u8 = undefined;
            hash.final(&hash_buf);
            files[i].hash = hash_buf;

            done_hashes_count += 1;
        }
    }

    var same_hash_count: u64 = 0;
    {
        var i: usize = 0;
        while (i < files.len) : (i += 1) {
            if (files[i].hash) |hash| {
                if (i > 0) {
                    if (files[i - 1].hash) |prev_hash| {
                        if (std.mem.eql(u8, &hash, &prev_hash)) {
                            files[i].duplicate_hash = true;
                            same_hash_count += 1;
                            continue; // Skip comparison with next
                        }
                    }
                }

                if (i < files.len - 1) {
                    if (files[i + 1].hash) |next_hash| {
                        if (std.mem.eql(u8, &hash, &next_hash)) {
                            files[i].duplicate_hash = true;
                            same_hash_count += 1;
                        }
                    }
                }
            }
        }
    }
    std.debug.print("Znaleziono {d} plików o tej samej zawartości\n", .{same_hash_count});

    {
        var stdout = std.io.getStdOut();
        var writer = stdout.writer();
        var last_hash = [_]u8{0} ** HASH_LEN;
        for (file_list.items) |info| {
            if (info.duplicate_hash) {
                const hash = info.hash.?;
                if (!std.mem.eql(u8, &last_hash, &hash)) {
                    try writer.print("\n", .{});
                }
                try writer.print("{s}\t{s}\n", .{ format_size(info.size), info.full_path });
                std.mem.copy(u8, &last_hash, &hash);
            }
        }
    }
}

fn format_size(size: u64) [5]u8 {
    const suffixes = [_]u8{ 'B', 'K', 'M', 'G', 'T', 'P', 'E' };
    const kibi: f64 = 1024;
    var size_left = @intToFloat(f64, size);
    var suffix_index: usize = 0;
    while (size_left >= kibi) {
        suffix_index += 1;
        size_left /= kibi;
    }

    var result = [_]u8{' '} ** 5;
    if (size_left < 10) {
        if (suffix_index == 0) {
            _ = std.fmt.bufPrint(&result, "   {d}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        } else {
            _ = std.fmt.bufPrint(&result, "{d:.2}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        }
    } else if (size_left < 100) {
        if (suffix_index == 0) {
            _ = std.fmt.bufPrint(&result, "  {d}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        } else {
            _ = std.fmt.bufPrint(&result, "{d:.1}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        }
    } else if (size_left < 1000) {
        _ = std.fmt.bufPrint(&result, " {d}{c}", .{ @floor(size_left), suffixes[suffix_index] }) catch unreachable;
    } else { // 1000 to 1023
        _ = std.fmt.bufPrint(&result, "{d}{c}", .{ @floor(size_left), suffixes[suffix_index] }) catch unreachable;
    }

    return result;
}
