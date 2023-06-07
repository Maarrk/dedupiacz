const std = @import("std");
const builtin = @import("builtin");
const clap = @import("clap");

const dir_tree = @import("dir_tree.zig");
const TreeNode = dir_tree.TreeNode;

const utils = @import("utils.zig");

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
        \\-v, --verbose Wyświetlaj więcej informacji w trakcie pracy (można podać kilka razy)
        \\-q, --quiet   Wyświetlaj mniej informacji
        \\-i, --interactive Interaktywnie usuwaj pliki po przeszukaniu drzewa
        \\--exclude <str>   Ignoruj pliki zawierające ten tekst w ścieżce
        \\<path>...     Ścieżki do przeszukania.
    );
    // TODO: \\-d, --dirs    Traktuj strukturę folderów jako znaczącą
    const parsers = comptime .{
        .str = clap.parsers.string,
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

    if (res.args.help != 0) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return;
    }
    const verbosity: i16 = @as(i16, res.args.verbose) - @as(i16, res.args.quiet);
    if (verbosity >= 2) std.debug.print("args: {any}", .{res.args});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var node_list = std.ArrayList(TreeNode).init(alloc);
    defer node_list.deinit();
    try node_list.append(TreeNode.initRoot());

    var realpath_buf: [dir_tree.max_path_len]u8 = undefined;

    var file_count: usize = 0;
    var search_paths_ancestors: usize = 0; // count of folders above the passed paths, will be used to exclude them from results

    // to match the types, cast array literal to "[]T - pointer to runtime-known number of items", hence the need for &
    var search_paths = if (res.positionals.len > 0) res.positionals else @as([]const []const u8, &[_][]const u8{"."});
    for (search_paths) |path| {
        const realpath = try (try std.fs.cwd().openDir(path, .{})).realpath(".", &realpath_buf);
        // this workaround is necessary, because there are still bugs with ".." on windows
        // FIXME: will fail if realpath doesn't contain any separator (like "C:")
        const parent_realpath = realpath[0..std.mem.lastIndexOfScalar(u8, realpath, std.fs.path.sep).?];
        search_paths_ancestors = try dir_tree.findOrAddPathIndex(&node_list, parent_realpath) + 1; // save count
    }
    // TODO: Validate that none of the search_paths is equal or contained in another

    for (search_paths) |path| {
        var walker = try (try std.fs.cwd().openIterableDir(path, .{})).walk(alloc);
        defer walker.deinit();

        if (verbosity >= 0) std.debug.print("\nIndeksowanie {s} ...", .{path});
        while (try walker.next()) |entry| {
            if (entry.kind != .File) continue;

            const file_realpath = try entry.dir.realpath(entry.basename, &realpath_buf);
            if (res.args.exclude) |exclude_str| {
                if (std.mem.indexOf(u8, file_realpath, exclude_str) != null) {
                    if (verbosity >= 3) std.debug.print("Pomijanie pliku {s}\n", .{file_realpath});
                    continue;
                }
            }

            file_count += 1;
            if (verbosity >= 0 and file_count % 100 == 0) {
                std.debug.print("\rIndeksowanie {s} ... ({d} plików)", .{ path, file_count });
            }

            const dir_realpath = try entry.dir.realpath(".", &realpath_buf);
            const parent_index = try dir_tree.findOrAddPathIndex(&node_list, dir_realpath);
            const stat = try entry.dir.statFile(entry.basename);
            try node_list.append(try TreeNode.initFile(node_list.items, parent_index, entry.basename, stat.size));
        }
    }
    if (verbosity >= 0) std.debug.print("\n", .{});

    const nodes = node_list.items; // don't modify the list from now on

    dir_tree.sumFileSizes(nodes);
    if (verbosity >= 0) std.debug.print("Znaleziono {d} plików, całkowity rozmiar {s}\n", .{ file_count, utils.formatSize(nodes[0].size) });

    if (verbosity >= 2) {
        for (nodes[search_paths_ancestors..]) |*node| {
            std.debug.print("{s}\n", .{try TreeNode.fullPath(node, nodes, &realpath_buf)});
        }
        std.debug.print("\n", .{});
    }

    var node_ptrs: []*TreeNode = try alloc.alloc(*TreeNode, nodes.len);
    defer alloc.free(node_ptrs);

    { // put all files into node_ptrs
        var i: usize = 0;
        for (nodes) |*node| {
            if (node.info == .file) {
                node_ptrs[i] = node;
                i += 1;
            }
        }
    }
    std.sort.sort(*TreeNode, node_ptrs[0..file_count], {}, TreeNode.sizeDesc);

    if (verbosity >= 2) {
        std.debug.print("Posortowane pliki:\n", .{});
        for (node_ptrs[0..file_count]) |node| {
            std.debug.print("{s}\t{s}\n", .{ utils.formatSize(node.size), try TreeNode.fullPath(node, nodes, &realpath_buf) });
        }
        std.debug.print("\n", .{});
    }

    var same_size_count: u64 = 0;
    var same_size_size: u64 = 0;
    {
        // Check with either neighbor (to correctly count two and three consecutive files correctly, you have to check three per iteration)
        var i: usize = 0;
        while (i < file_count) : (i += 1) {
            const size = node_ptrs[i].size;
            if (i > 0 and node_ptrs[i - 1].size == size) {
                same_size_count += 1;
                same_size_size += node_ptrs[i].size;
                switch (node_ptrs[i].info) {
                    .file => |*info| info.duplicate_size = true,
                    .dir => unreachable, // only expect files here
                }
                continue; // Don't count the middle file twice
            }
            if (i < file_count - 1 and node_ptrs[i + 1].size == size) {
                same_size_count += 1;
                same_size_size += node_ptrs[i].size;
                switch (node_ptrs[i].info) {
                    .file => |*info| info.duplicate_size = true,
                    .dir => unreachable, // only expect files here
                }
            }
        }
    }
    if (verbosity >= 0) std.debug.print("{d} plików ma ten sam rozmiar\n", .{same_size_count});

    const hash_start_time = std.time.timestamp();
    var done_hashes_count: u64 = 0;
    var done_hashes_size: u64 = 0;
    for (node_ptrs[0..file_count]) |node| {
        switch (node.info) {
            .file => |info| if (!info.duplicate_size) continue,
            .dir => unreachable,
        }

        if (verbosity >= 0) std.debug.print("przetwarzanie pliku {s}", .{utils.formatSize(node.size)});
        var hash = std.crypto.hash.Md5.init(.{});
        var file = try std.fs.openFileAbsoluteZ(@ptrCast([*:0]const u8, try TreeNode.fullPath(node, nodes, &realpath_buf)), .{});
        defer file.close();
        var buf_reader = std.io.bufferedReader(file.reader());
        var in_stream = buf_reader.reader();

        var buf: [1024]u8 = undefined;
        while (try in_stream.read(&buf) > 0) {
            hash.update(&buf);
        }
        var hash_buf: [16]u8 = undefined;
        hash.final(&hash_buf);
        node.hash = hash_buf;

        const time_elapsed = std.math.absCast(std.time.timestamp() - hash_start_time);
        done_hashes_count += 1;
        const count_part: f64 = @intToFloat(f64, done_hashes_count) / @intToFloat(f64, same_size_count);
        const count_eta: u64 = std.math.absCast(@floatToInt(i64, @intToFloat(f64, time_elapsed) / count_part * (1 - count_part)));
        done_hashes_size += node.size;
        const size_part: f64 = @intToFloat(f64, done_hashes_size) / @intToFloat(f64, same_size_size);
        const size_eta: u64 = std.math.absCast(@floatToInt(i64, @intToFloat(f64, time_elapsed) / size_part * (1 - size_part)));

        if (verbosity >= 0) std.debug.print("\r{s}: {d}/{d} ({d:.2}% ETA: {s}), {s}/{s} ({d:.2}% ETA: {s}), ", .{ utils.formatTime(time_elapsed), done_hashes_count, same_size_count, count_part * 100, utils.formatTime(count_eta), utils.formatSize(done_hashes_size), utils.formatSize(same_size_size), size_part * 100, utils.formatTime(size_eta) });
    }
    if (verbosity >= 0) std.debug.print("{s}\n", .{[_]u8{' '} ** 25}); // overwrite the opened file text from loop

    // // TODO: Include directory structure
    // if (res.args.dirs != 0) {

    // }

    std.sort.sort(*TreeNode, node_ptrs[0..file_count], {}, TreeNode.sizeDesc); // also sorts by hash
    var same_file_hash_count: u64 = 0;
    {
        var i: usize = 0;
        while (i < file_count) : (i += 1) {
            if (node_ptrs[i].hash) |hash| {
                if (i > 0) {
                    if (node_ptrs[i - 1].hash) |prev_hash| {
                        if (std.mem.eql(u8, &hash, &prev_hash)) {
                            node_ptrs[i].duplicate_hash = true;
                            same_file_hash_count += 1;
                            continue; // Skip comparison with next
                        }
                    }
                }

                if (i < file_count - 1) {
                    if (node_ptrs[i + 1].hash) |next_hash| {
                        if (std.mem.eql(u8, &hash, &next_hash)) {
                            node_ptrs[i].duplicate_hash = true;
                            same_file_hash_count += 1;
                        }
                    }
                }
            }
        }
    }
    if (verbosity >= 0) std.debug.print("Znaleziono {d} plików o tej samej zawartości\n", .{same_file_hash_count});

    for (0..nodes.len) |i| { // add hashes into parents
        const i_rev = nodes.len - 1 - i;
        const node = nodes[i_rev];
        if (node.parent_index) |parent_index| {
            if (node.hash) |hash| {
                nodes[parent_index].addHash(hash);
            } else {
                nodes[parent_index].addSize(node.size);
            }
        }
    }

    // Find duplicate hashes for directories
    // Only consider nodes at or below search_paths, and only nodes with sibling to avoid marking identical child as duplicate
    var nodes_with_siblings: usize = 0;
    for (nodes[search_paths_ancestors..]) |*node| {
        const parent = nodes[node.parent_index.?]; // Since ancestors are skipped, there definitely isn't root node
        const parent_info: dir_tree.DirInfo = switch (parent.info) {
            .dir => |info| info,
            .file => unreachable, // Files can't be parents
        };
        if (parent_info.dir_children + parent_info.file_children > 1) {
            node_ptrs[nodes_with_siblings] = node;
            nodes_with_siblings += 1;
        }
    }
    std.sort.sort(*TreeNode, node_ptrs[0..nodes_with_siblings], {}, TreeNode.sizeDesc);
    {
        var i: usize = 0;
        while (i < nodes_with_siblings) : (i += 1) {
            if (node_ptrs[i].hash) |hash| {
                if (i > 0) {
                    if (node_ptrs[i - 1].hash) |prev_hash| {
                        if (std.mem.eql(u8, &hash, &prev_hash)) {
                            node_ptrs[i].duplicate_hash = true;
                            continue; // Skip comparison with next
                        }
                    }
                }

                if (i < nodes_with_siblings - 1) {
                    if (node_ptrs[i + 1].hash) |next_hash| {
                        if (std.mem.eql(u8, &hash, &next_hash)) {
                            node_ptrs[i].duplicate_hash = true;
                        }
                    }
                }
            }
        }
    }

    var duplicate_files: usize = 0;
    var duplicate_dirs: usize = 0;
    var duplicate_elements: usize = 0;
    var deleted_size: u64 = 0;
    {
        const stdout = std.io.getStdOut();
        var out_writer = stdout.writer();
        var last_hash = [_]u8{0} ** dir_tree.hash_len;
        for (node_ptrs[0..nodes_with_siblings]) |node| {
            if (node.duplicate_hash) {
                switch (node.info) {
                    .file => duplicate_files += 1,
                    .dir => duplicate_dirs += 1,
                }

                if (node.parent_index) |parent_index| {
                    if (nodes[parent_index].duplicate_hash) continue;
                }
                const hash = node.hash.?;
                if (!std.mem.eql(u8, &last_hash, &hash)) { // FIXME: some way to also show the last pair
                    if (res.args.interactive == 0) try out_writer.print("\n", .{});
                    duplicate_elements += 1;
                }
                if (res.args.interactive == 0) try out_writer.print("{s}\t{s}\n", .{ utils.formatSize(node.size), try TreeNode.fullPath(node, nodes, &realpath_buf) });
                @memcpy(&last_hash, &hash);
            }
        }
    }
    if (verbosity >= 0) std.debug.print("Rozpoznano {d} zduplikowanych folderów i {d} pojedynczych plików\n", .{ duplicate_dirs, duplicate_files });

    if (res.args.interactive != 0) {
        const stdout = std.io.getStdOut();
        var out_writer = stdout.writer();
        var last_hash = [_]u8{0} ** dir_tree.hash_len;
        const stdin = std.io.getStdIn();
        var input_buffer: [dir_tree.max_name_len]u8 = undefined;
        var options_list = std.ArrayList(*TreeNode).init(alloc);
        defer options_list.deinit();
        var handled_duplicates: usize = 0;

        for (node_ptrs[0..nodes_with_siblings]) |node| {
            if (node.duplicate_hash) {
                if (node.parent_index) |parent_index| {
                    if (nodes[parent_index].duplicate_hash) continue;
                }
                const hash = node.hash.?;
                if (!std.mem.eql(u8, &last_hash, &hash) and options_list.items.len > 0) { // FIXME: some way to also show the last pair
                    handled_duplicates += 1;
                    try out_writer.print("\n{d}/{d} Wybierz plik (rozmiar {s}) do pozostawienia, lub 'n' aby pominąć usuwanie\n", .{ handled_duplicates, duplicate_elements, utils.formatSize(options_list.items[0].size) });

                    std.sort.sort(*TreeNode, options_list.items, {}, TreeNode.nameAsc);
                    for (options_list.items, 1..) |option, i| {
                        try out_writer.print("{d}: {s}\n", .{ i, try TreeNode.fullPath(option, nodes, &realpath_buf) });
                    }

                    const input = (try utils.nextLine(stdin.reader(), &input_buffer)).?;
                    if (input[0] == 'n') {
                        try out_writer.print("Pomijam usuwanie pliku\n", .{});
                    } else if (std.fmt.parseInt(u16, input, 10) catch null) |choice| {
                        try out_writer.print("Pozostawiam {d}\n", .{choice});
                        for (options_list.items, 1..) |deleted_node, i| {
                            if (i != choice) {
                                try std.fs.deleteTreeAbsolute(try TreeNode.fullPath(deleted_node, nodes, &realpath_buf));
                                deleted_size += deleted_node.size;
                            }
                        }
                    }
                    options_list.clearRetainingCapacity();
                }
                try options_list.append(node);
                @memcpy(&last_hash, &hash);
            }
        }

        std.debug.print("Usunięto pliki o łącznym rozmiarze {s}\n", .{utils.formatSize(deleted_size)});
    }
}
