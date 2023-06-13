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
        \\-h, --help        Wyświetl tę pomoc i wyjdź.
        \\-v, --verbose     Wyświetlaj więcej informacji w trakcie pracy (można podać kilka razy)
        \\-q, --quiet       Wyświetlaj mniej informacji
        \\-i, --interactive Interaktywnie usuwaj pliki po przeszukaniu drzewa
        \\-d, --dirs        Traktuj nazwy folderów jako znaczące
        \\--exclude <str>   Ignoruj pliki zawierające ten tekst w ścieżce
        \\<path>...         Ścieżki do przeszukania.
    ); // FIXME: Doesn't print the whole <path> line
    // Arguments roadmap:
    // \\-s, --save <file>  Zapisz wyniki skanowania do pliku JSON
    // \\-l, --load <file>  Wczytaj zapisane drzewo zamiast skanować ścieżkę
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

    var search_paths = if (res.positionals.len > 0) res.positionals else @as([]const []const u8, &[_][]const u8{"."});

    // first put all the ancestors, so they can later be excluded from results just by index
    var search_paths_ancestors: usize = 0; // count of folders above the passed paths
    for (search_paths) |path| {
        const realpath = try (try std.fs.cwd().openDir(path, .{})).realpath(".", &realpath_buf);
        // this workaround is necessary, because there are still bugs with ".." on windows
        // doesn't add anything if realpath doesn't contain any separator (like "C:")
        if (std.mem.lastIndexOfScalar(u8, realpath, std.fs.path.sep)) |parent_subpath_len| {
            const parent_realpath = realpath[0..parent_subpath_len];
            search_paths_ancestors = try dir_tree.findOrAddPathIndex(&node_list, parent_realpath) + 1; // save count
        }
    }

    { // add search_paths and check that they aren't contained in another
        var search_indices = std.ArrayList(usize).init(alloc);
        defer search_indices.deinit();

        for (search_paths) |path| {
            const realpath = try (try std.fs.cwd().openDir(path, .{})).realpath(".", &realpath_buf);
            const index = try dir_tree.findOrAddPathIndex(&node_list, realpath);
            try search_indices.append(index);
        }

        for (search_indices.items) |index| {
            var index_array = [1]usize{index}; // HACK: need a slice for std.mem.count
            if (std.mem.containsAtLeast(usize, search_indices.items, 2, &index_array)) {
                std.debug.print("Błąd: zduplikowana ścieżka:\n{s}\n", .{try TreeNode.fullPath(&node_list.items[index], node_list.items, &realpath_buf)});
                return;
            }

            var ancestor_index: ?usize = node_list.items[index].parent_index;
            while (ancestor_index) |a_idx| {
                index_array[0] = a_idx;
                if (std.mem.containsAtLeast(usize, search_indices.items, 1, &index_array)) {
                    std.debug.print("Błąd: ścieżka zawarta w innej:\n{s}\n{s}\n", .{ try TreeNode.fullPath(&node_list.items[index], node_list.items, &realpath_buf), try TreeNode.fullPath(&node_list.items[a_idx], node_list.items, &realpath_buf) });
                    return;
                }
                ancestor_index = node_list.items[a_idx].parent_index;
            }
        }
    }

    var file_count: usize = 0;
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
        var hash_buf: [dir_tree.hash_len]u8 = undefined;
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

        // include directory structure into hash
        // at this point the content hash is complete, also add the name
        // hash of a hash is different, so multiple nestings will give a different result
        if (res.args.dirs != 0 and node.info == .dir) {
            var hash = std.crypto.hash.Md5.init(.{});
            if (node.hash) |node_hash| { // can be null for childless directory
                hash.update(node_hash[0..]);
            }
            hash.update(&node.name);
            var hash_buf: [dir_tree.hash_len]u8 = undefined;
            hash.final(&hash_buf); // this is needed because node.hash is optional
            nodes[i_rev].hash = hash_buf;
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
                if (!std.mem.eql(u8, &last_hash, &hash)) {
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
        var last_hash = [_]u8{0} ** dir_tree.hash_len;
        var options_list = std.ArrayList(*TreeNode).init(alloc);
        defer options_list.deinit();
        var handled_duplicates: usize = 0;

        for (node_ptrs[0..nodes_with_siblings]) |node| {
            if (node.duplicate_hash) {
                if (node.parent_index) |parent_index| {
                    if (nodes[parent_index].duplicate_hash) continue;
                }
                const hash = node.hash.?;
                if (!std.mem.eql(u8, &last_hash, &hash) and options_list.items.len > 0) {
                    handled_duplicates += 1;
                    const deleted_now = try interactiveDeletion(nodes, options_list.items, handled_duplicates, duplicate_elements);
                    deleted_size += deleted_now orelse 0;
                    options_list.clearRetainingCapacity();
                }
                try options_list.append(node);
                @memcpy(&last_hash, &hash);
            }
        }

        if (options_list.items.len > 0) {
            handled_duplicates += 1;
            const deleted_now = try interactiveDeletion(nodes, options_list.items, handled_duplicates, duplicate_elements);
            deleted_size += deleted_now orelse 0;
        }

        std.debug.print("Usunięto pliki o łącznym rozmiarze {s}\n", .{utils.formatSize(deleted_size)});
    }
}

fn interactiveDeletion(nodes: []TreeNode, options: []*TreeNode, handled_duplicates: usize, duplicate_elements: usize) !?u64 {
    std.debug.assert(options.len > 1); // doesn't make sense to only have one duplicate

    const stdout = std.io.getStdOut();
    var out_writer = stdout.writer();
    const stdin = std.io.getStdIn();
    var input_buffer: [dir_tree.max_name_len]u8 = undefined;
    var realpath_buf: [dir_tree.max_path_len]u8 = undefined;
    while (true) {
        try out_writer.print("\n{d}/{d} Wybierz obiekt (rozmiar {s}) do pozostawienia, 'n' aby pominąć usuwanie, lub '0' aby usunąć wszystkie\n", .{ handled_duplicates, duplicate_elements, utils.formatSize(options[0].size) });

        std.sort.sort(*TreeNode, options, {}, TreeNode.nameAsc);
        for (options, 1..) |option, i| {
            try out_writer.print("{d}: {s}\n", .{ i, try TreeNode.fullPath(option, nodes, &realpath_buf) });
        }

        var deleted_size: u64 = 0;
        const input = (try utils.nextLine(stdin.reader(), &input_buffer)).?;
        if (input[0] == 'n') {
            try out_writer.print("Pomijam usuwanie obiektu\n", .{});
            return null;
        } else if (std.fmt.parseInt(u16, input, 10) catch null) |choice| {
            if (choice == 0) {
                try out_writer.print("Usuwam wszystkie obiekty\n", .{});
            } else if (choice <= options.len) {
                try out_writer.print("Pozostawiam {d}\n", .{choice});
            } else {
                try out_writer.print("Podana liczba jest większa niż liczba opcji\n", .{});
                continue;
            }
            var error_count: u64 = 0;
            for (options, 1..) |deleted_node, i| {
                if (i != choice) {
                    const realpath = try TreeNode.fullPath(deleted_node, nodes, &realpath_buf);
                    std.fs.deleteTreeAbsolute(realpath) catch |err| {
                        std.debug.print("Błąd '{s}' przy usuwaniu pliku: {s}\n", .{ @errorName(err), realpath });
                        error_count += 1;
                        continue;
                    };
                    deleted_size += deleted_node.size;
                }
            }
            if (error_count > 0) continue;

            return deleted_size; // FIXME: for some reason crashes on this statement with "unreachable code reached"
        } else {
            try out_writer.print("Nie rozpoznano wejścia: {s}\n", .{input});
        }
    }
}
