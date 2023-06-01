const std = @import("std");
const builtin = @import("builtin");
const clap = @import("clap");
// const clap = @import("../libs/zig-clap/clap.zig"); // For ZLS completions, not allowed when building

const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;

const MAX_PATH_LEN: comptime_int = 512;
const MAX_NAME_LEN: comptime_int = 64;
const HASH_LEN: comptime_int = 16;

const TreeNode = struct {
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    parent_index: ?usize, // can only be null at the root node
    size: u64 = 0,
    hash: ?[HASH_LEN]u8 = null,
    duplicate_hash: bool = false,
    info: NodeInfo,

    /// Use init_root, init_dir or init_file instead, to force passing correct arguments
    fn _init(nodes: []TreeNode, parent_index: usize, kind: NodeKind, name: []const u8) !TreeNode {
        switch (nodes[parent_index].info) {
            .dir => |*info| {
                switch (kind) {
                    .dir => info.dir_children += 1,
                    .file => info.file_children += 1,
                }
            },
            .file => return error.NonDirectoryParent,
        }

        var self = TreeNode{ .parent_index = parent_index, .info = switch (kind) {
            .dir => NodeInfo{ .dir = DirInfo{} },
            .file => NodeInfo{ .file = FileInfo{} },
        } };
        if (name.len > self.name.len) return error.NameTooLong;
        @memcpy(self.name[0..name.len], name);
        return self;
    }

    fn init_root() TreeNode {
        return TreeNode{
            .parent_index = null,
            .info = NodeInfo{ .dir = DirInfo{} },
        };
    }

    fn init_dir(nodes: []TreeNode, parent_index: usize, name: []const u8) !TreeNode {
        return TreeNode._init(nodes, parent_index, .dir, name);
    }

    fn init_file(nodes: []TreeNode, parent_index: usize, name: []const u8, size: u64) !TreeNode {
        var self = try TreeNode._init(nodes, parent_index, .file, name);
        self.size = size;
        return self;
    }

    /// Update every directory size with sum of size of its children.
    /// The `nodes` list must be sorted so that all children are after their parent
    fn sum_file_sizes(nodes: []TreeNode) void {
        for (nodes, 0..) |_, i| {
            const i_rev = nodes.len - 1 - i;
            const node = nodes[i_rev];
            if (node.parent_index) |p| {
                nodes[p].size += node.size;
            }
        }
    }

    /// Sort descending by size
    fn size_desc(context: void, a: *TreeNode, b: *TreeNode) bool {
        _ = context;
        return a.size > b.size;
    }

    /// Sorts nodes to get a deterministic, content-dependent order.
    /// (ascending hash, then ascending size)
    /// If hashes are not calculated, will sort by size (which must be unique for files, since no hash)
    /// Should work also for unstable sorts
    fn parent_hashing_order(context: void, a: *TreeNode, b: *TreeNode) bool {
        _ = context;
        if (a.hash) |a_hash| {
            if (b.hash) |b_hash| {
                return std.mem.order(u8, a_hash, b_hash) == .lt;
            } else {
                return true; // first files with hash
            }
        } else if (b.hash) {
            return false;
        } else {
            if (a.size == b.size) { // should only happen for a directory
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }
    }

    fn full_path(self: *TreeNode, nodes: []TreeNode, out_buffer: []u8) ![]u8 {
        var path_len: usize = 0;
        const offset = @ptrToInt(self) - @ptrToInt(&nodes[0]);
        var current_index: ?usize = @divExact(offset, @sizeOf(TreeNode));
        while (current_index) |i| { // iterate until we get a null (root node)
            // write the name in reverse
            const node = nodes[i];
            const name_slice = std.mem.sliceTo(&(node.name), 0);
            const new_end = path_len + name_slice.len;
            if (new_end > out_buffer.len) return error.NameTooLong;
            @memcpy(out_buffer[path_len..new_end], name_slice);
            std.mem.reverse(u8, out_buffer[path_len..new_end]);
            path_len = new_end;

            if (path_len + 1 > out_buffer.len) return error.NameTooLong;
            out_buffer[path_len] = std.fs.path.sep;
            path_len += 1;

            current_index = node.parent_index;
        }
        if (builtin.os.tag == .windows) {
            path_len -= 2; // strip backslash before and after root node
        } else {
            path_len -= 1; // strip slash before root node (so path starts with slash)
        }
        std.mem.reverse(u8, out_buffer[0..path_len]); // reverse back the name to go from root
        return out_buffer[0..path_len];
    }
};

test "absolute path of a node" {
    var nodes: [4]TreeNode = undefined;
    nodes[0] = TreeNode.init_root();
    nodes[1] = try TreeNode.init_dir(&nodes, 0, "C:");
    nodes[2] = try TreeNode.init_dir(&nodes, 1, "foo");
    nodes[3] = try TreeNode.init_file(&nodes, 2, "bar.txt", 1);

    var path_buffer: [MAX_PATH_LEN]u8 = undefined;
    const full_path = try TreeNode.full_path(&nodes[3], &nodes, &path_buffer);
    const expected_path = if (builtin.os.tag == .windows) "C:\\foo\\bar.txt" else "/C:/foo/bar.txt";

    try expectEqualStrings(expected_path, full_path);
}

test "counting children" {
    var nodes: [6]TreeNode = undefined;
    nodes[0] = TreeNode.init_root();
    nodes[1] = try TreeNode.init_dir(&nodes, 0, "C:"); // drive
    nodes[2] = try TreeNode.init_dir(&nodes, 1, "foo"); // dir
    nodes[3] = try TreeNode.init_file(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.init_file(&nodes, 2, "baz.zip", 2);
    nodes[5] = try TreeNode.init_file(&nodes, 1, "fubar", 4);

    switch (nodes[0].info) {
        .dir => |info| {
            try expectEqual(@as(u64, 1), info.dir_children);
            try expectEqual(@as(u64, 0), info.file_children);
        },
        .file => unreachable,
    }
    switch (nodes[1].info) {
        .dir => |info| {
            try expectEqual(@as(u64, 1), info.dir_children);
            try expectEqual(@as(u64, 1), info.file_children);
        },
        .file => unreachable,
    }
    switch (nodes[2].info) {
        .dir => |info| {
            try expectEqual(@as(u64, 0), info.dir_children);
            try expectEqual(@as(u64, 2), info.file_children);
        },
        .file => unreachable,
    }
}

test "directory sizes" {
    var nodes: [6]TreeNode = undefined;
    nodes[0] = TreeNode.init_root();
    nodes[1] = try TreeNode.init_dir(&nodes, 0, "C:"); // drive
    nodes[2] = try TreeNode.init_dir(&nodes, 1, "foo"); // dir
    nodes[3] = try TreeNode.init_file(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.init_file(&nodes, 2, "baz.zip", 2);
    nodes[5] = try TreeNode.init_file(&nodes, 1, "fubar", 4);

    TreeNode.sum_file_sizes(nodes[0..]);

    try expectEqual(@as(u64, 7), nodes[0].size);
    try expectEqual(@as(u64, 7), nodes[1].size);
    try expectEqual(@as(u64, 3), nodes[2].size);
}

const NodeKind = enum {
    dir,
    file,
};

const NodeInfo = union(NodeKind) {
    dir: DirInfo,
    file: FileInfo,
};

const DirInfo = struct {
    dir_children: u64 = 0,
    file_children: u64 = 0,
    hashed_children: u64 = 0,
    md5: ?*std.crypto.hash.Md5 = null,
};

const FileInfo = struct {
    duplicate_size: bool = false,
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

    // TODO: Overall algorithm:
    //
    // ## Directory tree
    //
    // Create ArrayList for TreeNodes
    // Set empty root element with invalid parent pointer as node 0 in list
    // For each path passed, add nodes for it, starting from root
    // This way every parent is on lower index in the list, and has a valid pointer
    // Save the length of nodes above passed paths
    // Add all passed paths
    // Walk the directory tree, creating nodes and linking up to parent dir
    // Add the size of file to parent dir, add relevant children count
    // Create immutable slice for all nodes, don't modify the list anymore
    //
    // ## Hashing the tree
    //
    // Create an ArrayList of pointers to TreeNodes
    // Sort pointer list by size
    // Calculate a hash for all the files with duplicate sizes
    // Sort pointer list by parent_hashing_order
    // For each file, put its hash or size into parent dir, increase hashed_children count
    //
    // ### Hashing directories
    //
    // Put all directories with all children hashed into a slice of pointer list
    // Sort by parent_hashing_order
    // Repeatedly get fully hashed dirs into the slice
    // Terminate when root is fully hashed
    //
    // ## Results
    //
    // Get a buffer of pointers to TreeNodes
    // Sort by hash
    // Mark all duplicate hashes
    // Sort by size descending
    // Print out all nodes whose parent isn't duplicate

    var tree_list = std.ArrayList(TreeNode).init(alloc);
    defer tree_list.deinit();

    {
        const root_node = TreeNode{
            .parent = @ptrCast(*TreeNode, null),
            .info = NodeInfo{.dir},
        };
        tree_list.append(root_node);
    }

    const realpath_buf: []u8 = try alloc.alloc(u8, MAX_PATH_LEN);
    defer alloc.free(realpath_buf);

    var file_count: u64 = 0;

    // to match the types, cast array literal to "[]T - pointer to runtime-known number of items", hence the need for &
    var search_paths = if (res.positionals.len > 0) res.positionals else @as([]const []const u8, &[_][]const u8{"."});
    for (search_paths) |path| {
        var walker = try (try std.fs.cwd().openIterableDir(path, .{})).walk(alloc);
        defer walker.deinit();

        std.debug.print("\nIndeksowanie {s} ...", .{path});
        while (try walker.next()) |entry| {
            if (entry.kind != .File) continue;

            file_count += 1;
            if (file_count % 100 == 0) {
                std.debug.print("\rIndeksowanie {s} ... ({d} plików)", .{ path, file_count });
            }

            const stat = try entry.dir.statFile(entry.basename);
            const file_realpath = try entry.dir.realpath(entry.basename, realpath_buf);
            var info = FileInfo{
                .size = stat.size,
            };
            std.mem.copy(u8, &info.full_path, file_realpath);
        }
    }
    std.debug.print("\n", .{});

    var total_size: u64 = 0;
    for (tree_list.items) |node| {
        if (node.info == .file) {
            total_size += node.size;
        }
    }
    std.debug.print("Znaleziono {d} plików, całkowity rozmiar {s}\n", .{ file_count, format_size(total_size) });

    const nodes = tree_list.items;
    _ = nodes; // Only edit specific fields from now on

    // var same_size_count: u64 = 0;
    // var same_size_size: u64 = 0;
    // {
    //     // Check with either neighbor (to correctly count two and three consecutive files correctly, you have to check three per iteration)
    //     var i: usize = 0;
    //     while (i < files.len) : (i += 1) {
    //         const size = files[i].size;
    //         if (i > 0 and files[i - 1].size == size) {
    //             same_size_count += 1;
    //             same_size_size += files[i].size;
    //             files[i].duplicate_size = true;
    //             continue; // Don't count the middle file twice
    //         }
    //         if (i < files.len - 1 and files[i + 1].size == size) {
    //             same_size_count += 1;
    //             same_size_size += files[i].size;
    //             files[i].duplicate_size = true;
    //         }
    //     }
    // }
    // std.debug.print("{d} plików ma ten sam rozmiar\n", .{same_size_count});

    // const hash_start_time = std.time.timestamp();
    // var done_hashes_count: u64 = 0;
    // var done_hashes_size: u64 = 0;
    // for (files, 0..) |info, i| {
    //     if (info.duplicate_size) {
    //         std.debug.print("przetwarzanie pliku {s}", .{format_size(info.size)});
    //         var hash = std.crypto.hash.Md5.init(.{});
    //         var file = try std.fs.openFileAbsoluteZ(@ptrCast([*:0]const u8, &info.full_path), .{});
    //         defer file.close();
    //         var buf_reader = std.io.bufferedReader(file.reader());
    //         var in_stream = buf_reader.reader();

    //         var buf: [1024]u8 = undefined;
    //         while (try in_stream.read(&buf) > 0) {
    //             hash.update(&buf);
    //         }
    //         var hash_buf: [16]u8 = undefined;
    //         hash.final(&hash_buf);
    //         files[i].hash = hash_buf;

    //         const time_elapsed = std.math.absCast(std.time.timestamp() - hash_start_time);
    //         done_hashes_count += 1;
    //         const count_part: f64 = @intToFloat(f64, done_hashes_count) / @intToFloat(f64, same_size_count);
    //         const count_eta: u64 = std.math.absCast(@floatToInt(i64, @intToFloat(f64, time_elapsed) / count_part * (1 - count_part)));
    //         done_hashes_size += files[i].size;
    //         const size_part: f64 = @intToFloat(f64, done_hashes_size) / @intToFloat(f64, same_size_size);
    //         const size_eta: u64 = std.math.absCast(@floatToInt(i64, @intToFloat(f64, time_elapsed) / size_part * (1 - size_part)));

    //         std.debug.print("\r{s}: {d}/{d} ({d:.2}% ETA: {s}), {s}/{s} ({d:.2}% ETA: {s}), ", .{ format_time(time_elapsed), done_hashes_count, same_size_count, count_part * 100, format_time(count_eta), format_size(done_hashes_size), format_size(same_size_size), size_part * 100, format_time(size_eta) });
    //     }
    // }
    // std.debug.print("{s}\n", .{[_]u8{' '} ** 25}); // overwrite the opened file text from loop

    // var same_hash_count: u64 = 0;
    // {
    //     var i: usize = 0;
    //     while (i < files.len) : (i += 1) {
    //         if (files[i].hash) |hash| {
    //             if (i > 0) {
    //                 if (files[i - 1].hash) |prev_hash| {
    //                     if (std.mem.eql(u8, &hash, &prev_hash)) {
    //                         files[i].duplicate_hash = true;
    //                         same_hash_count += 1;
    //                         continue; // Skip comparison with next
    //                     }
    //                 }
    //             }

    //             if (i < files.len - 1) {
    //                 if (files[i + 1].hash) |next_hash| {
    //                     if (std.mem.eql(u8, &hash, &next_hash)) {
    //                         files[i].duplicate_hash = true;
    //                         same_hash_count += 1;
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }
    // std.debug.print("Znaleziono {d} plików o tej samej zawartości\n", .{same_hash_count});

    // {
    //     var stdout = std.io.getStdOut();
    //     var writer = stdout.writer();
    //     var last_hash = [_]u8{0} ** HASH_LEN;
    //     for (file_list.items) |info| {
    //         if (info.duplicate_hash) {
    //             const hash = info.hash.?;
    //             if (!std.mem.eql(u8, &last_hash, &hash)) {
    //                 try writer.print("\n", .{});
    //             }
    //             try writer.print("{s}\t{s}\n", .{ format_size(info.size), info.full_path });
    //             std.mem.copy(u8, &last_hash, &hash);
    //         }
    //     }
    // }
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
    if (size_left <= 9.99) {
        if (suffix_index == 0) {
            _ = std.fmt.bufPrint(&result, "   {d}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        } else {
            _ = std.fmt.bufPrint(&result, "{d:.2}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        }
    } else if (size_left <= 99.9) {
        if (suffix_index == 0) {
            _ = std.fmt.bufPrint(&result, "  {d}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        } else {
            _ = std.fmt.bufPrint(&result, "{d:.1}{c}", .{ size_left, suffixes[suffix_index] }) catch unreachable;
        }
    } else if (size_left <= 999) {
        _ = std.fmt.bufPrint(&result, " {d}{c}", .{ @floor(size_left), suffixes[suffix_index] }) catch unreachable;
    } else { // 1000 to 1023
        _ = std.fmt.bufPrint(&result, "{d}{c}", .{ @floor(size_left), suffixes[suffix_index] }) catch unreachable;
    }

    return result;
}

fn format_time(time_seconds: u64) [6]u8 {
    var t = time_seconds;
    const seconds = t % 60;
    t /= 60;
    const minutes = t % 60;
    t /= 60;
    const hours = t % 24;
    t /= 24;
    const days = t;

    var result = [_]u8{' '} ** 6;
    if (hours == 0 and days == 0) {
        _ = std.fmt.bufPrint(&result, "{d: >2}m{d: >2}s", .{ minutes, seconds }) catch unreachable;
    } else if (days == 0) {
        _ = std.fmt.bufPrint(&result, "{d: >2}h{d: >2}m", .{ hours, minutes }) catch unreachable;
    } else if (days <= 99) {
        _ = std.fmt.bufPrint(&result, "{d: >2}d{d: >2}h", .{ days, hours }) catch unreachable;
    } else if (days <= 99999) {
        _ = std.fmt.bufPrint(&result, "{d: >5}d", .{days}) catch unreachable;
    } else {
        _ = std.fmt.bufPrint(&result, "w ch*j", .{}) catch unreachable;
    }

    return result;
}
