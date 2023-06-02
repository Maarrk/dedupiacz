const std = @import("std");
const builtin = @import("builtin");
const clap = @import("clap");
// const clap = @import("../libs/zig-clap/clap.zig"); // For ZLS completions, not allowed when building

const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;
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

    /// Sort descending by size, then hash
    fn size_desc(context: void, a: *TreeNode, b: *TreeNode) bool {
        _ = context;
        if (a.size != b.size) return a.size > b.size;

        if (a.hash) |a_hash| {
            if (b.hash) |b_hash| {
                return std.mem.order(u8, &a_hash, &b_hash) == .gt;
            } else {
                return false; // b hash is null and a not; first files with hash
            }
        }

        return true; // either a hash is null, or or both are
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
        if (self.parent_index) |_| { // skip that for root node
            if (builtin.os.tag == .windows) {
                path_len -= 2; // strip backslash before and after root node
            } else {
                path_len -= 1; // strip slash before root node (so path starts with slash)
            }
        }
        std.mem.reverse(u8, out_buffer[0..path_len]); // reverse back the name to go from root
        out_buffer[path_len] = 0; // for compatibility with [:0]
        return out_buffer[0..path_len];
    }

    fn find_path_index(nodes: []TreeNode, path: []const u8) ?usize {
        if (path.len == 0) { // handle root as a special case
            if (nodes[0].name[0] == 0) { // string of length 0
                return 0;
            } else unreachable; // root node has non-empty name or passed empty node which isn't root
        }

        var parent_index: usize = 0; // look for a child of root node
        var current_index: usize = 0; // last matched node
        var path_iter = std.mem.split(u8, path, std.fs.path.sep_str);

        if (builtin.os.tag != .windows) {
            try path_iter.next(); // skip leading slash on posix
        }

        while (path_iter.next()) |name| {
            while (current_index < nodes.len) {
                const node = nodes[current_index];
                if (node.parent_index == parent_index and std.mem.eql(u8, name, node.name[0..name.len])) {
                    parent_index = current_index;
                    break;
                }
                current_index += 1;
            }
            if (current_index == nodes.len) {
                return null; //went beyond the node list, didn't find
            }
        }
        return current_index;
    }

    // Adding was chosen to ignore order of operations; XOR would have more data, but XORing the same file twice would remove it

    /// Add other hash to this one, as if they were two u512 little-endian numbers, allowing overflow
    fn add_hash(self: *TreeNode, hash: [HASH_LEN]u8) void {
        if (self.hash == null) {
            self.hash = [_]u8{0} ** HASH_LEN;
        }
        var self_hash = (self.hash.?)[0..];
        var carry: u1 = 0;
        for (0..HASH_LEN) |i| {
            const sum: u9 = @as(u9, self_hash[i]) + @as(u9, hash[i]) + @as(u9, carry);
            self_hash[i] = @intCast(u8, sum & 0xFF);
            carry = @intCast(u1, sum >> 8);
        }
    }

    /// Add other size to this hash, as if it were a u512 little-endian number.
    fn add_size(self: *TreeNode, size: u64) void {
        var hash_buf = [_]u8{0} ** HASH_LEN;
        @memcpy(hash_buf[0..@sizeOf(u64)], @ptrCast(*[@sizeOf(u64)]u8, @constCast(&size)));
        switch (builtin.target.cpu.arch.endian()) {
            .Big => std.mem.reverse(u8, hash_buf[0..@sizeOf(u64)]),
            .Little => {}, //do nothing
        }
        self.add_hash(hash_buf);
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

test "finding by path" {
    var nodes: [6]TreeNode = undefined;
    nodes[0] = TreeNode.init_root();
    nodes[1] = try TreeNode.init_dir(&nodes, 0, "C:"); // drive
    nodes[2] = try TreeNode.init_dir(&nodes, 1, "foo"); // dir
    nodes[3] = try TreeNode.init_file(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.init_file(&nodes, 2, "baz.zip", 2);
    nodes[5] = try TreeNode.init_file(&nodes, 1, "fubar", 4);

    const full_path = if (builtin.os.tag == .windows) "C:\\foo\\baz.zip" else "/C:/foo/baz.zip";
    try expectEqual(@as(?usize, 4), TreeNode.find_path_index(&nodes, full_path));
    const bad_path = if (builtin.os.tag == .windows) "C:\\nonexistent" else "/C:/nonexistent";
    try expectEqual(@as(?usize, null), TreeNode.find_path_index(&nodes, bad_path));

    try expectEqual(@as(?usize, 0), TreeNode.find_path_index(&nodes, ""));
}

fn find_or_add_path_index(node_list: *std.ArrayList(TreeNode), path: []const u8) !usize {
    var iter = SubpathIterator.init(path);
    var parent_subpath: []const u8 = "";
    while (iter.next()) |subpath| {
        if (TreeNode.find_path_index(node_list.items, subpath) == null) {
            const parent_index = TreeNode.find_path_index(node_list.items, parent_subpath).?;
            var this_name = subpath[parent_subpath.len..];
            if (this_name[0] == std.fs.path.sep) this_name = this_name[1..];
            try node_list.append(try TreeNode.init_dir(node_list.items, parent_index, this_name));
        }
        parent_subpath = subpath;
    }
    return TreeNode.find_path_index(node_list.items, path).?;
}

test "adding path" {
    var node_list = std.ArrayList(TreeNode).init(std.testing.allocator);
    defer node_list.deinit();

    try node_list.append(TreeNode.init_root());
    try node_list.append(try TreeNode.init_dir(node_list.items, 0, "C:")); // drive
    try node_list.append(try TreeNode.init_dir(node_list.items, 1, "foo")); // dir
    try node_list.append(try TreeNode.init_file(node_list.items, 2, "bar.txt", 1));
    try node_list.append(try TreeNode.init_file(node_list.items, 2, "baz.zip", 2));
    try node_list.append(try TreeNode.init_file(node_list.items, 1, "fubar", 4));

    const full_path = if (builtin.os.tag == .windows) "C:\\foo\\baz.zip" else "/C:/foo/baz.zip";
    try expectEqual(@as(usize, 4), try find_or_add_path_index(&node_list, full_path));

    const new_path = if (builtin.os.tag == .windows) "C:\\nonexistent" else "/C:/nonexistent";
    try expectEqual(@as(usize, 6), try find_or_add_path_index(&node_list, new_path));
    var path_buffer: [MAX_PATH_LEN]u8 = undefined;
    try expectEqualStrings(new_path, try TreeNode.full_path(&node_list.items[6], node_list.items, &path_buffer));
    try expectEqual(NodeKind.dir, node_list.items[6].info);
    try expectEqualStrings("nonexistent", std.mem.sliceTo(&node_list.items[6].name, 0));
}

test "adding to hash" {
    var nodes: [2]TreeNode = undefined;
    nodes[0] = TreeNode.init_root();
    nodes[1] = try TreeNode.init_dir(&nodes, 0, "dir");

    // Start from zero
    const hash1 = [_]u8{127} ** HASH_LEN;
    nodes[1].add_hash(hash1);
    try expectEqualSlices(u8, &hash1, &(nodes[1].hash.?));

    // Overflow a single byte
    const hash2 = [1]u8{129} ++ [_]u8{0} ** (HASH_LEN - 1);
    const result2 = [2]u8{ 0, 128 } ++ [_]u8{127} ** (HASH_LEN - 2);
    nodes[1].add_hash(hash2);
    try expectEqualSlices(u8, &result2, &(nodes[1].hash.?));

    // Overflow the whole array
    const hash3 = [1]u8{0} ++ [_]u8{128} ** (HASH_LEN - 1);
    const result3 = [_]u8{0} ** (HASH_LEN);
    nodes[1].add_hash(hash3);
    try expectEqualSlices(u8, &result3, &(nodes[1].hash.?));
}

test "adding size to hash" {
    var nodes: [2]TreeNode = undefined;
    nodes[0] = TreeNode.init_root();
    nodes[1] = try TreeNode.init_dir(&nodes, 0, "dir");

    const size1 = 42;
    const result1 = [1]u8{size1} ++ [_]u8{0} ** (HASH_LEN - 1);
    nodes[1].add_size(size1);
    try expectEqualSlices(u8, &result1, &(nodes[1].hash.?));

    const size2 = 0x10000 - size1;
    const result2 = [3]u8{ 0, 0, 1 } ++ [_]u8{0} ** (HASH_LEN - 3);
    nodes[1].add_size(size2);
    try expectEqualSlices(u8, &result2, &(nodes[1].hash.?));
}

const SubpathIterator = struct {
    full_path: []const u8,
    taken_chars: usize = 0,

    fn init(path: []const u8) SubpathIterator {
        var taken_chars: usize = if (builtin.os.tag != .windows and path[0] == std.fs.path.sep) 1 else 0;
        return SubpathIterator{ .full_path = path, .taken_chars = taken_chars };
    }

    fn next(self: *SubpathIterator) ?[]const u8 {
        if (self.taken_chars == self.full_path.len) return null;
        const next_sep = std.mem.indexOf(u8, self.full_path[self.taken_chars..], std.fs.path.sep_str);
        if (next_sep) |sep_idx| {
            self.taken_chars += sep_idx + 1;
            return self.full_path[0 .. self.taken_chars - 1];
        } else {
            self.taken_chars = self.full_path.len;
            return self.full_path;
        }
    }
};

test "iterating over subpath" {
    if (builtin.os.tag == .windows) {
        const path = "C:\\Users\\Smith\\document.docx";
        var iter = SubpathIterator.init(path);
        try expectEqualStrings("C:", iter.next().?);
        try expectEqualStrings("C:\\Users", iter.next().?);
        try expectEqualStrings("C:\\Users\\Smith", iter.next().?);
        try expectEqualStrings("C:\\Users\\Smith\\document.docx", iter.next().?);
        try expectEqual(@as(?[]const u8, null), iter.next());
    } else {
        const path = "/home/smith/document.odt";
        var iter = SubpathIterator.init(path);
        try expectEqualStrings("/home", iter.next().?);
        try expectEqualStrings("/home/smith", iter.next().?);
        try expectEqualStrings("/home/smith/document.odt", iter.next().?);
        try expectEqual(@as(?[]const u8, null), iter.next());
    }
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
        \\-v, --verbose Wyświetlaj więcej informacji w trakcie pracy (można podać kilka razy)
        \\-q, --quiet   Wyświetlaj mniej informacji
        //\\-d, --dirs    Traktuj strukturę folderów jako znaczącą
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

    if (res.args.help != 0) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return;
    }
    const verbosity: i16 = @as(i16, res.args.verbose) - @as(i16, res.args.quiet);
    if (verbosity >= 2) std.debug.print("args: {any}", .{res.args});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    // TODO: Overall algorithm:
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

    var node_list = std.ArrayList(TreeNode).init(alloc);
    defer node_list.deinit();
    try node_list.append(TreeNode.init_root());

    const realpath_buf: []u8 = try alloc.alloc(u8, MAX_PATH_LEN);
    defer alloc.free(realpath_buf);

    var file_count: usize = 0;
    var search_paths_ancestors: usize = 0; // count of folders above the passed paths, will be used to exclude them from results

    // to match the types, cast array literal to "[]T - pointer to runtime-known number of items", hence the need for &
    var search_paths = if (res.positionals.len > 0) res.positionals else @as([]const []const u8, &[_][]const u8{"."});
    for (search_paths) |path| {
        const realpath = try (try std.fs.cwd().openDir(path, .{})).realpath(".", realpath_buf);
        // this workaround is necessary, because there are still bugs with ".." on windows
        // FIXME: will fail if realpath doesn't contain any separator (like "C:")
        const parent_realpath = realpath[0..std.mem.lastIndexOfScalar(u8, realpath, std.fs.path.sep).?];
        search_paths_ancestors = try find_or_add_path_index(&node_list, parent_realpath) + 1; // save count
    }
    // TODO: Validate that none of the search_paths is equal or contained in another

    for (search_paths) |path| {
        var walker = try (try std.fs.cwd().openIterableDir(path, .{})).walk(alloc);
        defer walker.deinit();

        if (verbosity >= 0) std.debug.print("\nIndeksowanie {s} ...", .{path});
        while (try walker.next()) |entry| {
            if (entry.kind != .File) continue;

            file_count += 1;
            if (verbosity >= 0 and file_count % 100 == 0) {
                std.debug.print("\rIndeksowanie {s} ... ({d} plików)", .{ path, file_count });
            }

            const dir_realpath = try entry.dir.realpath(".", realpath_buf);
            const parent_index = try find_or_add_path_index(&node_list, dir_realpath);
            const stat = try entry.dir.statFile(entry.basename);
            try node_list.append(try TreeNode.init_file(node_list.items, parent_index, entry.basename, stat.size));
        }
    }
    if (verbosity >= 0) std.debug.print("\n", .{});

    const nodes = node_list.items; // don't modify the list from now on

    TreeNode.sum_file_sizes(nodes);
    if (verbosity >= 0) std.debug.print("Znaleziono {d} plików, całkowity rozmiar {s}\n", .{ file_count, format_size(nodes[0].size) });

    if (verbosity >= 2) {
        for (nodes[search_paths_ancestors..]) |*node| {
            std.debug.print("{s}\n", .{try TreeNode.full_path(node, nodes, realpath_buf)});
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
    std.sort.sort(*TreeNode, node_ptrs[0..file_count], {}, TreeNode.size_desc);

    if (verbosity >= 2) {
        std.debug.print("Posortowane pliki:\n", .{});
        for (node_ptrs[0..file_count]) |node| {
            std.debug.print("{s}\t{s}\n", .{ format_size(node.size), try TreeNode.full_path(node, nodes, realpath_buf) });
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

        std.debug.print("przetwarzanie pliku {s}", .{format_size(node.size)});
        var hash = std.crypto.hash.Md5.init(.{});
        var file = try std.fs.openFileAbsoluteZ(@ptrCast([*:0]const u8, try TreeNode.full_path(node, nodes, realpath_buf)), .{});
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

        std.debug.print("\r{s}: {d}/{d} ({d:.2}% ETA: {s}), {s}/{s} ({d:.2}% ETA: {s}), ", .{ format_time(time_elapsed), done_hashes_count, same_size_count, count_part * 100, format_time(count_eta), format_size(done_hashes_size), format_size(same_size_size), size_part * 100, format_time(size_eta) });
    }
    std.debug.print("{s}\n", .{[_]u8{' '} ** 25}); // overwrite the opened file text from loop

    // // TODO: Include directory structure
    // if (res.args.dirs != 0) {

    // }

    std.sort.sort(*TreeNode, node_ptrs[0..file_count], {}, TreeNode.size_desc); // also sorts by hash
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
    std.debug.print("Znaleziono {d} plików o tej samej zawartości\n", .{same_file_hash_count});

    for (0..nodes.len) |i| { // add hashes into parents
        const i_rev = nodes.len - 1 - i;
        const node = nodes[i_rev];
        if (node.parent_index) |parent_index| {
            if (node.hash) |hash| {
                nodes[parent_index].add_hash(hash);
            } else {
                nodes[parent_index].add_size(node.size);
            }
        }
    }

    // Find duplicate hashes for directories
    // Only consider nodes at or below search_paths, and only nodes with sibling to avoid marking identical child as duplicate
    var nodes_with_siblings: usize = 0;
    for (nodes[search_paths_ancestors..]) |*node| {
        const parent = nodes[node.parent_index.?]; // Since ancestors are skipped, there definitely isn't root node
        const parent_info: DirInfo = switch (parent.info) {
            .dir => |info| info,
            .file => unreachable, // Files can't be parents
        };
        if (parent_info.dir_children + parent_info.file_children > 1) {
            node_ptrs[nodes_with_siblings] = node;
            nodes_with_siblings += 1;
        }
    }
    std.sort.sort(*TreeNode, node_ptrs[0..nodes_with_siblings], {}, TreeNode.size_desc);
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

    {
        var stdout = std.io.getStdOut();
        var writer = stdout.writer();
        var last_hash = [_]u8{0} ** HASH_LEN;
        for (node_ptrs[0..nodes_with_siblings]) |node| {
            if (node.duplicate_hash) {
                if (node.parent_index) |parent_index| {
                    if (nodes[parent_index].duplicate_hash) continue;
                }
                const hash = node.hash.?;
                if (!std.mem.eql(u8, &last_hash, &hash)) {
                    try writer.print("\n", .{});
                }
                try writer.print("{s}\t{s}\n", .{ format_size(node.size), try TreeNode.full_path(node, nodes, realpath_buf) });
                @memcpy(&last_hash, &hash);
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
