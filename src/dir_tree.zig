//! This module provides a tree of directories and files, reflecting the directory structure.
//! They are allocated in a continuous array of memory sorted in a topological order, each parent
//! precedes all of its children.

const std = @import("std");
const builtin = @import("builtin");

const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;
const expectEqualStrings = std.testing.expectEqualStrings;

pub const max_path_len: comptime_int = 512;
pub const max_name_len: comptime_int = 256;
pub const hash_len: comptime_int = std.crypto.hash.Md5.digest_length;

pub const TreeNode = struct {
    name: [max_name_len]u8 = [_]u8{0} ** max_name_len,
    parent_index: ?usize, // can only be null at the root node
    size: u64 = 0,
    hash: ?[hash_len]u8 = null,
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

    /// Initialize the root node. There **must** be one at `nodes[0]` slice, and it cannot appear anywhere else
    pub fn initRoot() TreeNode {
        return TreeNode{
            .parent_index = null,
            .info = NodeInfo{ .dir = DirInfo{} },
        };
    }

    /// Initialize a node for a directory. Will typically be called by `find_or_add_path_index`
    pub fn initDir(nodes: []TreeNode, parent_index: usize, name: []const u8) !TreeNode {
        return TreeNode._init(nodes, parent_index, .dir, name);
    }

    /// Initialize a node for a file.
    pub fn initFile(nodes: []TreeNode, parent_index: usize, name: []const u8, size: u64) !TreeNode {
        var self = try TreeNode._init(nodes, parent_index, .file, name);
        self.size = size;
        return self;
    }

    /// Sort descending by size, then non-null hash, then descending hash.
    /// Note that `nodes: TreeNode[]` must be preserved in original order, you should sort
    /// a buffer of pointers to elements of the original array
    pub fn sizeDesc(context: void, a: *TreeNode, b: *TreeNode) bool {
        // Note that this is passed as lessThan, so return means "a goes before b"
        _ = context;
        if (a.size != b.size) return a.size > b.size;

        if (a.hash != null and b.hash != null) {
            return std.mem.order(u8, &a.hash.?, &b.hash.?) == .gt;
        }

        if (a.hash != null and b.hash == null) {
            return true; // only a has a hash
        } else {
            return false; // b goes after, or consider them equal
        }
    }

    /// Sort in lexical order by `name` - not the full path, just name of this node.
    /// Note that `nodes: TreeNode[]` must be preserved in original order, you should sort
    /// a buffer of pointers to elements of the original array
    pub fn nameAsc(context: void, a: *TreeNode, b: *TreeNode) bool {
        _ = context;
        return std.mem.order(u8, &a.name, &b.name) == .lt;
    }

    /// Traverse up the tree until root node and construct the absolute path into `out_buffer`.
    /// Assumes that the path will start with a single separator character, except in `.windows` os.
    /// Adds `\0` byte after the returned slice.
    pub fn fullPath(self: *TreeNode, nodes: []TreeNode, out_buffer: []u8) ![]u8 {
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
        // don't need to check for space because initial slash was removed earlier
        return out_buffer[0..path_len];
    }

    /// Traverse the full tree to find a node whose `fullPath` matches `path` exactly
    fn findPathIndex(nodes: []TreeNode, path: []const u8) ?usize {
        if (path.len == 0) { // handle root as a special case
            if (nodes[0].name[0] == 0) { // string of length 0
                return 0;
            } else unreachable; // root node has non-empty name or passed empty node which isn't root
        }

        var parent_index: usize = 0; // look for a child of root node
        var current_index: usize = 0; // last matched node
        var path_iter = std.mem.split(u8, path, std.fs.path.sep_str);

        if (builtin.os.tag != .windows) {
            _ = path_iter.next(); // skip leading slash on posix
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

    /// Add other hash to this one, meant to be used for adding all children of a directory node
    pub fn addHash(self: *TreeNode, hash: [hash_len]u8) void {
        assert(self.info == .dir); // only directories can have children
        if (self.hash == null) {
            self.hash = [_]u8{0} ** hash_len;
        }
        var self_hash = (self.hash.?)[0..];
        var carry: u1 = 0;
        for (0..hash_len) |i| {
            const sum: u9 = @as(u9, self_hash[i]) + @as(u9, hash[i]) + @as(u9, carry);
            self_hash[i] = @intCast(u8, sum & 0xFF);
            carry = @intCast(u1, sum >> 8);
        }
    }

    /// Add other size to this hash, as if it were a u512 little-endian number.
    /// Meant to be used for adding children to a directory.
    ///
    /// When this is used on files only, the size is guaranteed to be unique,
    /// otherwise they should have a hash. It may not be unique when two directories
    /// happen to have only children of unique sizes that happen to sum to a same number
    pub fn addSize(self: *TreeNode, size: u64) void {
        var hash_buf = [_]u8{0} ** hash_len;
        @memcpy(hash_buf[0..@sizeOf(u64)], @ptrCast(*[@sizeOf(u64)]u8, @constCast(&size)));
        switch (builtin.target.cpu.arch.endian()) {
            .Big => std.mem.reverse(u8, hash_buf[0..@sizeOf(u64)]),
            .Little => {}, //do nothing
        }
        self.addHash(hash_buf);
    }
};

const NodeKind = enum {
    /// Directory node that can have children
    /// `size` is sum of sizes of all contained files, after `sumFileSizes` is run on complete tree.
    /// `hash` contains the sum of all children, as if it were a `u512` number, ignoring overflow.
    ///
    /// Adding was chosen to ignore order of operations; XOR would have more data,
    /// but XORing the same file twice would remove it
    dir,
    /// Node for a file, must be a leaf node
    file,
};

pub const NodeInfo = union(NodeKind) {
    dir: DirInfo,
    file: FileInfo,
};

pub const DirInfo = struct {
    dir_children: u64 = 0,
    file_children: u64 = 0,
    hashed_children: u64 = 0,
};

pub const FileInfo = struct {
    duplicate_size: bool = false,
};

/// Update every directory size with sum of size of its children.
/// The `nodes` list must be sorted so that all children are after their parent
pub fn sumFileSizes(nodes: []TreeNode) void {
    for (nodes, 0..) |_, i| {
        const i_rev = nodes.len - 1 - i;
        const node = nodes[i_rev];
        if (node.parent_index) |p| {
            assert(nodes[p].info == .dir); // only directories can have children
            nodes[p].size += node.size;
        }
    }
}

test "absolute path of a node" {
    var nodes: [5]TreeNode = undefined;
    nodes[0] = TreeNode.initRoot();
    nodes[1] = try TreeNode.initDir(&nodes, 0, "C:");
    nodes[2] = try TreeNode.initDir(&nodes, 1, "foo");
    nodes[3] = try TreeNode.initFile(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.initDir(&nodes, 2, "directory");

    var path_buffer: [max_path_len]u8 = undefined;

    const full_path = try TreeNode.fullPath(&nodes[3], &nodes, &path_buffer);
    const expected_path = if (builtin.os.tag == .windows) "C:\\foo\\bar.txt" else "/C:/foo/bar.txt";
    try expectEqualStrings(expected_path, full_path);

    const full_dir_path = try TreeNode.fullPath(&nodes[4], &nodes, &path_buffer);
    const expected_dir_path = if (builtin.os.tag == .windows) "C:\\foo\\directory" else "/C:/foo/directory";
    try expectEqualStrings(expected_dir_path, full_dir_path);
}

test "counting children" {
    var nodes: [6]TreeNode = undefined;
    nodes[0] = TreeNode.initRoot();
    nodes[1] = try TreeNode.initDir(&nodes, 0, "C:"); // drive
    nodes[2] = try TreeNode.initDir(&nodes, 1, "foo"); // dir
    nodes[3] = try TreeNode.initFile(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.initFile(&nodes, 2, "baz.zip", 2);
    nodes[5] = try TreeNode.initFile(&nodes, 1, "fubar", 4);

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
    nodes[0] = TreeNode.initRoot();
    nodes[1] = try TreeNode.initDir(&nodes, 0, "C:"); // drive
    nodes[2] = try TreeNode.initDir(&nodes, 1, "foo"); // dir
    nodes[3] = try TreeNode.initFile(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.initFile(&nodes, 2, "baz.zip", 2);
    nodes[5] = try TreeNode.initFile(&nodes, 1, "fubar", 4);

    sumFileSizes(nodes[0..]);

    try expectEqual(@as(u64, 7), nodes[0].size);
    try expectEqual(@as(u64, 7), nodes[1].size);
    try expectEqual(@as(u64, 3), nodes[2].size);
}

test "finding by path" {
    var nodes: [6]TreeNode = undefined;
    nodes[0] = TreeNode.initRoot();
    nodes[1] = try TreeNode.initDir(&nodes, 0, "C:"); // drive
    nodes[2] = try TreeNode.initDir(&nodes, 1, "foo"); // dir
    nodes[3] = try TreeNode.initFile(&nodes, 2, "bar.txt", 1);
    nodes[4] = try TreeNode.initFile(&nodes, 2, "baz.zip", 2);
    nodes[5] = try TreeNode.initFile(&nodes, 1, "fubar", 4);

    const full_path = if (builtin.os.tag == .windows) "C:\\foo\\baz.zip" else "/C:/foo/baz.zip";
    try expectEqual(@as(?usize, 4), TreeNode.findPathIndex(&nodes, full_path));
    const bad_path = if (builtin.os.tag == .windows) "C:\\nonexistent" else "/C:/nonexistent";
    try expectEqual(@as(?usize, null), TreeNode.findPathIndex(&nodes, bad_path));

    try expectEqual(@as(?usize, 0), TreeNode.findPathIndex(&nodes, ""));
}

test "adding to hash" {
    var nodes: [2]TreeNode = undefined;
    nodes[0] = TreeNode.initRoot();
    nodes[1] = try TreeNode.initDir(&nodes, 0, "dir");

    // Start from zero
    const hash1 = [_]u8{127} ** hash_len;
    nodes[1].addHash(hash1);
    try expectEqualSlices(u8, &hash1, &(nodes[1].hash.?));

    // Overflow a single byte
    const hash2 = [1]u8{129} ++ [_]u8{0} ** (hash_len - 1);
    const result2 = [2]u8{ 0, 128 } ++ [_]u8{127} ** (hash_len - 2);
    nodes[1].addHash(hash2);
    try expectEqualSlices(u8, &result2, &(nodes[1].hash.?));

    // Overflow the whole array
    const hash3 = [1]u8{0} ++ [_]u8{128} ** (hash_len - 1);
    const result3 = [_]u8{0} ** (hash_len);
    nodes[1].addHash(hash3);
    try expectEqualSlices(u8, &result3, &(nodes[1].hash.?));
}

test "adding size to hash" {
    var nodes: [2]TreeNode = undefined;
    nodes[0] = TreeNode.initRoot();
    nodes[1] = try TreeNode.initDir(&nodes, 0, "dir");

    const size1 = 42;
    const result1 = [1]u8{size1} ++ [_]u8{0} ** (hash_len - 1);
    nodes[1].addSize(size1);
    try expectEqualSlices(u8, &result1, &(nodes[1].hash.?));

    const size2 = 0x10000 - size1;
    const result2 = [3]u8{ 0, 0, 1 } ++ [_]u8{0} ** (hash_len - 3);
    nodes[1].addSize(size2);
    try expectEqualSlices(u8, &result2, &(nodes[1].hash.?));
}

/// Combines `findPathIndex` with `initDir` to create the missing directories in the path.
/// Assumes `dir_path` is an absolute path to a directory
pub fn findOrAddPathIndex(node_list: *std.ArrayList(TreeNode), dir_path: []const u8) !usize {
    var iter = SubpathIterator.init(dir_path);
    var parent_subpath: []const u8 = "";
    while (iter.next()) |subpath| {
        if (TreeNode.findPathIndex(node_list.items, subpath) == null) {
            const parent_index = TreeNode.findPathIndex(node_list.items, parent_subpath).?;
            var this_name = subpath[parent_subpath.len..];
            if (this_name[0] == std.fs.path.sep) this_name = this_name[1..];
            try node_list.append(try TreeNode.initDir(node_list.items, parent_index, this_name));
        }
        parent_subpath = subpath;
    }
    return TreeNode.findPathIndex(node_list.items, dir_path).?;
}

test "adding path" {
    var node_list = std.ArrayList(TreeNode).init(std.testing.allocator);
    defer node_list.deinit();

    try node_list.append(TreeNode.initRoot());
    try node_list.append(try TreeNode.initDir(node_list.items, 0, "C:")); // drive
    try node_list.append(try TreeNode.initDir(node_list.items, 1, "foo")); // dir
    try node_list.append(try TreeNode.initFile(node_list.items, 2, "bar.txt", 1));
    try node_list.append(try TreeNode.initFile(node_list.items, 2, "baz.zip", 2));
    try node_list.append(try TreeNode.initFile(node_list.items, 1, "fubar", 4));

    const full_path = if (builtin.os.tag == .windows) "C:\\foo\\baz.zip" else "/C:/foo/baz.zip";
    try expectEqual(@as(usize, 4), try findOrAddPathIndex(&node_list, full_path));

    const new_path = if (builtin.os.tag == .windows) "C:\\nonexistent" else "/C:/nonexistent";
    try expectEqual(@as(usize, 6), try findOrAddPathIndex(&node_list, new_path));
    var path_buffer: [max_path_len]u8 = undefined;
    try expectEqualStrings(new_path, try TreeNode.fullPath(&node_list.items[6], node_list.items, &path_buffer));
    try expectEqual(NodeKind.dir, node_list.items[6].info);
    try expectEqualStrings("nonexistent", std.mem.sliceTo(&node_list.items[6].name, 0));
}

/// Iterate through progressively deeper subpaths of a path.
///
/// For example for `/a/b/c` it would give `/a`, `/a/b`, `/a/b/c`
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
