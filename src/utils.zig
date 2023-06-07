const std = @import("std");

/// Format size with a 1024 prefix with three significant digits
pub fn formatSize(size: u64) [5]u8 {
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

/// Write out the time period in human-readable format, including very long times
pub fn formatTime(time_seconds: u64) [6]u8 {
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

/// From https://ziglearn.org/chapter-2/#readers-and-writers
pub fn nextLine(reader: anytype, buffer: []u8) !?[]const u8 {
    var line = (try reader.readUntilDelimiterOrEof(
        buffer,
        '\n',
    )) orelse return null;
    // trim annoying windows-only carriage return character
    if (@import("builtin").os.tag == .windows) {
        return std.mem.trimRight(u8, line, "\r");
    } else {
        return line;
    }
}
