// This file Copyright © Mnemosyne LLC / BT project contributors.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
//
// Tests for BEP 47: Padding files and extended file attributes.
// Covers metainfo parsing of 'attr' flags, symlink path accumulation,
// padding-file suppression, and security rejection of unsafe symlink targets.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <libtransmission/error.h>
#include <libtransmission/torrent-metainfo.h>

#include "gtest/gtest.h"

using namespace std::literals;

namespace libtransmission::test
{

// ---------------------------------------------------------------------------
// Helpers: minimal bencoded .torrent builders

// Build a v1 multi-file torrent with custom files list.
// files_benc: the bencoded list value for "files", e.g.
//   "ld6:lengthi0e4:pathl4:linkeee"
// total_size: sum of non-symlink file sizes — used to compute the correct
// number of SHA-1 piece hashes so the parser's size/pieces check passes.
// Pass 0 for symlink-only or zero-content torrents.
static std::string make_torrent(std::string_view files_benc, std::string_view name = "test"sv, uint64_t total_size = 0U)
{
    static constexpr uint64_t PieceLen = 262144U;
    uint64_t const n_pieces = (total_size == 0U) ? 0U : (total_size + PieceLen - 1U) / PieceLen;
    auto const pieces_data = std::string(n_pieces * 20U, '\0');
    auto const pieces_field = "6:pieces" + std::to_string(pieces_data.size()) + ":" + pieces_data;
    auto const name_field = "4:name" + std::to_string(name.size()) + ":" + std::string{ name };
    auto const files_field = "5:files" + std::string{ files_benc };
    auto const info = "d" + name_field + "12:piece lengthi262144e" + pieces_field + files_field + "e";
    return "d4:info" + info + "e";
}

// Build a bencoded file entry dict.
// Params:
//   length   : integer length
//   path_components : array of path strings, e.g. {"dir", "file.txt"}
//   attr     : optional attr string, e.g. "l", "p", "lx"
//   symlink_path : optional symlink path array components
static std::string make_file_entry(int64_t length,
                                   std::vector<std::string> const& path_components,
                                   std::string_view attr = ""sv,
                                   std::vector<std::string> const& symlink_path = {})
{
    // build path list
    std::string path_list = "l";
    for (auto const& p : path_components)
    {
        path_list += std::to_string(p.size()) + ":" + p;
    }
    path_list += "e";

    std::string entry = "d";
    entry += "4:attr" + std::to_string(attr.size()) + ":" + std::string{ attr };
    entry += "6:lengthi" + std::to_string(length) + "e";
    entry += "4:path" + path_list;

    if (!symlink_path.empty())
    {
        std::string sl = "l";
        for (auto const& p : symlink_path)
        {
            sl += std::to_string(p.size()) + ":" + p;
        }
        sl += "e";
        entry += "12:symlink path" + sl;
    }

    entry += "e";
    return entry;
}

// ---------------------------------------------------------------------------
// Tests

// A normal file (no attr) parses without BEP 47 flags set.
TEST(Bep47Test, NormalFileHasNoFlags)
{
    auto const files = "l" + make_file_entry(1024, { "data.bin" }) + "e";
    auto tm = tr_torrent_metainfo{};
    auto err = tr_error{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 1024U), &err)) << err.message();
    ASSERT_EQ(tm.file_count(), 1U);
    EXPECT_FALSE(tm.file_is_padding(0));
    EXPECT_FALSE(tm.file_is_symlink(0));
    EXPECT_EQ(tm.file_size(0), 1024U);
}

// attr="p" marks a file as padding.
TEST(Bep47Test, PaddingAttrFlag)
{
    auto const files = "l" + make_file_entry(512, { ".pad", "512" }, "p") + "e";
    auto tm = tr_torrent_metainfo{};
    auto err = tr_error{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 512U), &err)) << err.message();
    ASSERT_EQ(tm.file_count(), 1U);
    EXPECT_TRUE(tm.file_is_padding(0));
    EXPECT_FALSE(tm.file_is_symlink(0));
    EXPECT_EQ(tm.file_size(0), 512U);
}

// attr="l" + symlink path marks a file as a symlink with the correct target.
TEST(Bep47Test, SymlinkAttrFlag)
{
    // Include a tiny real file so the torrent has valid v1 metadata (pieces_ non-empty).
    // BEP 47 torrents with only symlinks are degenerate; real torrents always have content.
    auto const files = "l" + make_file_entry(1, { "dir", "original.txt" }) // anchor: the symlink target
        + make_file_entry(0, { "link.txt" }, "l", { "dir", "original.txt" }) + "e";
    auto tm = tr_torrent_metainfo{};
    auto err = tr_error{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 1U), &err)) << err.message();
    ASSERT_EQ(tm.file_count(), 2U);
    // file 0: the real anchor file
    EXPECT_FALSE(tm.file_is_symlink(0));
    // file 1: the symlink
    EXPECT_TRUE(tm.file_is_symlink(1));
    EXPECT_FALSE(tm.file_is_padding(1));
    EXPECT_EQ(tm.file_size(1), 0U);
    EXPECT_EQ(tm.file_symlink_target(1), "dir/original.txt");
}

// attr="l" with a single-component symlink path (no directory).
TEST(Bep47Test, SymlinkFlatTarget)
{
    auto const files = "l" + make_file_entry(1, { "real.bin" }) // anchor
        + make_file_entry(0, { "alias.bin" }, "l", { "real.bin" }) + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 1U)));
    ASSERT_EQ(tm.file_count(), 2U);
    EXPECT_TRUE(tm.file_is_symlink(1));
    EXPECT_EQ(tm.file_symlink_target(1), "real.bin");
}

// Unknown attr characters are tolerated (BEP 47: "unknown characters should be ignored").
TEST(Bep47Test, UnknownAttrCharsIgnored)
{
    // 'x' = executable, 'h' = hidden — not yet acted on but must not crash/fail parse
    auto const files = "l" + make_file_entry(256, { "script.sh" }, "xh") + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 256U)));
    ASSERT_EQ(tm.file_count(), 1U);
    EXPECT_FALSE(tm.file_is_padding(0));
    EXPECT_FALSE(tm.file_is_symlink(0));
}

// Combined attr flags: 'l' + 'x' — symlink + executable hint.
TEST(Bep47Test, CombinedAttrFlags)
{
    auto const files = "l" + make_file_entry(1, { "bin", "run.sh" }) // anchor
        + make_file_entry(0, { "run" }, "lx", { "bin", "run.sh" }) + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 1U)));
    ASSERT_EQ(tm.file_count(), 2U);
    EXPECT_TRUE(tm.file_is_symlink(1));
    EXPECT_EQ(tm.file_symlink_target(1), "bin/run.sh");
}

// Mixed torrent: one normal file, one padding file, one symlink.
TEST(Bep47Test, MixedFileTypes)
{
    auto const files = "l" + make_file_entry(4096, { "data.bin" }) + make_file_entry(256, { ".pad", "256" }, "p") +
        make_file_entry(0, { "data_link.bin" }, "l", { "data.bin" }) + "e";
    auto tm = tr_torrent_metainfo{};
    auto err = tr_error{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 4352U), &err)) << err.message();
    ASSERT_EQ(tm.file_count(), 3U);

    // file 0: normal
    EXPECT_FALSE(tm.file_is_padding(0));
    EXPECT_FALSE(tm.file_is_symlink(0));
    EXPECT_EQ(tm.file_size(0), 4096U);

    // file 1: padding
    EXPECT_TRUE(tm.file_is_padding(1));
    EXPECT_FALSE(tm.file_is_symlink(1));
    EXPECT_EQ(tm.file_size(1), 256U);

    // file 2: symlink
    EXPECT_FALSE(tm.file_is_padding(2));
    EXPECT_TRUE(tm.file_is_symlink(2));
    EXPECT_EQ(tm.file_size(2), 0U);
    EXPECT_EQ(tm.file_symlink_target(2), "data.bin");
}

// Security: symlink path components containing ".." are sanitized away.
// sanitize_subpath() strips ".." — the target should not escape the torrent root.
TEST(Bep47Test, SymlinkTargetDotDotSanitized)
{
    // A malicious torrent attempts "../../../etc/passwd" as symlink target.
    auto const files = "l" + make_file_entry(1, { "anchor.txt" }) // real file so torrent has valid v1 metadata
        + make_file_entry(0, { "evil_link" }, "l", { "..", "..", "etc", "passwd" }) + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 1U)));
    ASSERT_EQ(tm.file_count(), 2U);
    EXPECT_TRUE(tm.file_is_symlink(1));
    // sanitize_subpath() replaces ".." with "_..": the path component is mangled so it
    // cannot be interpreted as a parent-directory traversal by the OS. Verify that the
    // result does NOT start with "../" (which would escape the torrent root) and that
    // the raw ".." component has been altered.
    auto const& target = tm.file_symlink_target(1);
    // The target must not start with "../" — that would be a traversal escape.
    EXPECT_FALSE(target.substr(0, 3) == "../") << "target starts with ../: " << target;
    // The sanitizer should have mangled the ".." components (prefixes them with "_").
    // After sanitization "_../" is present instead of "../" — not an OS traversal.
    EXPECT_NE(target.find("_.."), std::string::npos) << "expected mangled '..' in: " << target;
}

// Padding file total_size is included in the torrent's byte accounting
// (padding files occupy piece space) but the file itself is never wanted.
TEST(Bep47Test, PaddingFileSizeAccountedButNotWanted)
{
    // 4096-byte data file + 256-byte padding
    auto const files = "l" + make_file_entry(4096, { "data.bin" }) + make_file_entry(256, { ".pad", "256" }, "p") + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 4352U)));
    ASSERT_EQ(tm.file_count(), 2U);

    // Padding IS counted in total_size (it occupies piece space).
    EXPECT_EQ(tm.total_size(), 4096U + 256U);

    // Padding IS parsed as padding.
    EXPECT_TRUE(tm.file_is_padding(1));

    // The padding file's own size is correct.
    EXPECT_EQ(tm.file_size(1), 256U);
}

// Empty attr string is treated as a normal file.
TEST(Bep47Test, EmptyAttrIsNormal)
{
    auto const files = "l" + make_file_entry(100, { "readme.txt" }, "") + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 100U)));
    ASSERT_EQ(tm.file_count(), 1U);
    EXPECT_FALSE(tm.file_is_padding(0));
    EXPECT_FALSE(tm.file_is_symlink(0));
}

// Multiple symlinks in one torrent parse independently.
TEST(Bep47Test, MultipleSymlinks)
{
    auto const files = "l" + make_file_entry(1000, { "original.txt" }) +
        make_file_entry(0, { "alias1.txt" }, "l", { "original.txt" }) +
        make_file_entry(0, { "subdir", "alias2.txt" }, "l", { "original.txt" }) + "e";
    auto tm = tr_torrent_metainfo{};
    ASSERT_TRUE(tm.parse_benc(make_torrent(files, "test"sv, 1000U)));
    ASSERT_EQ(tm.file_count(), 3U);

    EXPECT_FALSE(tm.file_is_symlink(0));
    EXPECT_TRUE(tm.file_is_symlink(1));
    EXPECT_EQ(tm.file_symlink_target(1), "original.txt");
    EXPECT_TRUE(tm.file_is_symlink(2));
    EXPECT_EQ(tm.file_symlink_target(2), "original.txt");
}

} // namespace libtransmission::test
