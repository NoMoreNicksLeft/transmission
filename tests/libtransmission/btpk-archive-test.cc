// Tests for btpk archive infrastructure.
// Exercises the file-level operations: move to archive, symlink creation,
// symlink resolution, rename detection via size heuristic.

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include <libtransmission/error.h>
#include <libtransmission/file.h>
#include <libtransmission/tr-strbuf.h>

#include "gtest/gtest.h"
#include "test-fixtures.h"

using namespace std::literals;

namespace libtransmission::test
{

class BtpkArchiveTest : public SandboxedTest
{
protected:
    // Create a file with specific content (content = repeated character to fill size)
    static void createFile(std::string const& path, size_t size, char fill = 'A')
    {
        // Create parent directories
        auto const parent = path.substr(0, path.rfind('/'));
        tr_sys_dir_create(parent, TR_SYS_DIR_CREATE_PARENTS, 0777);
        std::ofstream ofs(path, std::ios::binary);
        std::string content(size, fill);
        ofs.write(content.data(), content.size());
    }

    static bool isSymlink(std::string const& path)
    {
        auto const info = tr_sys_path_get_info(path);
        if (!info)
            return false;
        // Check if the file is a symlink by comparing resolved path
        tr_error err;
        auto resolved = tr_sys_path_resolve(path, &err);
        return !resolved.empty() && resolved != path;
    }

    static std::string readFile(std::string const& path)
    {
        std::ifstream ifs(path, std::ios::binary);
        return std::string{ std::istreambuf_iterator<char>(ifs),
                            std::istreambuf_iterator<char>() };
    }

    // Replicate the core archive logic from session.cc::archiveBtpkContent
    // without needing a tr_torrent* — just uses file maps and paths directly.
    static void doArchive(
        std::string const& download_dir,
        std::string const& archive_dir,
        std::map<std::string, uint64_t> const& old_files,
        std::map<std::string, uint64_t> const& new_files)
    {
        // Create the archive directory
        tr_error mkdir_err;
        tr_sys_dir_create(archive_dir, TR_SYS_DIR_CREATE_PARENTS, 0777, &mkdir_err);

        for (auto const& [old_path, old_size] : old_files)
        {
            auto const src = download_dir + "/" + old_path;
            auto const dest = archive_dir + "/" + old_path;

            // Create parent dirs in archive
            auto const dest_parent = dest.substr(0, dest.rfind('/'));
            if (dest_parent != archive_dir)
            {
                tr_error p_err;
                tr_sys_dir_create(dest_parent, TR_SYS_DIR_CREATE_PARENTS, 0777, &p_err);
            }

            // Resolve symlinks
            auto real_src = src;
            {
                tr_error resolve_err;
                auto resolved = tr_sys_path_resolve(src, &resolve_err);
                if (!resolved.empty())
                    real_src = std::move(resolved);
            }

            // Move real file to archive
            tr_error move_err;
            if (!tr_sys_path_rename(real_src, dest, &move_err))
                continue;

            // Remove stale entry at src (may be dangling symlink)
            if (real_src != src)
            {
                tr_error rm_err;
                tr_sys_path_remove(src, &rm_err);
            }

            // Symlink back for unchanged files
            auto const new_it = new_files.find(old_path);
            if (new_it != new_files.end() && new_it->second == old_size)
            {
                tr_error link_err;
                tr_sys_path_create_symlink(src.c_str(), dest.c_str(), &link_err);
            }

            // Handle renames
            if (new_it == new_files.end())
            {
                for (auto const& [new_path, new_size] : new_files)
                {
                    if (new_size == old_size && old_files.find(new_path) == old_files.end())
                    {
                        auto const renamed_link = download_dir + "/" + new_path;
                        if (!tr_sys_path_exists(renamed_link))
                        {
                            auto const rp = renamed_link.substr(0, renamed_link.rfind('/'));
                            if (!rp.empty())
                            {
                                tr_error rp_err;
                                tr_sys_dir_create(rp, TR_SYS_DIR_CREATE_PARENTS, 0777, &rp_err);
                            }
                            tr_error rl_err;
                            tr_sys_path_create_symlink(renamed_link.c_str(), dest.c_str(), &rl_err);
                        }
                        break;
                    }
                }
            }
        }
    }
};

// Test 1: Basic archive — all files move to archive, unchanged files get symlinks
TEST_F(BtpkArchiveTest, UnchangedFilesGetSymlinks)
{
    auto const dl_dir = sandboxDir() + "/downloads/myfiles";
    auto const archive_dir = sandboxDir() + "/archive/myfiles/seq-0";

    // Create "old" files: A.txt (100 bytes), B.txt (200 bytes)
    createFile(dl_dir + "/A.txt", 100, 'A');
    createFile(dl_dir + "/B.txt", 200, 'B');

    // Old version has A and B; new version has A (unchanged) and B (unchanged) and C (added)
    std::map<std::string, uint64_t> old_files = { {"A.txt", 100}, {"B.txt", 200} };
    std::map<std::string, uint64_t> new_files = { {"A.txt", 100}, {"B.txt", 200}, {"C.txt", 300} };

    doArchive(dl_dir, archive_dir, old_files, new_files);

    // Archive should contain real files
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/A.txt"));
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/B.txt"));

    // Download dir should have symlinks pointing to archive
    EXPECT_TRUE(tr_sys_path_exists(dl_dir + "/A.txt"));
    EXPECT_TRUE(tr_sys_path_exists(dl_dir + "/B.txt"));
    EXPECT_TRUE(isSymlink(dl_dir + "/A.txt"));
    EXPECT_TRUE(isSymlink(dl_dir + "/B.txt"));

    // Symlinks should resolve to the archive copies
    auto const resolved_a = tr_sys_path_resolve(dl_dir + "/A.txt");
    auto const resolved_b = tr_sys_path_resolve(dl_dir + "/B.txt");
    auto const expected_a = tr_sys_path_resolve(archive_dir + "/A.txt");
    auto const expected_b = tr_sys_path_resolve(archive_dir + "/B.txt");
    EXPECT_EQ(resolved_a, expected_a);
    EXPECT_EQ(resolved_b, expected_b);

    // Content should be readable through the symlink
    EXPECT_EQ(readFile(dl_dir + "/A.txt").size(), 100U);
    EXPECT_EQ(readFile(dl_dir + "/B.txt").size(), 200U);
}

// Test 2: Changed file — old version archived, NO symlink (new version will be downloaded)
TEST_F(BtpkArchiveTest, ChangedFileNoSymlink)
{
    auto const dl_dir = sandboxDir() + "/downloads/myfiles";
    auto const archive_dir = sandboxDir() + "/archive/myfiles/seq-0";

    createFile(dl_dir + "/data.bin", 1000, 'X');

    // Old: data.bin at 1000 bytes; new: data.bin at 1500 bytes (changed)
    std::map<std::string, uint64_t> old_files = { {"data.bin", 1000} };
    std::map<std::string, uint64_t> new_files = { {"data.bin", 1500} };

    doArchive(dl_dir, archive_dir, old_files, new_files);

    // Archive has the old file
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/data.bin"));
    EXPECT_EQ(readFile(archive_dir + "/data.bin").size(), 1000U);

    // Download dir should NOT have a symlink (file changed, needs re-download)
    EXPECT_FALSE(tr_sys_path_exists(dl_dir + "/data.bin"));
}

// Test 3: Removed file — archived, no symlink
TEST_F(BtpkArchiveTest, RemovedFileArchived)
{
    auto const dl_dir = sandboxDir() + "/downloads/myfiles";
    auto const archive_dir = sandboxDir() + "/archive/myfiles/seq-0";

    createFile(dl_dir + "/gone.txt", 500, 'G');

    std::map<std::string, uint64_t> old_files = { {"gone.txt", 500} };
    std::map<std::string, uint64_t> new_files = {}; // completely removed

    doArchive(dl_dir, archive_dir, old_files, new_files);

    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/gone.txt"));
    EXPECT_FALSE(tr_sys_path_exists(dl_dir + "/gone.txt"));
}

// Test 4: Renamed file — archived under old name, symlink at new path
TEST_F(BtpkArchiveTest, RenamedFileDetectedBySize)
{
    auto const dl_dir = sandboxDir() + "/downloads/myfiles";
    auto const archive_dir = sandboxDir() + "/archive/myfiles/seq-0";

    createFile(dl_dir + "/old_name.mp3", 4096, 'M');

    // old_name.mp3 disappears, new_name.mp3 appears with same size
    std::map<std::string, uint64_t> old_files = { {"old_name.mp3", 4096} };
    std::map<std::string, uint64_t> new_files = { {"new_name.mp3", 4096} };

    doArchive(dl_dir, archive_dir, old_files, new_files);

    // Archive has old name
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/old_name.mp3"));

    // Download dir has symlink at new name pointing to archive
    EXPECT_TRUE(tr_sys_path_exists(dl_dir + "/new_name.mp3"));
    EXPECT_TRUE(isSymlink(dl_dir + "/new_name.mp3"));

    auto const resolved = tr_sys_path_resolve(dl_dir + "/new_name.mp3");
    auto const expected = tr_sys_path_resolve(archive_dir + "/old_name.mp3");
    EXPECT_EQ(resolved, expected);
}

// Test 5: Existing symlinks resolved before archive (no symlink chains)
TEST_F(BtpkArchiveTest, ExistingSymlinksResolved)
{
    auto const dl_dir = sandboxDir() + "/downloads/myfiles";
    auto const archive_seq0 = sandboxDir() + "/archive/myfiles/seq-0";
    auto const archive_seq1 = sandboxDir() + "/archive/myfiles/seq-1";

    // Simulate state after first archive: real file in seq-0, symlink in dl_dir
    createFile(archive_seq0 + "/stable.txt", 100, 'S');
    tr_sys_dir_create(dl_dir, TR_SYS_DIR_CREATE_PARENTS, 0777);
    tr_sys_path_create_symlink(
        (dl_dir + "/stable.txt").c_str(),
        (archive_seq0 + "/stable.txt").c_str());

    // Verify the symlink exists
    EXPECT_TRUE(isSymlink(dl_dir + "/stable.txt"));

    // Now archive again (seq-1): stable.txt is unchanged in new version
    std::map<std::string, uint64_t> old_files = { {"stable.txt", 100} };
    std::map<std::string, uint64_t> new_files = { {"stable.txt", 100} };

    doArchive(dl_dir, archive_seq1, old_files, new_files);

    // The real file should have moved from seq-0 to seq-1
    EXPECT_TRUE(tr_sys_path_exists(archive_seq1 + "/stable.txt"));
    EXPECT_FALSE(tr_sys_path_exists(archive_seq0 + "/stable.txt"));

    // The symlink in dl_dir should point to seq-1 (not to seq-0, not chain)
    EXPECT_TRUE(isSymlink(dl_dir + "/stable.txt"));
    auto const resolved = tr_sys_path_resolve(dl_dir + "/stable.txt");
    auto const expected = tr_sys_path_resolve(archive_seq1 + "/stable.txt");
    EXPECT_EQ(resolved, expected);

    // Content still readable
    EXPECT_EQ(readFile(dl_dir + "/stable.txt").size(), 100U);
}

// Test 6: Mixed scenario — unchanged, changed, added, removed, renamed
TEST_F(BtpkArchiveTest, MixedScenario)
{
    auto const dl_dir = sandboxDir() + "/downloads/myfiles";
    auto const archive_dir = sandboxDir() + "/archive/myfiles/seq-0";

    createFile(dl_dir + "/keep.txt", 100, 'K');      // unchanged
    createFile(dl_dir + "/modify.txt", 200, 'M');     // will change size
    createFile(dl_dir + "/delete_me.txt", 300, 'D');  // removed in new
    createFile(dl_dir + "/rename_me.txt", 400, 'R');  // renamed in new

    std::map<std::string, uint64_t> old_files = {
        {"keep.txt", 100},
        {"modify.txt", 200},
        {"delete_me.txt", 300},
        {"rename_me.txt", 400},
    };
    std::map<std::string, uint64_t> new_files = {
        {"keep.txt", 100},          // unchanged
        {"modify.txt", 500},        // changed (different size)
        {"new_file.txt", 600},      // added (no old equivalent)
        {"renamed.txt", 400},       // renamed (same size as rename_me.txt)
    };

    doArchive(dl_dir, archive_dir, old_files, new_files);

    // keep.txt: archived + symlinked
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/keep.txt"));
    EXPECT_TRUE(isSymlink(dl_dir + "/keep.txt"));

    // modify.txt: archived, no symlink (size changed)
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/modify.txt"));
    EXPECT_FALSE(tr_sys_path_exists(dl_dir + "/modify.txt"));

    // delete_me.txt: archived, no symlink (removed from new)
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/delete_me.txt"));
    EXPECT_FALSE(tr_sys_path_exists(dl_dir + "/delete_me.txt"));

    // rename_me.txt: archived under old name, symlink at new name
    EXPECT_TRUE(tr_sys_path_exists(archive_dir + "/rename_me.txt"));
    EXPECT_FALSE(tr_sys_path_exists(dl_dir + "/rename_me.txt")); // old path gone
    EXPECT_TRUE(tr_sys_path_exists(dl_dir + "/renamed.txt"));    // new path symlinked
    EXPECT_TRUE(isSymlink(dl_dir + "/renamed.txt"));
}

} // namespace libtransmission::test
