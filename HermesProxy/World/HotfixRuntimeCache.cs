using System;
using System.Collections.Generic;
using System.IO;

using Framework.IO;
using Framework.Logging;

using HermesProxy.World.Enums;
using HermesProxy.World.Objects;

namespace HermesProxy.World;

/// <summary>
/// 运行期算出来的热修记录落盘。
/// </summary>
/// <remarks>
/// GenerateItemSparseUpdateIfNeeded 检出「服务端数值与客户端自带 DB2 不一致」后，只把结果写进
/// 内存里的 Hotfixes 表并返回 null —— 注释说这是为了「下次登录再发」。可 Hotfixes 是纯内存的，
/// 而登录器在游戏退出时会把代理一起关掉，于是这些修正记录随进程一起消失，下次启动又从 CSV
/// 重新加载，玩家永远等不到那句「下次登录」。
///
/// 这里把每条运行期记录按 (表, 记录ID) 追加到 CSV/Hotfix/runtime-&lt;资料片&gt;.bin，
/// 代理启动、CSV 全部加载完之后再读回来重建 HotfixRecord，这样第二次启动就能把它们推给客户端。
///
/// 文件格式（小端）：
///   'HRC1' | count(u32) | count × { tableHash(u32) recordId(u32) length(u32) content[length] }
/// length == 0 表示这条记录是被移除的（Status = RecordRemoved）。
/// </remarks>
public static class HotfixRuntimeCache
{
    private const uint Magic = 0x31435248; // 'HRC1'
    private const long CompactThreshold = 8L * 1024 * 1024;

    private static readonly object Sync = new();
    private static readonly Dictionary<(uint Table, uint RecordId), byte[]> Entries = new();
    private static string _path = string.Empty;

    /// <summary>热修表里恢复出来的条数（只用于日志）。</summary>
    public static int Count
    {
        get { lock (Sync) return Entries.Count; }
    }

    private static string PathFor(int expansionVersion) =>
        Path.Combine("CSV", "Hotfix", $"runtime-{expansionVersion}.bin");

    /// <summary>在 LoadHotfixes 之后调用：把上次运行攒下的记录读回内存。</summary>
    public static void Init(int expansionVersion)
    {
        lock (Sync)
        {
            Entries.Clear();
            _path = PathFor(expansionVersion);

            if (!File.Exists(_path))
                return;

            try
            {
                using FileStream fs = File.OpenRead(_path);
                using BinaryReader br = new(fs);
                if (fs.Length < 8)
                    return;

                if (br.ReadUInt32() != Magic)
                {
                    Log.Print(LogType.Storage, $"[HotfixCache] {_path}: bad magic, ignored");
                    return;
                }

                uint count = br.ReadUInt32();
                for (uint i = 0; i < count; i++)
                {
                    if (fs.Position + 12 > fs.Length)
                        break;

                    uint table = br.ReadUInt32();
                    uint recordId = br.ReadUInt32();
                    int length = (int)br.ReadUInt32();
                    if (length < 0 || fs.Position + length > fs.Length)
                        break;

                    // 同一个 (表, ID) 后写的覆盖先写的，和运行时 UpdateHotfix 的语义一致。
                    Entries[(table, recordId)] = br.ReadBytes(length);
                }

                Log.Print(LogType.Storage, $"[HotfixCache] restored {Entries.Count} runtime hotfix record(s)");
            }
            catch (Exception e)
            {
                Entries.Clear();
                Log.Print(LogType.Storage, $"[HotfixCache] load failed: {e.Message}");
            }
        }
    }

    /// <summary>把内存里的记录重建进 Hotfixes 表，客户端登录时会经 SMSG_HOTFIX_CONNECT 收到。</summary>
    public static void RestoreIntoHotfixes(Action<uint, DB2Hash, byte[], bool> addRecord)
    {
        List<KeyValuePair<(uint Table, uint RecordId), byte[]>> snapshot;
        lock (Sync)
        {
            if (Entries.Count == 0)
                return;
            snapshot = new List<KeyValuePair<(uint, uint), byte[]>>(Entries);
        }

        foreach (var pair in snapshot)
        {
            var (table, recordId) = pair.Key;
            byte[] content = pair.Value;
            addRecord(recordId, (DB2Hash)table, content, content.Length == 0);
        }
    }

    /// <summary>记一条运行期热修。写盘失败不影响本次运行。</summary>
    public static void Remember(DB2Hash table, uint recordId, bool remove, ByteBuffer content)
    {
        byte[] bytes;
        if (remove)
        {
            bytes = Array.Empty<byte>();
        }
        else
        {
            try
            {
                bytes = content.GetData();
            }
            catch (Exception e)
            {
                Log.Print(LogType.Storage, $"[HotfixCache] read content failed for {table} #{recordId}: {e.Message}");
                return;
            }
        }

        lock (Sync)
        {
            if (_path.Length == 0)
                return;

            Entries[((uint)table, recordId)] = bytes;

            try
            {
                AppendToFile((uint)table, recordId, bytes);
            }
            catch (Exception e)
            {
                Log.Print(LogType.Storage, $"[HotfixCache] write failed: {e.Message}");
            }
        }
    }

    private static void AppendToFile(uint table, uint recordId, byte[] content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

        bool exists = File.Exists(_path);
        if (exists && new FileInfo(_path).Length > CompactThreshold)
        {
            RewriteFile();
            return;
        }

        using FileStream fs = new(_path, FileMode.OpenOrCreate, FileAccess.Write);
        using BinaryWriter bw = new(fs);
        if (!exists || fs.Length < 8)
        {
            fs.SetLength(0);
            bw.Write(Magic);
            bw.Write(0u);
        }

        fs.Seek(0, SeekOrigin.End);
        bw.Write(table);
        bw.Write(recordId);
        bw.Write((uint)content.Length);
        bw.Write(content);

        // 记录数放在文件头，追加时顺手 +1；这里直接重算，比维护计数器省心。
        fs.Seek(4, SeekOrigin.Begin);
        bw.Write((uint)Entries.Count);
        bw.Flush();
    }

    private static void RewriteFile()
    {
        string tmp = _path + ".tmp";
        using (FileStream fs = new(tmp, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new(fs))
        {
            bw.Write(Magic);
            bw.Write((uint)Entries.Count);
            foreach (var pair in Entries)
            {
                bw.Write(pair.Key.Table);
                bw.Write(pair.Key.RecordId);
                bw.Write((uint)pair.Value.Length);
                bw.Write(pair.Value);
            }
        }

        File.Move(tmp, _path, overwrite: true);
    }
}
