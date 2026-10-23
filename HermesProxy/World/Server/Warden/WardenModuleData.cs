using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Framework.Logging;

namespace HermesProxy.World.Server.Warden;

/// <summary>One row of the module's challenge/response table (<c>.cr</c>).</summary>
internal sealed class WardenChallengeEntry
{
    public const int SeedSize = 16;
    public const int ReplySize = 20;
    public const int KeySize = 16;
    public const int EntrySize = SeedSize + ReplySize + KeySize + KeySize;

    public byte[] Seed = null!;
    public byte[] Reply = null!;
    public byte[] ClientKey = null!;
    public byte[] ServerKey = null!;
}

/// <summary>
/// A Warden module as the legacy server ships it: the encrypted/compressed client binary,
/// the RC4 key used to send it, its MD5, and the scan metadata that lives in the <c>.cr</c>.
/// </summary>
/// <remarks>
/// The server derives all of this from three files per module (<c>*.bin</c>, <c>*.key</c>,
/// <c>*.cr</c>) — see <c>WardenModule::WardenModule</c>. Sugar embeds the same data as package
/// level variables; we load the server's files instead so the two cannot drift.
/// </remarks>
internal sealed class WardenModuleData
{
    public const int KeySize = 16;
    public const int ScanTypeCount = 9;
    public const int MinimumBinarySize = 264;

    public byte[] Binary = null!;
    public byte[] Key = null!;
    public byte[] Hash = null!;      // MD5 of Binary, equal to the module file name

    public uint MemoryRead;
    public uint PageScanCheck;
    public byte[] ScanOpcodes = new byte[ScanTypeCount];
    public byte ScanTerminator;

    public IReadOnlyList<WardenChallengeEntry> ChallengeEntries = Array.Empty<WardenChallengeEntry>();

    public bool IsWindowsModule
    {
        get
        {
            foreach (byte opcode in ScanOpcodes)
                if (opcode != 0)
                    return true;
            return false;
        }
    }

    /// <summary>
    /// Reads one module from its three sibling files. Returns null when what is on disk is not
    /// a module the server could have loaded, which matches how the server silently skips them.
    /// </summary>
    public static WardenModuleData? LoadFrom(string binPath)
    {
        try
        {
            byte[] binary = File.ReadAllBytes(binPath);
            if (binary.Length < MinimumBinarySize + 4)
                return null;

            string stem = binPath[..^4];
            string keyPath = stem + ".key";
            string crPath = stem + ".cr";

            if (!File.Exists(keyPath) || !File.Exists(crPath))
                return null;

            byte[] key = File.ReadAllBytes(keyPath);
            if (key.Length != KeySize)
                return null;

            byte[] raw = File.ReadAllBytes(crPath);
            const int headerSize = sizeof(uint) * 2 + ScanTypeCount;
            if (raw.Length < headerSize)
                return null;

            int entryBytes = raw.Length - headerSize;
            if (entryBytes % WardenChallengeEntry.EntrySize != 0)
                return null;

            var module = new WardenModuleData
            {
                Binary = binary,
                Key = key,
                Hash = MD5.HashData(binary),
                MemoryRead = BitConverter.ToUInt32(raw, 0),
                PageScanCheck = BitConverter.ToUInt32(raw, 4),
            };

            Array.Copy(raw, 8, module.ScanOpcodes, 0, ScanTypeCount);

            var entries = new List<WardenChallengeEntry>(entryBytes / WardenChallengeEntry.EntrySize);
            for (int offset = headerSize; offset < raw.Length; offset += WardenChallengeEntry.EntrySize)
            {
                var entry = new WardenChallengeEntry
                {
                    Seed = raw[offset..(offset + WardenChallengeEntry.SeedSize)],
                    Reply = raw[(offset + WardenChallengeEntry.SeedSize)
                                ..(offset + WardenChallengeEntry.SeedSize + WardenChallengeEntry.ReplySize)],
                    ClientKey = raw[(offset + WardenChallengeEntry.SeedSize + WardenChallengeEntry.ReplySize)
                                    ..(offset + WardenChallengeEntry.SeedSize + WardenChallengeEntry.ReplySize + WardenChallengeEntry.KeySize)],
                    ServerKey = raw[(offset + WardenChallengeEntry.SeedSize + WardenChallengeEntry.ReplySize + WardenChallengeEntry.KeySize)
                                    ..(offset + WardenChallengeEntry.EntrySize)],
                };
                entries.Add(entry);
            }

            module.ChallengeEntries = entries;

            if (module.IsWindowsModule)
            {
                for (int candidate = 0; candidate <= byte.MaxValue; candidate++)
                {
                    bool used = false;
                    foreach (byte opcode in module.ScanOpcodes)
                        if (opcode == candidate)
                        {
                            used = true;
                            break;
                        }

                    if (!used)
                    {
                        module.ScanTerminator = (byte)candidate;
                        break;
                    }
                }

                if (module.MemoryRead == 0 || module.PageScanCheck == 0)
                    return null;
            }

            return module;
        }
        catch (Exception e)
        {
            Log.Print(LogType.Warn, $"Could not load Warden module '{binPath}': {e.Message}");
            return null;
        }
    }

    /// <summary>Loads every <c>*.bin</c> in <paramref name="directory"/>, skipping unusable ones.</summary>
    public static IReadOnlyList<WardenModuleData> LoadDirectory(string directory)
    {
        var modules = new List<WardenModuleData>();

        if (!Directory.Exists(directory))
        {
            Log.Print(LogType.Warn, $"Warden module directory not found: {directory}");
            return modules;
        }

        foreach (string binPath in Directory.EnumerateFiles(directory, "*.bin"))
        {
            WardenModuleData? module = LoadFrom(binPath);
            if (module != null)
                modules.Add(module);
        }

        return modules;
    }

    /// <summary>Hash comparison against the <c>MODULE_USE</c> hash the server sends.</summary>
    public bool MatchesHash(ReadOnlySpan<byte> hash)
    {
        return hash.Length == Hash.Length && hash.SequenceEqual(Hash);
    }
}
