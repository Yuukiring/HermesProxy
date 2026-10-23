using System;
using System.Collections.Generic;
using System.IO;
using Framework.Logging;

namespace HermesProxy.World.Server.Warden;

/// <summary>Legacy Warden opcodes, mirrored from <c>Anticheat/Warden/Warden.hpp</c>.</summary>
internal enum WardenOpcode : byte
{
    // Server -> client
    SmsgModuleUse = 0,
    SmsgModuleCache = 1,
    SmsgCheatChecksRequest = 2,
    SmsgModuleInitialize = 3,
    SmsgMemChecksRequest = 4,
    SmsgHashRequest = 5,

    // Client -> server
    CmsgModuleMissing = 0,
    CmsgModuleOk = 1,
    CmsgCheatChecksResult = 2,
    CmsgMemChecksResult = 3,
    CmsgHashResult = 4,
    CmsgModuleFailed = 5,
}

/// <summary>
/// Emulates the vanilla client's Warden module towards the legacy server.
/// </summary>
/// <remarks>
/// Why this exists: Hermes used to drop SMSG_WARDEN_DATA on the floor (see
/// <c>WorldClient.IsIgnorableDuringHandshake</c>). A server with <c>Warden.WinEnabled=1</c>
/// then waits for a reply that never comes and kicks the session, which players see as an
/// unexplained disconnect. Sugar ships a full emulation; this is the equivalent layer, built
/// from the server's own implementation rather than from its binary.
///
/// The module data (<c>*.bin/.key/.cr</c>) still comes from the server: the challenge/response
/// table is per-module secret material, not something a proxy can derive.
/// </remarks>
internal sealed class WardenSession
{
    /// <summary>Where the server's <c>warden_modules</c> directory is expected to live.</summary>
    public static string ModuleDirectory { get; set; } = ResolveDefaultModuleDirectory();

    private static IReadOnlyList<WardenModuleData>? _modules;

    private readonly WardenArc4 _incoming;   // server -> proxy
    private readonly WardenArc4 _outgoing;   // proxy  -> server
    private byte _xor;

    private WardenModuleData? _module;
    private WardenChallengeEntry? _pendingChallenge;
    private int _moduleBytesReceived;
    private int _cheatCheckRequests;

    /// <summary>Set once the hash challenge has been answered, i.e. the keystreams were re-keyed.</summary>
    public bool IsHandshakeComplete { get; private set; }

    /// <summary>Raised for every cheat-check request we could not answer yet (diagnostics).</summary>
    public int UnansweredCheatChecks => _cheatCheckRequests;

    /// <summary>Scan terminator obfuscation byte, kept for the scan layer.</summary>
    public byte XorKey => _xor;

    /// <summary>How many bytes of the module binary the server has pushed so far.</summary>
    public int ModuleBytesReceived => _moduleBytesReceived;

    public WardenSession(byte[] premasterSecret)
    {
        if (premasterSecret == null || premasterSecret.Length == 0)
            throw new ArgumentException("Warden needs the SRP session key", nameof(premasterSecret));

        var generator = new WardenKeyGenerator(premasterSecret);

        byte[] inputKey = new byte[32];
        byte[] outputKey = new byte[32];
        generator.Generate(inputKey);
        generator.Generate(outputKey);

        // Server: _inputCrypto=inputKey (decrypts what we send), _outputCrypto=outputKey (what it sends).
        _outgoing = new WardenArc4(inputKey);
        _incoming = new WardenArc4(outputKey);
        _xor = inputKey[0];
    }

    private static string ResolveDefaultModuleDirectory()
    {
        foreach (string candidate in new[]
                 {
                     Path.Combine(AppContext.BaseDirectory, "warden_modules"),
                     Path.Combine(Environment.CurrentDirectory, "warden_modules"),
                 })
        {
            if (Directory.Exists(candidate))
                return candidate;
        }

        return Path.Combine(Environment.CurrentDirectory, "warden_modules");
    }

    private static IReadOnlyList<WardenModuleData> Modules =>
        _modules ??= WardenModuleData.LoadDirectory(ModuleDirectory);

    /// <summary>
    /// Handles one SMSG_WARDEN_DATA body. <paramref name="sendReply"/> receives the raw
    /// (already encrypted) CMSG_WARDEN_DATA payload to put on the wire.
    /// </summary>
    public void HandleServerPayload(ReadOnlySpan<byte> encryptedPayload, Action<byte[]> sendReply)
    {
        if (encryptedPayload.Length == 0)
            return;

        // The server RC4s the whole body in place; decrypt a copy so the caller's buffer stays intact.
        byte[] plain = encryptedPayload.ToArray();
        _incoming.Process(plain);

        var opcode = (WardenOpcode)plain[0];
        ReadOnlySpan<byte> body = plain.AsSpan(1);

        switch (opcode)
        {
            case WardenOpcode.SmsgModuleUse:
                HandleModuleUse(body, sendReply);
                break;

            case WardenOpcode.SmsgModuleCache:
                HandleModuleCache(body);
                break;

            case WardenOpcode.SmsgHashRequest:
                HandleHashRequest(body, sendReply);
                break;

            case WardenOpcode.SmsgCheatChecksRequest:
                // Next batch: parse the string table + scan list and answer each scan.
                // Until then this is the only reason a Warden-enabled server would still kick.
                _cheatCheckRequests++;
                if (_cheatCheckRequests == 1)
                {
                    Log.Print(LogType.Warn,
                        $"Warden cheat-check request received ({body.Length} bytes) but scan replies are not implemented yet; " +
                        "a server with Warden enabled will time this session out.");
                }
                break;

            case WardenOpcode.SmsgMemChecksRequest:
                Log.Print(LogType.Debug, $"Warden mem-check request ({body.Length} bytes) ignored.");
                break;

            default:
                Log.Print(LogType.Debug, $"Warden: unhandled server opcode {(byte)opcode} ({body.Length} bytes).");
                break;
        }
    }

    private void HandleModuleUse(ReadOnlySpan<byte> body, Action<byte[]> sendReply)
    {
        // uint8 opcode | hash[16] | key[16] | uint32 binarySize
        const int headerSize = 16 + WardenModuleData.KeySize + sizeof(uint);
        if (body.Length < headerSize)
        {
            Log.Print(LogType.Warn, $"Warden MODULE_USE truncated ({body.Length} bytes).");
            return;
        }

        ReadOnlySpan<byte> hash = body[..16];
        uint binarySize = BitConverter.ToUInt32(body[(16 + WardenModuleData.KeySize)..]);

        _module = FindModule(hash);
        _moduleBytesReceived = 0;

        if (_module == null)
        {
            // We can still serve the hash challenge only if the module is present locally.
            Log.Print(LogType.Warn,
                $"Warden module {Convert.ToHexString(hash)} ({binarySize} bytes) is not in '{ModuleDirectory}'; " +
                "the server will expect a challenge/response we cannot produce.");
            sendReply(new[] { (byte)WardenOpcode.CmsgModuleMissing });
            return;
        }

        Log.Print(LogType.Network, $"Warden module {Convert.ToHexString(hash)} accepted ({binarySize} bytes to receive).");
        sendReply(new[] { (byte)WardenOpcode.CmsgModuleOk });
    }

    private void HandleModuleCache(ReadOnlySpan<byte> body)
    {
        // uint16 length | chunk
        if (body.Length < sizeof(ushort))
            return;

        int length = BitConverter.ToUInt16(body);
        if (body.Length < sizeof(ushort) + length)
            return;

        _moduleBytesReceived += length;
    }

    private void HandleHashRequest(ReadOnlySpan<byte> body, Action<byte[]> sendReply)
    {
        // uint8 opcode | seed[16]
        if (body.Length < WardenChallengeEntry.SeedSize || _module == null)
            return;

        ReadOnlySpan<byte> seed = body[..WardenChallengeEntry.SeedSize];
        _pendingChallenge = null;

        foreach (WardenChallengeEntry entry in _module.ChallengeEntries)
        {
            if (seed.SequenceEqual(entry.Seed))
            {
                _pendingChallenge = entry;
                break;
            }
        }

        if (_pendingChallenge == null)
        {
            Log.Print(LogType.Warn, $"Warden challenge seed {Convert.ToHexString(seed)} is not in the module's table.");
            return;
        }

        byte[] reply = new byte[1 + WardenChallengeEntry.ReplySize];
        reply[0] = (byte)WardenOpcode.CmsgHashResult;
        _pendingChallenge.Reply.CopyTo(reply, 1);

        // Encrypt with the *current* keystream: the server decrypts this reply before re-keying.
        _outgoing.Process(reply);
        sendReply(reply);

        // Both sides now switch to the per-challenge keys.
        _outgoing.Init(_pendingChallenge.ClientKey);
        _incoming.Init(_pendingChallenge.ServerKey);
        _xor = _pendingChallenge.ClientKey[0];
        _pendingChallenge = null;
        IsHandshakeComplete = true;

        Log.Print(LogType.Network, "Warden hash challenge answered; keystreams re-keyed.");
    }

    private static WardenModuleData? FindModule(ReadOnlySpan<byte> hash)
    {
        foreach (WardenModuleData module in Modules)
            if (module.MatchesHash(hash))
                return module;

        return null;
    }
}
