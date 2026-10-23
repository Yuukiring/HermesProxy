using System;
using System.Security.Cryptography;

namespace HermesProxy.World.Server.Warden;

/// <summary>
/// Port of MaNGOS <c>SHA1Randx</c> (src/game/Anticheat/Warden/WardenKeyGeneration.h).
/// The legacy Warden keys are not a plain hash of the session key: the input is split in
/// half, each half hashed, and the keystream is a SHA1 chain over (o1, o0, o2) that is
/// re-seeded every 20 bytes. Any deviation here produces a keystream the server cannot
/// decrypt, so the shape below is deliberately a line-by-line mirror.
/// </summary>
internal sealed class WardenKeyGenerator
{
    private const int DigestSize = 20;

    private readonly byte[] _o0 = new byte[DigestSize];
    private readonly byte[] _o1 = new byte[DigestSize];
    private readonly byte[] _o2 = new byte[DigestSize];
    private int _taken;

    public WardenKeyGenerator(ReadOnlySpan<byte> input)
    {
        int half = input.Length / 2;

        SHA1.HashData(input[..half], _o1);
        SHA1.HashData(input[half..], _o2);

        // _o0 starts as 20 zero bytes (field initialiser above).
        FillUp();
    }

    public void Generate(Span<byte> output)
    {
        for (int i = 0; i < output.Length; i++)
        {
            if (_taken == DigestSize)
                FillUp();

            output[i] = _o0[_taken++];
        }
    }

    private void FillUp()
    {
        Span<byte> buffer = stackalloc byte[DigestSize * 3];
        _o1.CopyTo(buffer);
        _o0.CopyTo(buffer[DigestSize..]);
        _o2.CopyTo(buffer[(DigestSize * 2)..]);

        SHA1.HashData(buffer, _o0);
        _taken = 0;
    }
}

/// <summary>
/// RC4/ARC4 as used by legacy Warden (<c>Auth/ARC4.h</c>). The stream is stateful and must
/// be fed every packet in order, in both directions.
/// </summary>
internal sealed class WardenArc4
{
    private readonly byte[] _state = new byte[256];
    private int _i;
    private int _j;

    public WardenArc4(ReadOnlySpan<byte> key)
    {
        Init(key);
    }

    public void Init(ReadOnlySpan<byte> key)
    {
        for (int i = 0; i < 256; i++)
            _state[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + _state[i] + key[i % key.Length]) & 0xFF;
            (_state[i], _state[j]) = (_state[j], _state[i]);
        }

        _i = 0;
        _j = 0;
    }

    /// <summary>XORs <paramref name="data"/> in place with the keystream (encrypt == decrypt).</summary>
    public void Process(Span<byte> data)
    {
        for (int k = 0; k < data.Length; k++)
        {
            _i = (_i + 1) & 0xFF;
            _j = (_j + _state[_i]) & 0xFF;
            (_state[_i], _state[_j]) = (_state[_j], _state[_i]);
            data[k] ^= _state[(_state[_i] + _state[_j]) & 0xFF];
        }
    }
}
