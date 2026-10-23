using System;
using Framework;
using Framework.Logging;
using HermesProxy.Enums;
using HermesProxy.World.Enums;
using HermesProxy.World.Dispatch;
using HermesProxy.World.Server.Warden;

namespace HermesProxy.World.Client;

public partial class WorldClient
{
    /// <summary>
    /// Legacy Warden traffic. Historically this opcode was dropped (it is on the handshake
    /// ignore-list), which is fine only while the server has Warden disabled: with
    /// <c>Warden.WinEnabled=1</c> the server asks for a challenge response nobody produces and
    /// kicks the session after the timeout.
    /// </summary>
    [HandlesSmsg(Opcode.SMSG_WARDEN_DATA)]
    internal void HandleWardenData(WorldPacket packet)
    {
        var session = GetSession();

        WardenSession? warden = session.Warden;
        if (warden == null)
        {
            // The keystream is derived from the SRP premaster secret of the legacy login.
            byte[]? sessionKey = session.AuthClient?.GetSessionKey();
            if (sessionKey == null || sessionKey.Length == 0)
            {
                Log.Print(LogType.Warn, "Warden data received but the SRP session key is unavailable; ignoring.");
                return;
            }

            warden = new WardenSession(sessionKey);
            session.Warden = warden;
        }

        ReadOnlySpan<byte> body = packet.GetRemainingSpan();
        warden.HandleServerPayload(body, reply =>
        {
            var outbound = new WorldPacket(Opcode.CMSG_WARDEN_DATA);
            outbound.WriteBytes(reply);
            SendPacketToServer(outbound);
        });
    }
}
