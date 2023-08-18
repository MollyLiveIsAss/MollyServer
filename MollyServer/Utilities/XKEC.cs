using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MollyServer.Utilities
{
    internal class XKEC
    {
        public static Random Random = new Random();
        public static int GetRandomNumber(int Min, int Max) { return Random.Next(Min, Max); }
        public static byte[] ComputeECCDigest(byte[] HVSalt, string CPUKey)
        {
            for (int i = 0; i < 0x100; i++)
            {
                if (!Enumerable.SequenceEqual(HVSalt, File.ReadAllBytes("assets/xkec/Salts.bin").Skip(i * 0x10).Take(0x10).ToArray())) continue;
                return File.ReadAllBytes("assets/xkec/Keysets/" + File.ReadAllText("assets/xkec/KeysetIDs/" + CPUKey + ".txt") + "/ECCDigests.bin").Skip(i * 0x14).Take(0x14).ToArray();
            }
            return null;
        }
        public static byte[] ComputeHVDigest(byte[] HVSalt, string CPUKey)
        {
            for (int i = 0; i < 0x100; i++)
            {
                if (!Enumerable.SequenceEqual(HVSalt, File.ReadAllBytes("assets/xkec/Salts.bin").Skip(i * 0x10).Take(0x10).ToArray())) continue;
                return File.ReadAllBytes("assets/xkec/HVDigests.bin").Skip(i * 0x6).Take(0x6).ToArray();
            }
            return null;
        }
        public static byte[] ComputeUpdateSequence(byte[] Index)
        {
            byte[] UpdateSequence = new byte[0x3];
            Buffer.BlockCopy(SHA1ComputeHash(Index), 0, UpdateSequence, 0, 0x3);
            return UpdateSequence;
        }
        public static uint ComputeHVStatusFlags(bool CRL, bool FCRT)
        {
            uint HVStatusFlags = 0x023289D3;
            if (CRL) { HVStatusFlags |= 0x10000; }
            if (FCRT) { HVStatusFlags |= 0x1000000; }
            return HVStatusFlags;
        }
        public static uint ComputeConsoleTypeFlags(byte ConsoleIdentifier)
        {
            uint ConsoleTypeFlags = 0;
            if (ConsoleIdentifier < 0x10) ConsoleTypeFlags = 0x010B0524;
            else if (ConsoleIdentifier < 0x14) ConsoleTypeFlags = 0x010C0AD0;
            else if (ConsoleIdentifier < 0x18) ConsoleTypeFlags = 0x010C0AD8;
            else if (ConsoleIdentifier < 0x52) ConsoleTypeFlags = 0x010C0FFB;
            else if (ConsoleIdentifier < 0x58) ConsoleTypeFlags = 0x0304000D;
            else ConsoleTypeFlags = 0x0304000E;
            return ConsoleTypeFlags;
        }
        public static byte[] SHA1ComputeHash(byte[] Data)
        {
            SHA1Managed SHA1 = new SHA1Managed();
            return SHA1.ComputeHash(Data);
        }

        public static byte[] XKECResponse(byte[] ReceivedBuffer)
        {
            byte[] XKECBuffer = File.ReadAllBytes("assets/xkec/Template.bin");
            byte[] CPUKey = new byte[0x10];
            byte[] HVSalt = new byte[0x10];
            bool CRL = false;
            bool FCRT = false;
            bool KVType = false;
            byte ConsoleIdentifier = 0;

            Buffer.BlockCopy(ReceivedBuffer, 0x0, CPUKey, 0x0, 0x10);
            Buffer.BlockCopy(ReceivedBuffer, 0x10, HVSalt, 0x0, 0x10);
            CRL = Convert.ToBoolean(ReceivedBuffer[0x20]);
            FCRT = Convert.ToBoolean(ReceivedBuffer[0x21]);
            KVType = Convert.ToBoolean(ReceivedBuffer[0x22]);
            ConsoleIdentifier = ReceivedBuffer[0x23];
            if (!File.Exists("assets/xkec/KeysetIDs/" + Utils.BytesToHexString(CPUKey) + ".txt") || !CRL)
            {
                File.WriteAllText("assets/xkec/KeysetIDs/" + Utils.BytesToHexString(CPUKey) + ".txt", "" + GetRandomNumber(1, 50));
            }

            Buffer.BlockCopy((KVType ? BitConverter.GetBytes((ushort)0xD81E).Reverse().ToArray() : BitConverter.GetBytes((ushort)0xD83E).Reverse().ToArray()), 0, XKECBuffer, 0x2E, 0x2);

            Buffer.BlockCopy(ComputeUpdateSequence(CPUKey.Skip(0xB).Take(0x5).Reverse().ToArray()), 0, XKECBuffer, 0x34, 0x3);

            Buffer.BlockCopy(BitConverter.GetBytes(ComputeHVStatusFlags(CRL, FCRT)).Reverse().ToArray(), 0, XKECBuffer, 0x38, 0x4);

            Buffer.BlockCopy(BitConverter.GetBytes(ComputeConsoleTypeFlags(ConsoleIdentifier)).Reverse().ToArray(), 0, XKECBuffer, 0x3C, 0x4);

            Buffer.BlockCopy(ComputeECCDigest(HVSalt, Utils.BytesToHexString(CPUKey)), 0, XKECBuffer, 0x50, 0x14);

            Buffer.BlockCopy(SHA1ComputeHash(CPUKey), 0, XKECBuffer, 0x64, 0x14);

            Buffer.BlockCopy(File.ReadAllBytes("assets/xkec/Keysets/" + File.ReadAllText("assets/xkec/KeysetIDs/" + Utils.BytesToHexString(CPUKey) + ".txt") + "/RSA.bin"), 0, XKECBuffer, 0x78, 0x80);

            Buffer.BlockCopy(ComputeHVDigest(HVSalt, Utils.BytesToHexString(CPUKey)), 0, XKECBuffer, 0xFA, 0x6);

            return XKECBuffer;
        }
    }
}
