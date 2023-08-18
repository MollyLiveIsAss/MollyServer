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
    internal class XOSC
    {
        public static byte[] SHA1ComputeHash(byte[] Data)
        {
            SHA1Managed SHA1 = new SHA1Managed();
            return SHA1.ComputeHash(Data);
        }
        public static byte[] ComputeSecurityFuse(byte ConsoleIdentifier)
        {
            byte[] SecurityFuse = new byte[0x10];
            if (ConsoleIdentifier < 0x10) SecurityFuse = new byte[] { 0xC0, 0xDC, 0xFE, 0xF3, 0xD7, 0x3E, 0xED, 0x7E, 0x5A, 0xF8, 0xB1, 0xBB, 0xB2, 0xE0, 0x26, 0x95 };
            else if (ConsoleIdentifier < 0x14) SecurityFuse = new byte[] { 0x02, 0x24, 0xEE, 0xA6, 0x1E, 0x89, 0x8B, 0xA1, 0x55, 0xB5, 0xAF, 0x74, 0xAA, 0x78, 0xAD, 0x0B };
            else if (ConsoleIdentifier < 0x18) SecurityFuse = new byte[] { 0x4E, 0xEA, 0xA3, 0x32, 0x3D, 0x9F, 0x40, 0xAA, 0x90, 0xC0, 0x0E, 0xFC, 0x5A, 0xD5, 0xB0, 0x00 };
            else if (ConsoleIdentifier < 0x52) SecurityFuse = new byte[] { 0xFF, 0x23, 0x99, 0x90, 0xED, 0x61, 0xD1, 0x54, 0xB2, 0x31, 0x35, 0x99, 0x0D, 0x90, 0xBD, 0xBC };
            else if (ConsoleIdentifier < 0x58) SecurityFuse = new byte[] { 0xDB, 0xE6, 0x35, 0x87, 0x78, 0xCB, 0xFC, 0x2F, 0x52, 0xA3, 0xBA, 0xF8, 0x92, 0x45, 0x8D, 0x65 };
            else SecurityFuse = new byte[] { 0x63, 0x2B, 0xBE, 0xDF, 0xBB, 0x41, 0x86, 0xA4, 0xD2, 0xB9, 0x4B, 0x8E, 0x44, 0xDD, 0x29, 0x52 };
            return SecurityFuse;
        }
        public static byte[] ComputeSMC(byte ConsoleIdentifier)
        {
            byte[] SMC = new byte[0x5];
            if (ConsoleIdentifier < 0x10) SMC = new byte[] { 0x12, 0x12, 0x01, 0x33, 0x00 };
            else if (ConsoleIdentifier < 0x14) SMC = new byte[] { 0x12, 0x21, 0x01, 0x09, 0x00 };
            else if (ConsoleIdentifier < 0x18) SMC = new byte[] { 0x12, 0x31, 0x01, 0x06, 0x00 };
            else if (ConsoleIdentifier < 0x52) SMC = new byte[] { 0x12, 0x41, 0x02, 0x03, 0x00 };
            else if (ConsoleIdentifier < 0x58) SMC = new byte[] { 0x12, 0x51, 0x03, 0x01, 0x00 };
            else SMC = new byte[] { 0x12, 0x62, 0x02, 0x05, 0x00 };
            return SMC;
        }
        public static byte[] ComputeTitleDigest(byte[] KVDigest, byte ConsoleIdentifier, byte[] MACAddress, uint TitleID, byte[] Final1, byte[] Final2)
        {
            SHA1Managed SHA1 = new SHA1Managed();
            byte[] TitleDigest = KVDigest;
            Buffer.BlockCopy(ComputeSecurityFuse(ConsoleIdentifier), 0, TitleDigest, 0x10, 0x4);
            SHA1.TransformBlock(File.ReadAllBytes("assets/xosc/HeaderData/Xam.bin"), 0, File.ReadAllBytes("assets/xosc/HeaderData/Xam.bin").Length, null, 0);
            SHA1.TransformBlock(TitleDigest, 0, 0x14, null, 0);
            SHA1.TransformFinalBlock(Enumerable.Repeat<byte>(0, 0x10).ToArray(), 0, 0x10);
            TitleDigest = SHA1.Hash;

            SHA1.Initialize();
            SHA1.TransformBlock(File.ReadAllBytes("assets/xosc/HeaderData/Kernel.bin"), 0, File.ReadAllBytes("assets/xosc/HeaderData/Kernel.bin").Length, null, 0);
            SHA1.TransformBlock(TitleDigest, 0, 0x14, null, 0);
            SHA1.TransformFinalBlock(MACAddress, 0, 0x6);
            TitleDigest = SHA1.Hash;

            SHA1.Initialize();
            if (File.Exists("assets/xosc/HeaderData/" + TitleID.ToString("X") + ".bin")) { SHA1.TransformBlock(File.ReadAllBytes("assets/xosc/HeaderData/" + TitleID.ToString("X") + ".bin").Skip(0x18).Take(File.ReadAllBytes("assets/xosc/HeaderData/" + TitleID.ToString("X") + ".bin").Length - 0x18).ToArray(), 0, File.ReadAllBytes("assets/xosc/HeaderData/" + TitleID.ToString("X") + ".bin").Length - 0x18, null, 0); }
            else { SHA1.TransformBlock(File.ReadAllBytes("assets/xosc/HeaderData/FFFE07D1.bin").Skip(0x18).Take(File.ReadAllBytes("assets/xosc/HeaderData/FFFE07D1.bin").Length - 0x18).ToArray(), 0, File.ReadAllBytes("assets/xosc/HeaderData/FFFE07D1.bin").Length - 0x18, null, 0); }
            SHA1.TransformBlock(TitleDigest, 0, 0x14, null, 0);
            SHA1.TransformFinalBlock(ComputeSMC(ConsoleIdentifier), 0, 0x5);
            TitleDigest = SHA1.Hash;

            SHA1.Initialize();
            byte[] FinalData = File.ReadAllBytes("assets/xosc/FinalTemplate.bin");
            Buffer.BlockCopy(Final1, 0, FinalData, 0x655D, 0x10);
            Buffer.BlockCopy(Final2, 0, FinalData, 0x6EC0, 0x8);
            SHA1.TransformBlock(FinalData, 0, 0x8E59, null, 0);
            SHA1.TransformFinalBlock(TitleDigest, 0, 0x14);
            TitleDigest = SHA1.Hash;
            TitleDigest[0] = 0x07;

            return TitleDigest;
        }
        public static byte[] ComputePCIEFlag(byte ConsoleIdentifier)
        {
            byte[] PCIEFlag = new byte[0x8];
            if (ConsoleIdentifier < 0x18) PCIEFlag = new byte[] { 0x21, 0x58, 0x02, 0x31, 0x02, 0x00, 0x03, 0x80 };
            else if (ConsoleIdentifier < 0x52) PCIEFlag = new byte[] { 0x31, 0x58, 0x11, 0x60, 0x02, 0x00, 0x03, 0x80 };
            else if (ConsoleIdentifier < 0x58) PCIEFlag = new byte[] { 0x41, 0x58, 0x01, 0x60, 0x02, 0x00, 0x03, 0x80 };
            else PCIEFlag = new byte[] { 0x41, 0x58, 0x01, 0x90, 0x02, 0x00, 0x03, 0x80 };
            return PCIEFlag;
        }
        public static byte[] ComputeHardwareFlag(byte ConsoleIdentifier)
        {
            byte[] HardwareFlag = new byte[0x4];
            if (ConsoleIdentifier < 0x10) HardwareFlag = new byte[] { 0x00, 0x00, 0x02, 0x27 };
            else if (ConsoleIdentifier < 0x14) HardwareFlag = new byte[] { 0x10, 0x00, 0x02, 0x27 };
            else if (ConsoleIdentifier < 0x18) HardwareFlag = new byte[] { 0x20, 0x00, 0x02, 0x27 };
            else if (ConsoleIdentifier < 0x52) HardwareFlag = new byte[] { 0x30, 0x00, 0x02, 0x27 };
            else if (ConsoleIdentifier < 0x58) HardwareFlag = new byte[] { 0x40, 0x00, 0x02, 0x27 };
            else HardwareFlag = new byte[] { 0x50, 0x00, 0x02, 0x27 };
            return HardwareFlag;
        }

        public static byte[] XOSCResponse(byte[] ReceivedBuffer)
        {
            byte[] XOSCBuffer = File.ReadAllBytes("assets/xosc/Template.bin");
            byte[] CPUKey = new byte[0x10];
            bool CRL = false;
            bool FCRT = false;
            bool KVType = false;
            byte ConsoleIdentifier = 0;
            uint TitleID = 0;
            byte[] Final1 = new byte[0x10];
            byte[] Final2 = new byte[0x8];
            byte[] MACAddress = new byte[0x6];
            byte[] KVDigest = new byte[0x14];
            byte KV_C89 = 0;
            byte[] KV_C8A_24 = new byte[0x24];
            byte[] KV_B0_C = new byte[0xC];
            byte[] KV_C8_2 = new byte[0x2];
            byte[] KV_1C_2 = new byte[0x2];
            byte[] KV_24_4 = new byte[0x4];
            byte[] KV_30_8 = new byte[0x8];
            byte[] KV_9CA_5 = new byte[0x5];

            Buffer.BlockCopy(ReceivedBuffer, 0x0, CPUKey, 0x0, 0x10);
            CRL = Convert.ToBoolean(ReceivedBuffer[0x10]);
            FCRT = Convert.ToBoolean(ReceivedBuffer[0x11]);
            KVType = Convert.ToBoolean(ReceivedBuffer[0x12]);
            ConsoleIdentifier = ReceivedBuffer[0x13];
            TitleID = BitConverter.ToUInt32(ReceivedBuffer.Skip(0x14).Take(0x4).Reverse().ToArray(), 0);
            Buffer.BlockCopy(ReceivedBuffer, 0x18, Final1, 0x0, 0x10);
            Buffer.BlockCopy(ReceivedBuffer, 0x28, Final2, 0x0, 0x8);
            Buffer.BlockCopy(ReceivedBuffer, 0x30, MACAddress, 0x0, 0x6);
            Buffer.BlockCopy(ReceivedBuffer, 0x36, KVDigest, 0x0, 0x14);
            KV_C89 = ReceivedBuffer[0x4A];
            Buffer.BlockCopy(ReceivedBuffer, 0x4B, KV_C8A_24, 0x0, 0x24);
            Buffer.BlockCopy(ReceivedBuffer, 0x6F, KV_B0_C, 0x0, 0xC);
            Buffer.BlockCopy(ReceivedBuffer, 0x7B, KV_C8_2, 0x0, 0x2);
            Buffer.BlockCopy(ReceivedBuffer, 0x7D, KV_1C_2, 0x0, 0x2);
            Buffer.BlockCopy(ReceivedBuffer, 0x7F, KV_24_4, 0x0, 0x4);
            Buffer.BlockCopy(ReceivedBuffer, 0x83, KV_30_8, 0x0, 0x8);
            Buffer.BlockCopy(ReceivedBuffer, 0x8B, KV_9CA_5, 0x0, 0x5);

            if (File.Exists("assets/xosc/HeaderData/" + TitleID.ToString("X") + ".bin")) { Buffer.BlockCopy(File.ReadAllBytes("assets/xosc/HeaderData/" + TitleID.ToString("X") + ".bin").Take(0x18).ToArray(), 0, XOSCBuffer, 0x38, 0x18); }
            else { Buffer.BlockCopy(File.ReadAllBytes("assets/xosc/HeaderData/FFFE07D1.bin").Take(0x18).ToArray(), 0, XOSCBuffer, 0x38, 0x18); }
            Buffer.BlockCopy(SHA1ComputeHash(CPUKey).Take(0x10).ToArray(), 0, XOSCBuffer, 0x50, 0x10);
            Buffer.BlockCopy(ComputeTitleDigest(KVDigest, ConsoleIdentifier, MACAddress, TitleID, Final1, Final2), 0, XOSCBuffer, 0x60, 0x10);
            Buffer.BlockCopy(ComputeSecurityFuse(ConsoleIdentifier), 0, XOSCBuffer, 0x70, 0x10);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)KV_C89).Reverse().ToArray(), 0, XOSCBuffer, 0x80, 0x4);
            Buffer.BlockCopy(KV_C8A_24, 0, XOSCBuffer, 0xF0, 0x24);
            Buffer.BlockCopy(KV_C8A_24, 0, XOSCBuffer, 0x114, 0x24);
            Buffer.BlockCopy(KV_B0_C, 0, XOSCBuffer, 0x138, 0xC);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)(KVType ? 0xD81E : 0xD83E)).Reverse().ToArray(), 0, XOSCBuffer, 0x146, 0x2);
            Buffer.BlockCopy(KV_C8_2, 0, XOSCBuffer, 0x148, 0x2);
            Buffer.BlockCopy(KV_1C_2, 0, XOSCBuffer, 0x14A, 0x2);
            Buffer.BlockCopy(KV_24_4, 0, XOSCBuffer, 0x150, 0x4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)(0x023289D3 | (CRL ? 0x10000 : 0) | (FCRT ? 0x1000000 : 0))).Reverse().ToArray(), 0, XOSCBuffer, 0x158, 0x4);
            Buffer.BlockCopy(ComputePCIEFlag(ConsoleIdentifier), 0, XOSCBuffer, 0x170, 0x8);
            Buffer.BlockCopy(KV_30_8, 0, XOSCBuffer, 0x180, 0x8);
            Buffer.BlockCopy(KV_9CA_5, 0, XOSCBuffer, 0x1A0, 0x5);
            Buffer.BlockCopy(ComputeHardwareFlag(ConsoleIdentifier), 0, XOSCBuffer, 0x1D0, 0x4);

            return XOSCBuffer;
        }
    }
}
