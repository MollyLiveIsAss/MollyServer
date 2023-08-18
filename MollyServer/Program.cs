using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using MollyServer.Security;
using MollyServer.Utilities;

/*
    Hello cutie, you may notice this source code is mess. I done this in under 3 hours.
    The XKE & XOS challenge generation was done through code used from leaked APIs. - Credit to the original creators.
    The Stream.cs was stolen from another source code, can't remember which one. - Same goes for the RC4 encryption.
    Rest was done by me.
 */

namespace MollyServer
{
    internal class Program
    {
        static TcpListener leServer = null;

        static void Main(string[] args)
        {
            Console.Title = "MLE ~ It's online more than the original!";
            Console.WindowWidth = 150;
            Console.WindowHeight = 31;

            try
            {
                leServer = new TcpListener(IPAddress.Any, 7364);
                Console.WriteLine("MollyLive Emulated ~ Services Online (unlike the original)");

                new Thread(new ThreadStart(() => ConnectionListener())).Start();
            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
            }
        }

        static void ConnectionListener()
        {
            leServer.Start();

            while (true)
            {
                Thread.Sleep(100);
                if (leServer.Pending())
                    new Thread(new ThreadStart(() => ClientHandler(leServer.AcceptTcpClient()))).Start();
            }
        }

        static void ClientHandler(TcpClient Client)
        {
            NetworkStream Stream = Client.GetStream();
            SecuredStream securedStream = new SecuredStream(Stream);

            try
            {
                byte[] Header = new byte[8];

                if (Stream.Read(Header, 0, 8) != 8)
                    return;

                EndianIO Endian = new EndianIO(Header, EndianStyle.BigEndian);
                uint Command = Endian.Reader.ReadUInt32();
                int Size = Endian.Reader.ReadInt32();
                byte[] Data = new byte[Size];

                if ((Size > 0x4100) || securedStream.Read(Data, 0, Size) != Size)
                {
                    Console.WriteLine("Invalid Packet Detected!");
                    return;
                }

                EndianIO SecuredEndian = new EndianIO(Data, EndianStyle.BigEndian)
                {
                    Writer = new EndianWriter(securedStream, EndianStyle.BigEndian)
                };

                switch (Command)
                {
                    case 0x10: // Authentication
                        uint AuthVersion = SecuredEndian.Reader.ReadUInt32(); // Version
                        byte[] AuthCPUKey = SecuredEndian.Reader.ReadBytes(0x10); // SeePeeYouKey
                        byte[] AuthModuleHash = SecuredEndian.Reader.ReadBytes(0x14); // Oh no, our module hash, it's broken!
                        byte[] AuthKV = SecuredEndian.Reader.ReadBytes(0x4000); // Let's not do a molly and store this.
                        File.WriteAllBytes($"assets/xosc/kvs/kv.{Utils.BytesToHexString(AuthCPUKey)}.bin", AuthKV);

                        //if (!ModuleHash.SequenceEqual(XeCrypt.XeCryptSha(File.ReadAllBytes("assets/molly.xex")))) {
                        //    // client needs an update
                        //}

                        Console.WriteLine("Authentication ~ Spoofed");

                        SecuredEndian.Writer.Write(0x4A000000); // Spoof le soccess statoos.
                        SecuredEndian.Writer.Write(File.ReadAllBytes("assets/patch_cod.bin"));
                        SecuredEndian.Writer.Write(0x82497EB0); // send dis
                        SecuredEndian.Writer.Write(0x00013000); // send dis
                        Client.Close(); // Close le connection.
                        break;
                    case 0x20: // Presence
                        uint TitleId = SecuredEndian.Reader.ReadUInt32(); // TitleId
                        byte[] PresCPUKey = SecuredEndian.Reader.ReadBytes(0x10); // SeePeeYouKey
                        byte[] PresModuleHash = SecuredEndian.Reader.ReadBytes(0x14); // Oh no, our module hash, it's broken!
                        byte[] Gamertag = SecuredEndian.Reader.ReadBytes(0x10); // Gamertag
                        uint KVStatus = SecuredEndian.Reader.ReadUInt32(); // KVStatus

                        Console.WriteLine("Presence ~ Spoofed");

                        byte[] Response = new byte[0x24];
                        Buffer.BlockCopy(BitConverter.GetBytes(0x4D000000).Reverse().ToArray(), 0, Response, 0, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(12).Reverse().ToArray(), 0, Response, 4, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(34).Reverse().ToArray(), 0, Response, 8, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(56).Reverse().ToArray(), 0, Response, 0xC, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(13).Reverse().ToArray(), 0, Response, 0x10, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(33).Reverse().ToArray(), 0, Response, 0x14, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(37).Reverse().ToArray(), 0, Response, 0x18, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(0x00000032).Reverse().ToArray(), 0, Response, 0x1C, 4);
                        Buffer.BlockCopy(BitConverter.GetBytes(0x0000000A).Reverse().ToArray(), 0, Response, 0x20, 4);

                        SecuredEndian.Writer.Write(Response); // Spoof le soccess statoos.
                        Client.Close(); // Close le connection.
                        break;
                    case 0x30: // XeKeysExecute
                        byte[] CPUKey = SecuredEndian.Reader.ReadBytes(0x10);
                        byte[] HVSalt = SecuredEndian.Reader.ReadBytes(0x10);
                        byte PartNumber = SecuredEndian.Reader.ReadByte();
                        bool CRL = Convert.ToBoolean(Convert.ToInt16(SecuredEndian.Reader.ReadInt32()));
                        bool FCRT = Convert.ToBoolean(Convert.ToInt16(SecuredEndian.Reader.ReadInt32()));
                        bool TypeOne = Convert.ToBoolean(Convert.ToInt16(SecuredEndian.Reader.ReadInt32()));

                        // Stolen From The Leaked API That They Use - Credit to whoever made it.

                        SecuredEndian.Writer.Write(0x4A000000); // Spoof le soccess statoos.

                        byte[] XKERequestBuffer = new byte[0x24];
                        Buffer.BlockCopy(CPUKey, 0, XKERequestBuffer, 0, 0x10);
                        Buffer.BlockCopy(HVSalt, 0, XKERequestBuffer, 0x10, 0x10);
                        XKERequestBuffer[0x20] = Convert.ToByte(CRL);
                        XKERequestBuffer[0x21] = Convert.ToByte(FCRT);
                        XKERequestBuffer[0x22] = Convert.ToByte(TypeOne);
                        XKERequestBuffer[0x23] = PartNumber;

                        // End Stolen

                        byte[] xkechallenge = XKEC.XKECResponse(XKERequestBuffer);
                        SecuredEndian.Writer.Write(xkechallenge);

                        Console.WriteLine("XKEC ~ Spoofed");

                        Client.Close(); // Close le connection.
                        break;
                    case 0x40: // XboxOnlineSupervisor
                        byte[] XOSCBuffer = SecuredEndian.Reader.ReadBytes(0x2E0);
                        byte[] XOSCTitle = SecuredEndian.Reader.ReadBytes(4);
                        byte[] XOSCCPUKey = SecuredEndian.Reader.ReadBytes(0x10);
                        byte[] XOSCKVDigest = SecuredEndian.Reader.ReadBytes(0x14);
                        byte[] XOSCFinal1 = SecuredEndian.Reader.ReadBytes(0x10);
                        byte[] XOSCFinal2 = SecuredEndian.Reader.ReadBytes(0x8);

                        SecuredEndian.Writer.Write(0x4A000000); // Spoof le soccess statoos.

                        // Stolen From The Leaked API That They Use - Credit to whoever made it.
                        byte[] KV = File.ReadAllBytes($"assets/xosc/kvs/kv.{Utils.BytesToHexString(XOSCCPUKey)}.bin");
                        byte[] ConsoleId = new byte[5]; Array.Copy(KV, 0x9CA, ConsoleId, 0, 5);
                        byte[] ConsolePartNumber = new byte[0xB]; Array.Copy(KV, 0x9CF, ConsolePartNumber, 0, 0xB);
                        byte SerialIndex = (byte)(((ConsolePartNumber[2] << 4) & 0xF0) | (ConsolePartNumber[3] & 0xF));
                        ushort KVOddFeatures = Utils.GetBeUInt16(KV, 0x1C);
                        bool fcrt = (KVOddFeatures & 0x120) != 0 ? true : false;
                        byte[] KVSig = new byte[0x100]; Array.Copy(KV, 0x1DF8, KVSig, 0, 0x100);
                        byte[] MACAddress = { 0, 0x22, 0x48, (byte)(((ConsoleId[1] << 4) & 0xF0) | ((ConsoleId[2] >> 4) & 0xF)), (byte)(((ConsoleId[2] << 4) & 0xF0) | ((ConsoleId[3] >> 4) & 0xF)), (byte)(((ConsoleId[3] << 4) & 0xF0) | ((ConsoleId[4] >> 4) & 0xF)) };

                        bool type1 = true;
                        for (int i = 0; i < 0x100; i++)
                        {
                            if (KVSig[i] != 0)
                            {
                                type1 = false;
                                break;
                            }
                        }

                        byte[] KeyvaultVariables = new byte[0x60];
                        Buffer.BlockCopy(MACAddress, 0, KeyvaultVariables, 0, 0x6);
                        Buffer.BlockCopy(XOSCKVDigest, 0, KeyvaultVariables, 0x6, 0x14);
                        KeyvaultVariables[0x1A] = KV[0xC89];
                        Buffer.BlockCopy(KV.Skip(0xC8A).Take(0x24).ToArray(), 0, KeyvaultVariables, 0x1B, 0x24);
                        Buffer.BlockCopy(KV.Skip(0xB0).Take(0xC).ToArray(), 0, KeyvaultVariables, 0x3F, 0xC);
                        Buffer.BlockCopy(KV.Skip(0xC8).Take(0x2).ToArray(), 0, KeyvaultVariables, 0x4B, 0x2);
                        Buffer.BlockCopy(KV.Skip(0x1C).Take(0x2).ToArray(), 0, KeyvaultVariables, 0x4D, 0x2);
                        Buffer.BlockCopy(KV.Skip(0x24).Take(0x4).ToArray(), 0, KeyvaultVariables, 0x4F, 0x4);
                        Buffer.BlockCopy(KV.Skip(0x30).Take(0x8).ToArray(), 0, KeyvaultVariables, 0x53, 0x8);
                        Buffer.BlockCopy(KV.Skip(0x9CA).Take(0x5).ToArray(), 0, KeyvaultVariables, 0x5B, 0x5);

                        byte[] RequestBuffer = new byte[0x90];
                        Buffer.BlockCopy(XOSCCPUKey, 0, RequestBuffer, 0, 0x10);
                        RequestBuffer[0x10] = Convert.ToByte(true);
                        RequestBuffer[0x11] = Convert.ToByte(fcrt);
                        RequestBuffer[0x12] = Convert.ToByte(type1);
                        RequestBuffer[0x13] = SerialIndex;
                        Buffer.BlockCopy(BitConverter.GetBytes(BitConverter.ToUInt32(XOSCTitle.Reverse().ToArray(), 0)).Reverse().ToArray(), 0, RequestBuffer, 0x14, 0x4);
                        Buffer.BlockCopy(XOSCFinal1, 0, RequestBuffer, 0x18, 0x10);
                        Buffer.BlockCopy(XOSCFinal2, 0, RequestBuffer, 0x28, 0x8);
                        Buffer.BlockCopy(KeyvaultVariables, 0, RequestBuffer, 0x30, 0x60);

                        byte[] challenge = XOSC.XOSCResponse(RequestBuffer);
                        SecuredEndian.Writer.Write(challenge.Take(0x2E0).Reverse().ToArray());

                        // End Stolen

                        Console.WriteLine("XOSC ~ Spoofed");

                        Client.Close(); // Close le connection.
                        break;
                    case 0x50: // Redeem Token
                        byte[] RTCPUKey = SecuredEndian.Reader.ReadBytes(0x10);
                        string Code = string.Join("", SecuredEndian.Reader.ReadBytes(0xC).ToArray().Select(x => (char)x).ToArray());
                        Console.WriteLine($"Token: {Code}");


                        SecuredEndian.Writer.Write(0x40000000);
                        Client.Close(); // Close le connection.
                        break;
                    case 0x60: // Download Engine
                        byte[] DECPUKey = SecuredEndian.Reader.ReadBytes(0x10);
                        uint DETitleId = SecuredEndian.Reader.ReadUInt32(); // TitleId

                        if (File.Exists($"assets/engines/{DETitleId.ToString("X").ToLower()}.xex"))
                        {
                            Console.WriteLine("Download Engine ~ Spoofed");
                            SecuredEndian.Writer.Write(0x14187F41); // Spoof le soccess statoos.

                            string Name = "cheats.bin";
                            byte[] EngineResponse = new byte[0x14];
                            Buffer.BlockCopy(new byte[0x10], 0, EngineResponse, 0, 0x10);
                            Buffer.BlockCopy(Encoding.ASCII.GetBytes(Name), 0, EngineResponse, 0, Name.Length);
                            Buffer.BlockCopy(BitConverter.GetBytes(File.ReadAllBytes($"assets/engines/{DETitleId.ToString("X").ToLower()}.xex").Length).Reverse().ToArray(), 0, EngineResponse, 0x10, 4);
                            SecuredEndian.Writer.Write(EngineResponse); // Send the data.

                            SecuredEndian.Writer.Write(File.ReadAllBytes($"assets/engines/{DETitleId.ToString("X").ToLower()}.xex")); // Send the engine.
                        }
                        else
                        {
                            Console.WriteLine("Download Engine ~ Not Found");
                            SecuredEndian.Writer.Write(0x40000000); // Spoof le failed statoos.
                        }

                        Client.Close(); // Close le connection.
                        break;
                    default:
                        Console.WriteLine($"Unknown Command: {Command.ToString("X")}");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}