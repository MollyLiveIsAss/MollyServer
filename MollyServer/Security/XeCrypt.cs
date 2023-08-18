using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MollyServer.Security
{
    internal class XeCrypt
    {
        public static void XeCryptRc4(ref byte[] Data, byte[] Key, uint BeginAt = 0)
        {
            byte num;
            int num2;
            int index = 0;

            byte[] buffer = new byte[0x100];
            byte[] buffer2 = new byte[0x100];

            for (num2 = 0; num2 < 0x100; num2++)
            {
                buffer[num2] = (byte)num2;
                buffer2[num2] = Key[num2 % Key.GetLength(0)];
            }

            for (num2 = 0; num2 < 0x100; num2++)
            {
                index = ((index + buffer[num2]) + buffer2[num2]) % 0x100;
                num = buffer[num2];
                buffer[num2] = buffer[index];
                buffer[index] = num;
            }

            num2 = index = 0;

            for (int i = (int)BeginAt; i < Data.GetLength(0); i++)
            {
                num2 = (num2 + 1) % 0x100;
                index = (index + buffer[num2]) % 0x100;
                num = buffer[num2];
                buffer[num2] = buffer[index];
                buffer[index] = num;
                int num5 = (buffer[num2] + buffer[index]) % 0x100;
                Data[i] = (byte)(Data[i] ^ buffer[num5]);
            }
        }

        public static byte[] XeCryptSha(byte[] Data)
        {
            SHA1Managed SHA1 = new SHA1Managed();
            return SHA1.ComputeHash(Data);
        }
    }
}