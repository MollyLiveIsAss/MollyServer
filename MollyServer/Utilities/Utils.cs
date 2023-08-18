using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MollyServer.Utilities
{
    internal class Utils
    {
        public static string BytesToHexString(byte[] Buffer)
        {
            string str = "";
            for (int i = 0; i < Buffer.Length; i++) { str = str + Buffer[i].ToString("X2"); }
            return str;
        }

        public static ushort GetBeUInt16(byte[] Data, int Index)
        {
            byte[] Buffer = new byte[2];
            Array.Copy(Data, Index, Buffer, 0, 2);
            Array.Reverse(Buffer);
            return BitConverter.ToUInt16(Buffer, 0);
        }
    }
}
