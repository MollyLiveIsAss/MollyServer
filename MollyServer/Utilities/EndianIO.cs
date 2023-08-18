using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MollyServer.Utilities
{
    public enum EndianStyle
    {
        LittleEndian,
        BigEndian
    }

    public class EndianReader : BinaryReader
    {
        private readonly EndianStyle endianStyle;

        public EndianReader(Stream stream, EndianStyle endianstyle)
            : base(stream)
        {
            this.endianStyle = endianstyle;
        }

        public override short ReadInt16()
        {
            return this.ReadInt16(this.endianStyle);
        }

        public short ReadInt16(EndianStyle endianstyle)
        {
            byte[] buffer = base.ReadBytes(2);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            return BitConverter.ToInt16(buffer, 0);
        }

        public override ushort ReadUInt16()
        {
            return this.ReadUInt16(this.endianStyle);
        }

        public ushort ReadUInt16(EndianStyle endianstyle)
        {
            byte[] buffer = base.ReadBytes(2);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            return BitConverter.ToUInt16(buffer, 0);
        }

        public override int ReadInt32()
        {
            return this.ReadInt32(this.endianStyle);
        }

        public int ReadInt32(EndianStyle endianstyle)
        {
            byte[] buffer = base.ReadBytes(4);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            return BitConverter.ToInt32(buffer, 0);
        }

        public override uint ReadUInt32()
        {
            return this.ReadUInt32(this.endianStyle);
        }

        public uint ReadUInt32(EndianStyle endianstyle)
        {
            byte[] buffer = base.ReadBytes(4);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            return BitConverter.ToUInt32(buffer, 0);
        }

        public override long ReadInt64()
        {
            return this.ReadInt64(this.endianStyle);
        }

        public long ReadInt64(EndianStyle endianstyle)
        {
            byte[] buffer = base.ReadBytes(8);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            return BitConverter.ToInt64(buffer, 0);
        }

        public override ulong ReadUInt64()
        {
            return this.ReadUInt64(this.endianStyle);
        }

        public ulong ReadUInt64(EndianStyle endianstyle)
        {
            byte[] buffer = base.ReadBytes(8);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            return BitConverter.ToUInt64(buffer, 0);
        }

        public void Seek(long position)
        {
            base.BaseStream.Position = position;
        }
    }

    public class EndianWriter : BinaryWriter
    {
        private readonly EndianStyle endianStyle;

        public EndianWriter(Stream stream, EndianStyle endianstyle)
            : base(stream)
        {
            this.endianStyle = endianstyle;
        }

        public override void Write(short value)
        {
            this.Write(value, this.endianStyle);
        }

        public void Write(short value, EndianStyle endianstyle)
        {
            byte[] buffer = BitConverter.GetBytes(value);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            base.Write(buffer);
        }

        public override void Write(ushort value)
        {
            this.Write(value, this.endianStyle);
        }

        public void Write(ushort value, EndianStyle endianstyle)
        {
            byte[] buffer = BitConverter.GetBytes(value);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            base.Write(buffer);
        }

        public override void Write(int value)
        {
            this.Write(value, this.endianStyle);
        }

        public void Write(int value, EndianStyle endianstyle)
        {
            byte[] buffer = BitConverter.GetBytes(value);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            base.Write(buffer);
        }

        public override void Write(uint value)
        {
            this.Write(value, this.endianStyle);
        }

        public void Write(uint value, EndianStyle endianstyle)
        {
            byte[] buffer = BitConverter.GetBytes(value);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            base.Write(buffer);
        }

        public override void Write(long value)
        {
            this.Write(value, this.endianStyle);
        }

        public void Write(long value, EndianStyle endianstyle)
        {
            byte[] buffer = BitConverter.GetBytes(value);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            base.Write(buffer);
        }

        public override void Write(ulong value)
        {
            this.Write(value, this.endianStyle);
        }

        public void Write(ulong value, EndianStyle endianstyle)
        {
            byte[] buffer = BitConverter.GetBytes(value);
            if (endianstyle == EndianStyle.BigEndian) Array.Reverse(buffer);
            base.Write(buffer);
        }

        public void WriteString(string value)
        {
            char[] buffer = value.ToCharArray();
            base.Write(buffer);
        }

        public void Seek(long position)
        {
            base.BaseStream.Position = position;
        }
    }

    public class EndianIO
    {
        private readonly EndianStyle endianStyle;
        private readonly string filePath;
        private readonly bool isFile;

        public EndianIO(Stream stream, EndianStyle endianstyle)
        {
            this.filePath = string.Empty;
            this.endianStyle = endianstyle;
            this.Stream = stream;
            this.isFile = false;
            this.Open();
        }

        public EndianIO(string filepath, EndianStyle endianstyle)
        {
            this.filePath = string.Empty;
            this.endianStyle = endianstyle;
            this.filePath = filepath;
            this.isFile = true;
            this.Open();
        }

        public EndianIO(byte[] buffer, EndianStyle endianstyle)
        {
            this.filePath = string.Empty;
            this.endianStyle = endianstyle;
            this.Stream = new MemoryStream(buffer);
            this.isFile = false;
            this.Open();
        }

        public EndianIO(string filepath, EndianStyle endianstyle, FileMode filemode)
        {
            this.filePath = string.Empty;
            this.endianStyle = endianstyle;
            this.filePath = filepath;
            this.isFile = true;
            this.Open(filemode);
        }

        public void Open()
        {
            this.Open(FileMode.Open);
        }

        public void Open(FileMode filemode)
        {
            if (!this.Opened)
            {
                if (this.isFile) this.Stream = new FileStream(this.filePath, filemode, FileAccess.ReadWrite);
                this.Reader = new EndianReader(this.Stream, this.endianStyle);
                this.Writer = new EndianWriter(this.Stream, this.endianStyle);
                this.Opened = true;
            }
        }

        public byte[] ToArray()
        {
            return ((MemoryStream)this.Stream).ToArray();
        }

        public long Position
        {
            get { return this.Stream.Position; }
            set { this.Stream.Position = value; }
        }

        public bool Opened { get; set; }

        public EndianReader Reader { get; set; }

        public EndianWriter Writer { get; set; }

        public Stream Stream { get; set; }
    }
}
