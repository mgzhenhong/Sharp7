namespace Sharp7.Tests
{
    public class ClientTest : ServerClientTestBase
    {

        [Fact]
        public void ClientIsNotNull()
        {
            this.Client.ShouldNotBeNull();
        }

        [Fact]
        public void ServerIsNotNull()
        {
            this.Server.ShouldNotBeNull();
        }

        [Fact]
        public void Timeout()
        {
            this.Client.ConnTimeout.ShouldBe(2000);
        }

        [Fact]
        public void Connected()
        {
            this.Client.Connected.ShouldBe(true);
        }

        [Fact]
        public void Port()
        {
            this.Client.PLCPort.ShouldBe(102);
        }

        [Fact]
        public void ReadWriteDb()
        {
            var bytes = new byte[] { 1, 2, 3 };
            var index = 3;
            this.Server.RegisterArea(S7Server.SrvAreaDB, index, ref bytes, bytes.Length);

            var buffer = new byte[bytes.Length];
            var rc = this.Client.DBRead(index, 0, bytes.Length, buffer);

            //test read
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            buffer.ShouldBe(bytes);

            buffer = new byte[] { 3, 2, 1 };
            rc = this.Client.DBWrite(index, 0, bytes.Length, buffer);

            //test write
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            bytes.ShouldBe(buffer);
        }

        [Fact]
        public void ReadWriteAb()
        {
            var bytes = new byte[] { 1, 2, 3 };
            this.Server.RegisterArea(S7Server.SrvAreaPa, 0, ref bytes, bytes.Length);

            var buffer = new byte[bytes.Length];
            var rc = this.Client.ABRead(0, bytes.Length, buffer);

            //test read
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            buffer.ShouldBe(bytes);

            buffer = new byte[] { 3, 2, 1 };
            rc = this.Client.ABWrite(0, bytes.Length, buffer);

            //test write
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            bytes.ShouldBe(buffer);
        }

        [Fact]
        public void ReadWriteCt()
        {
            var bytes = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
            var index = 3;
            this.Server.RegisterArea(S7Server.SrvAreaCt, index, ref bytes, bytes.Length / 2);

            var buffer = new ushort[2];
            var rc = this.Client.CTRead(0, 2, buffer);

            //test read
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            buffer.ShouldBe(new ushort[] { 0x0100, 0x0302 });

            buffer = new ushort[] { 0x0403, 0x0201 };
            rc = this.Client.CTWrite(0, 2, buffer);

            //test write
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            bytes.ShouldBe(new byte[] { 3, 4, 1, 2, 4, 5, 6, 7, 8 });
        }

        [Fact]
        public void ReadWriteMb()
        {
            var bytes = new byte[] { 0, 1, 2 };
            this.Server.RegisterArea(S7Server.SrvAreaMk, 0, ref bytes, bytes.Length);

            var buffer = new byte[bytes.Length];
            var rc = this.Client.MBRead(0, bytes.Length, buffer);

            //test read
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            buffer.ShouldBe(bytes);

            buffer = new byte[] { 3, 2, 1 };
            rc = this.Client.MBWrite(0, bytes.Length, buffer);

            //test write
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            bytes.ShouldBe(buffer);
        }

        [Fact]
        public void ReadWriteTm()
        {
            var bytes = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
            var index = 5;
            this.Server.RegisterArea(S7Server.SrvAreaTm, index, ref bytes, bytes.Length / 2);

            var buffer = new ushort[2];
            var rc = this.Client.TMRead(0, 2, buffer);

            //test read
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            buffer.ShouldBe(new ushort[] { 0x0100, 0x0302 });

            buffer = new ushort[] { 0x0403, 0x0201 };
            rc = this.Client.TMWrite(0, 2, buffer);

            //test write
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            bytes.ShouldBe(new byte[] { 3, 4, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11 });
        }

        [Fact]
        public void ReadWriteEb()
        {
            var bytes = new byte[] { 0, 1, 2 };
            this.Server.RegisterArea(S7Server.SrvAreaPe, 0, ref bytes, bytes.Length);

            var buffer = new byte[bytes.Length];
            var rc = this.Client.EBRead(0, bytes.Length, buffer);

            //test read
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            buffer.ShouldBe(bytes);

            buffer = new byte[] { 3, 2, 1 };
            rc = this.Client.EBWrite(0, bytes.Length, buffer);

            //test write
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
            bytes.ShouldBe(buffer);
        }

        [Fact]
        public void Multivars()
        {
            var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
            var index = 30;
            this.Server.RegisterArea(S7Server.SrvAreaDB, index, ref bytes, bytes.Length);

            var buffer = new byte[bytes.Length];
            var multivar = new S7MultiVar(this.Client);
            multivar.ShouldNotBeNull();

            multivar.Add(new Sharp7.S7Consts.S7Tag() { Area = (int)S7Area.DB, DBNumber = index, Elements = 2, Start = 0, WordLen = 2 }, ref buffer).ShouldBe(true);

            multivar.Read().ShouldBe(Sharp7.S7Consts.ResultOK);
            multivar.Add(new Sharp7.S7Consts.S7Tag() { Area = (int)S7Area.DB, DBNumber = index, Elements = 2, Start = 0, WordLen = 2 }, ref buffer).ShouldBe(true);

            multivar.Write().ShouldBe(Sharp7.S7Consts.ResultOK);

        }
    }
}
