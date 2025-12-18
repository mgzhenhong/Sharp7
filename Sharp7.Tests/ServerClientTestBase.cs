namespace Sharp7.Tests
{
    public class ServerClientTestBase : ServerTestBase, IDisposable
    {
        private S7Client client;
        public S7Client Client => this.client;

        public ServerClientTestBase() : base()
        {
            this.client = new S7Client("Test Plc");
            var rc = this.client.ConnectTo(this.Localhost, 0, 2);
            rc.ShouldBe(Sharp7.S7Consts.ResultOK);
        }


        public new void Dispose()
        {
            this.client.Disconnect();
            base.Dispose();
        }
    }
}