namespace Sharp7.Tests
{
    public class ServerTestBase : IDisposable
    {
        protected readonly string Localhost = "127.0.0.1";
        public ServerTestBase()
        {
            this.Server = new S7Server();
            var rc = this.Server.StartTo(this.Localhost);
            rc.ShouldBe(0);
        }

        public S7Server Server { get; }

        public void Dispose()
        {
            this.Server.Stop();
        }
    }
}