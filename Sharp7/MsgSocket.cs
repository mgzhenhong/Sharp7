using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;

namespace Sharp7
{
    internal class MsgSocket
    {
        private Socket TCPSocket;
        private int LastError;

        /// <summary>
        /// The Closed event is raised when the socket is closed
        /// </summary>
        public event Action Closed;

        public MsgSocket() {
        }

        ~MsgSocket() {
            Close();
        }

        public void Close() {
            if (this.TCPSocket != null) {
                this.TCPSocket.Dispose();
                this.TCPSocket = null;
                Closed?.Invoke();
            } else {
                Debug.WriteLine("Socket is null When MsgSocket Closing");
            }
        }

        private void CreateSocket() {
            this.TCPSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) {
                NoDelay = true
            };
        }

        private void TCPPing(string Host, int Port) {
            // To Ping the PLC an Asynchronous socket is used rather then an ICMP packet.
            // This allows the use also across Internet and Firewalls (obviously the port must be opened)
            this.LastError = 0;
            Socket PingSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try {

                IAsyncResult result = PingSocket.BeginConnect(Host, Port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(this.ConnectTimeout, true);

                if (!success) {
                    this.LastError = S7Consts.errTCPConnectionFailed;
                }
            } catch {
                this.LastError = S7Consts.errTCPConnectionFailed;
            }

            PingSocket.Close();
        }

        public int Connect(string Host, int Port) {
            this.LastError = 0;
            if (!this.Connected) {
                TCPPing(Host, Port);
                if (this.LastError == 0) {
                    try {
                        CreateSocket();
                        this.TCPSocket.Connect(Host, Port);
                    } catch {
                        this.LastError = S7Consts.errTCPConnectionFailed;
                    }
                }
            }
            return this.LastError;
        }

        private int WaitForData(int Size, int Timeout) {
            bool Expired = false;
            int SizeAvail;
            int Elapsed = Environment.TickCount;
            this.LastError = 0;
            try {
                SizeAvail = this.TCPSocket.Available;
                while ((SizeAvail < Size) && (!Expired)) {
                    Thread.Sleep(2);
                    SizeAvail = this.TCPSocket.Available;
                    Expired = Environment.TickCount - Elapsed > Timeout;
                    // If timeout we clean the buffer
                    if (Expired && (SizeAvail > 0)) {
                        try {
                            byte[] Flush = new byte[SizeAvail];
                            this.TCPSocket.Receive(Flush, 0, SizeAvail, SocketFlags.None);
                        } catch {
                            this.LastError = S7Consts.errTCPDataReceive;
                        }
                    }
                }
            } catch {
                this.LastError = S7Consts.errTCPDataReceive;
            }
            if (Expired) {
                this.LastError = S7Consts.errTCPDataReceive;
            }
            return this.LastError;
        }

        public int Receive(byte[] Buffer, int Start, int Size) {

            int BytesRead = 0;
            this.LastError = WaitForData(Size, this.ReadTimeout);
            if (this.LastError == 0) {
                try {
                    BytesRead = this.TCPSocket.Receive(Buffer, Start, Size, SocketFlags.None);
                } catch {
                    this.LastError = S7Consts.errTCPDataReceive;
                }
                if (BytesRead == 0) // Connection Reset by the peer
                {
                    this.LastError = S7Consts.errTCPDataReceive;
                    Close();
                }
            }
            return this.LastError;
        }

        public int Send(byte[] Buffer, int Size) {
            this.LastError = 0;
            try {
                this.TCPSocket.Send(Buffer, Size, SocketFlags.None);
            } catch {
                this.LastError = S7Consts.errTCPDataSend;
                Close();
            }
            return this.LastError;
        }

        public bool Connected => (this.TCPSocket != null) && this.TCPSocket.Connected;

        public int ReadTimeout { get; set; } = 2000;

        public int WriteTimeout { get; set; } = 2000;

        public int ConnectTimeout { get; set; } = 1000;
    }
}
