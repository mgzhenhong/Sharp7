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

        /// <summary>
        /// 等待TCP中已经有数据到达
        /// </summary>
        /// <param name="sizeNeeded">等待到达的数据量</param>
        /// <param name="timeout">超时时长(毫秒)</param>
        /// <returns></returns>
        private int WaitForData(int sizeNeeded, int timeout) {
            int sizeAvailable;
            int startTick = Environment.TickCount;
            this.LastError = 0;
            try {
                sizeAvailable = this.TCPSocket.Available;
                while (sizeAvailable < sizeNeeded) {
                    Thread.Sleep(2);
                    if (this.TCPSocket is null) {
                        this.LastError = S7Consts.errTCPDataReceive;
                        break;
                    }

                    bool timeouted = Environment.TickCount - startTick > timeout;
                    if (timeouted) {
                        this.LastError = S7Consts.errTCPReceiveTimeout;
                        break;
                    }

                    sizeAvailable = this.TCPSocket.Available;

                    // 超时后，TCP 缓冲区被清空，但网络中还有后续数据在传输，这些数据最终会到达 TCP 缓冲区。
                    // 此处如果仅读取缓冲区中的数据实现清空，会导致下次读取数据时, 与本次的剩余数据混合产生粘包问题
                    // 因此此处不再通过 Receive 清空缓冲区, 设置错误码后直接返回, 在 Receive 方法中进行关闭连接处理

                    // // If timeout we clean the buffer
                    // // 如果已超时且存在可读数据, 则通过 Receive 清空缓冲区
                    // if (timeouted && (sizeAvailable > 0)) {
                    //     try {
                    //         if (this.TCPSocket is null) {
                    //             this.LastError = S7Consts.errTCPDataReceive;
                    //             break;
                    //         }

                    //         byte[] bufferToFlush = new byte[sizeAvailable];
                    //         this.TCPSocket.Receive(bufferToFlush, 0, sizeAvailable, SocketFlags.None);
                    //     } catch {
                    //         this.LastError = S7Consts.errTCPDataReceive;
                    //     }
                    // }
                }
            } catch {
                this.LastError = S7Consts.errTCPDataReceive;
            }

            return this.LastError;
        }

        public int Receive(byte[] Buffer, int Start, int Size) {

            int BytesRead = 0;
            this.LastError = WaitForData(Size, this.ReadTimeout);
            if (this.LastError != 0) {
                Close();
                return this.LastError;
            }

            //if (this.LastError == 0) {
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
            //}
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
