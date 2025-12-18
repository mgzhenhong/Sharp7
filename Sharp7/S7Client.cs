using System;
using System.Runtime.InteropServices;

namespace Sharp7
{
    public class S7Client
    {
        #region [Constants and TypeDefs]

        // Block type
        public const int Block_OB = 0x38;
        public const int Block_DB = 0x41;
        public const int Block_SDB = 0x42;
        public const int Block_FC = 0x43;
        public const int Block_SFC = 0x44;
        public const int Block_FB = 0x45;
        public const int Block_SFB = 0x46;

        // Sub Block Type 
        public const byte SubBlk_OB = 0x08;
        public const byte SubBlk_DB = 0x0A;
        public const byte SubBlk_SDB = 0x0B;
        public const byte SubBlk_FC = 0x0C;
        public const byte SubBlk_SFC = 0x0D;
        public const byte SubBlk_FB = 0x0E;
        public const byte SubBlk_SFB = 0x0F;

        // Block languages
        public const byte BlockLangAWL = 0x01;
        public const byte BlockLangKOP = 0x02;
        public const byte BlockLangFUP = 0x03;
        public const byte BlockLangSCL = 0x04;
        public const byte BlockLangDB = 0x05;
        public const byte BlockLangGRAPH = 0x06;

        // Max number of vars (multiread/write)
        public static readonly int MaxVars = 20;

        // Result transport size
        private const byte TS_ResBit = 0x03;
        private const byte TS_ResByte = 0x04;
        private const byte TS_ResInt = 0x05;
        private const byte TS_ResReal = 0x07;
        private const byte TS_ResOctet = 0x09;

        private const ushort Code7Ok = 0x0000;
        private const ushort Code7AddressOutOfRange = 0x0005;
        private const ushort Code7InvalidTransportSize = 0x0006;
        private const ushort Code7WriteDataSizeMismatch = 0x0007;
        private const ushort Code7ResItemNotAvailable = 0x000A;
        private const ushort Code7ResItemNotAvailable1 = 0xD209;
        private const ushort Code7InvalidValue = 0xDC01;
        private const ushort Code7NeedPassword = 0xD241;
        private const ushort Code7InvalidPassword = 0xD602;
        private const ushort Code7NoPasswordToClear = 0xD604;
        private const ushort Code7NoPasswordToSet = 0xD605;
        private const ushort Code7FunNotAvailable = 0x8104;
        private const ushort Code7DataOverPDU = 0x8500;

        // Client Connection Type
        public static readonly UInt16 CONNTYPE_PG = 0x01;  // Connect to the PLC as a PG
        public static readonly UInt16 CONNTYPE_OP = 0x02;  // Connect to the PLC as an OP
        public static readonly UInt16 CONNTYPE_BASIC = 0x03;  // Basic connection 

        public int _LastError = 0;

        public struct S7DataItem
        {
            public int Area;
            public int WordLen;
            public int Result;
            public int DBNumber;
            public int Start;
            public int Amount;
            public IntPtr pData;
        }

        // Order Code + Version
        public struct S7OrderCode
        {
            public string Code; // such as "6ES7 151-8AB01-0AB0"
            public byte V1;     // Version 1st digit
            public byte V2;     // Version 2nd digit
            public byte V3;     // Version 3th digit
        };

        // CPU Info
        public struct S7CpuInfo
        {
            public string ModuleTypeName;
            public string SerialNumber;
            public string ASName;
            public string Copyright;
            public string ModuleName;
        }

        public struct S7CpInfo
        {
            public int MaxPduLength;
            public int MaxConnections;
            public int MaxMpiRate;
            public int MaxBusRate;
        };

        // Block List
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct S7BlocksList
        {
            public Int32 OBCount;
            public Int32 FBCount;
            public Int32 FCCount;
            public Int32 SFBCount;
            public Int32 SFCCount;
            public Int32 DBCount;
            public Int32 SDBCount;
        };

        // Managed Block Info
        public struct S7BlockInfo
        {
            public int BlkType;
            public int BlkNumber;
            public int BlkLang;
            public int BlkFlags;
            public int MC7Size;  // The real size in bytes
            public int LoadSize;
            public int LocalData;
            public int SBBLength;
            public int CheckSum;
            public int Version;
            // Chars info
            public string CodeDate;
            public string IntfDate;
            public string Author;
            public string Family;
            public string Header;
        };

        // See §33.1 of "System Software for S7-300/400 System and Standard Functions"
        // and see SFC51 description too
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SZL_HEADER
        {
            public UInt16 LENTHDR;
            public UInt16 N_DR;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct S7SZL
        {
            public SZL_HEADER Header;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] Data;
        };

        // SZL List of available SZL IDs : same as SZL but List items are big-endian adjusted
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct S7SZLList
        {
            public SZL_HEADER Header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x2000 - 2)]
            public UInt16[] Data;
        };

        // S7 Protection
        // See §33.19 of "System Software for S7-300/400 System and Standard Functions"
        public struct S7Protection
        {
            public ushort sch_schal;
            public ushort sch_par;
            public ushort sch_rel;
            public ushort bart_sch;
            public ushort anl_sch;
        };

        #endregion

        #region [S7 Telegrams]

        // ISO Connection Request telegram (contains also ISO Header and COTP Header)
        private readonly byte[] ISO_CR = {
			// TPKT (RFC1006 Header)
			0x03, // RFC 1006 ID (3) 
			0x00, // Reserved, always 0
			0x00, // High part of packet lenght (entire frame, payload and TPDU included)
			0x16, // Low part of packet lenght (entire frame, payload and TPDU included)
			// COTP (ISO 8073 Header)
			0x11, // PDU Size Length
			0xE0, // CR - Connection Request ID
			0x00, // Dst Reference HI
			0x00, // Dst Reference LO
			0x00, // Src Reference HI
			0x01, // Src Reference LO
			0x00, // Class + Options Flags
			0xC0, // PDU Max Length ID
			0x01, // PDU Max Length HI
			0x0A, // PDU Max Length LO
			0xC1, // Src TSAP Identifier
			0x02, // Src TSAP Length (2 bytes)
			0x01, // Src TSAP HI (will be overwritten)
			0x00, // Src TSAP LO (will be overwritten)
			0xC2, // Dst TSAP Identifier
			0x02, // Dst TSAP Length (2 bytes)
			0x01, // Dst TSAP HI (will be overwritten)
			0x02  // Dst TSAP LO (will be overwritten)
		};

        // TPKT + ISO COTP Header (Connection Oriented Transport Protocol)
        private readonly byte[] TPKT_ISO = { // 7 bytes
			0x03,0x00,
            0x00,0x1f,      // Telegram Length (Data Size + 31 or 35)
			0x02,0xf0,0x80  // COTP (see above for info)
		};

        // S7 PDU Negotiation Telegram (contains also ISO Header and COTP Header)
        private readonly byte[] S7_PN = {
            0x03, 0x00, 0x00, 0x19,
            0x02, 0xf0, 0x80, // TPKT + COTP (see above for info)
			0x32, 0x01, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x08,
            0x00, 0x00, 0xf0, 0x00,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x1e        // PDU Length Requested = HI-LO Here Default 480 bytes
		};

        // S7 Read/Write Request Header (contains also ISO Header and COTP Header)
        private readonly byte[] S7_RW = { // 31-35 bytes
			0x03,0x00,
            0x00,0x1f,       // Telegram Length (Data Size + 31 or 35)
			0x02,0xf0, 0x80, // COTP (see above for info)
			0x32,            // S7 Protocol ID 
			0x01,            // Job Type
			0x00,0x00,       // Redundancy identification
			0x05,0x00,       // PDU Reference
			0x00,0x0e,       // Parameters Length
			0x00,0x00,       // Data Length = Size(bytes) + 4      
			0x04,            // Function 4 Read Var, 5 Write Var  
			0x01,            // Items count
			0x12,            // Var spec.
			0x0a,            // Length of remaining bytes
			0x10,            // Syntax ID 
			(byte)S7WordLength.Byte,  // Transport Size idx=22                       
			0x00,0x00,       // Num Elements                          
			0x00,0x00,       // DB Number (if any, else 0)            
			0x84,            // Area Type                            
			0x00,0x00,0x00,  // Area Offset                     
			// WR area
			0x00,            // Reserved 
			0x04,            // Transport size
			0x00,0x00,       // Data Length * 8 (if not bit or timer or counter) 
		};
        private static readonly int Size_RD = 31; // Header Size when Reading 
        private static readonly int Size_WR = 35; // Header Size when Writing

        // S7 Variable MultiRead Header
        private readonly byte[] S7_MRD_HEADER = {
            0x03,0x00,
            0x00,0x1f,       // Telegram Length 
			0x02,0xf0, 0x80, // COTP (see above for info)
			0x32,            // S7 Protocol ID 
			0x01,            // Job Type
			0x00,0x00,       // Redundancy identification
			0x05,0x00,       // PDU Reference
			0x00,0x0e,       // Parameters Length
			0x00,0x00,       // Data Length = Size(bytes) + 4      
			0x04,            // Function 4 Read Var, 5 Write Var  
			0x01             // Items count (idx 18)
		};

        // S7 Variable MultiRead Item
        private readonly byte[] S7_MRD_ITEM = {
            0x12,            // Var spec.
			0x0a,            // Length of remaining bytes
			0x10,            // Syntax ID 
			(byte)S7WordLength.Byte,  // Transport Size idx=3                   
			0x00,0x00,       // Num Elements                          
			0x00,0x00,       // DB Number (if any, else 0)            
			0x84,            // Area Type                            
			0x00,0x00,0x00   // Area Offset                     
		};

        // S7 Variable MultiWrite Header
        private readonly byte[] S7_MWR_HEADER = {
            0x03,0x00,
            0x00,0x1f,       // Telegram Length 
			0x02,0xf0, 0x80, // COTP (see above for info)
			0x32,            // S7 Protocol ID 
			0x01,            // Job Type
			0x00,0x00,       // Redundancy identification
			0x05,0x00,       // PDU Reference
			0x00,0x0e,       // Parameters Length (idx 13)
			0x00,0x00,       // Data Length = Size(bytes) + 4 (idx 15)     
			0x05,            // Function 5 Write Var  
			0x01             // Items count (idx 18)
		};

        // S7 Variable MultiWrite Item (Param)
        private readonly byte[] S7_MWR_PARAM = {
            0x12,            // Var spec.
			0x0a,            // Length of remaining bytes
			0x10,            // Syntax ID 
			(byte)S7WordLength.Byte,  // Transport Size idx=3                      
			0x00,0x00,       // Num Elements                          
			0x00,0x00,       // DB Number (if any, else 0)            
			0x84,            // Area Type                            
			0x00,0x00,0x00,  // Area Offset                     
		};

        // SZL First telegram request   
        private readonly byte[] S7_SZL_FIRST = {
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00,
            0x05, 0x00, // Sequence out
			0x00, 0x08, 0x00,
            0x08, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x44, 0x01,
            0x00, 0xff, 0x09, 0x00,
            0x04,
            0x00, 0x00, // ID (29)
			0x00, 0x00  // Index (31)
		};

        // SZL Next telegram request 
        private readonly byte[] S7_SZL_NEXT = {
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x0c, 0x00,
            0x04, 0x00, 0x01, 0x12,
            0x08, 0x12, 0x44, 0x01,
            0x01, // Sequence
			0x00, 0x00, 0x00, 0x00,
            0x0a, 0x00, 0x00, 0x00
        };

        // Get Date/Time request
        private readonly byte[] S7_GET_DT = {
            0x03, 0x00, 0x00, 0x1d,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x38,
            0x00, 0x00, 0x08, 0x00,
            0x04, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x47, 0x01,
            0x00, 0x0a, 0x00, 0x00,
            0x00
        };

        // Set Date/Time command
        private readonly byte[] S7_SET_DT = {
            0x03, 0x00, 0x00, 0x27,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x89,
            0x03, 0x00, 0x08, 0x00,
            0x0e, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x47, 0x02,
            0x00, 0xff, 0x09, 0x00,
            0x0a, 0x00,
            0x19, // Hi part of Year (idx=30)
			0x13, // Lo part of Year
			0x12, // Month
			0x06, // Day
			0x17, // Hour
			0x37, // Min
			0x13, // Sec
			0x00, 0x01 // ms + Day of week   
		};

        // S7 Set Session Password 
        private readonly byte[] S7_SET_PWD = {
            0x03, 0x00, 0x00, 0x25,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x27,
            0x00, 0x00, 0x08, 0x00,
            0x0c, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x45, 0x01,
            0x00, 0xff, 0x09, 0x00,
            0x08, 
			// 8 Char Encoded Password
			0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        // S7 Clear Session Password 
        private readonly byte[] S7_CLR_PWD = {
            0x03, 0x00, 0x00, 0x1d,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x29,
            0x00, 0x00, 0x08, 0x00,
            0x04, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x45, 0x02,
            0x00, 0x0a, 0x00, 0x00,
            0x00
        };

        // S7 STOP request
        private readonly byte[] S7_STOP = {
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xf0, 0x80, 0x32,
            0x01, 0x00, 0x00, 0x0e,
            0x00, 0x00, 0x10, 0x00,
            0x00, 0x29, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x09,
            0x50, 0x5f, 0x50, 0x52,
            0x4f, 0x47, 0x52, 0x41,
            0x4d
        };

        // S7 HOT Start request
        private readonly byte[] S7_HOT_START = {
            0x03, 0x00, 0x00, 0x25,
            0x02, 0xf0, 0x80, 0x32,
            0x01, 0x00, 0x00, 0x0c,
            0x00, 0x00, 0x14, 0x00,
            0x00, 0x28, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xfd, 0x00, 0x00, 0x09,
            0x50, 0x5f, 0x50, 0x52,
            0x4f, 0x47, 0x52, 0x41,
            0x4d
        };

        // S7 COLD Start request
        private readonly byte[] S7_COLD_START = {
            0x03, 0x00, 0x00, 0x27,
            0x02, 0xf0, 0x80, 0x32,
            0x01, 0x00, 0x00, 0x0f,
            0x00, 0x00, 0x16, 0x00,
            0x00, 0x28, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xfd, 0x00, 0x02, 0x43,
            0x20, 0x09, 0x50, 0x5f,
            0x50, 0x52, 0x4f, 0x47,
            0x52, 0x41, 0x4d
        };
        private const byte pduStart = 0x28;   // CPU start
        private const byte pduStop = 0x29;   // CPU stop
        private const byte pduAlreadyStarted = 0x02;   // CPU already in run mode
        private const byte pduAlreadyStopped = 0x07;   // CPU already in stop mode

        // S7 Get PLC Status 
        private readonly byte[] S7_GET_STAT = {
            0x03, 0x00, 0x00, 0x21,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x2c,
            0x00, 0x00, 0x08, 0x00,
            0x08, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x44, 0x01,
            0x00, 0xff, 0x09, 0x00,
            0x04, 0x04, 0x24, 0x00,
            0x00
        };

        // S7 Get Block Info Request Header (contains also ISO Header and COTP Header)
        private readonly byte[] S7_BI = {
            0x03, 0x00, 0x00, 0x25,
            0x02, 0xf0, 0x80, 0x32,
            0x07, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x08, 0x00,
            0x0c, 0x00, 0x01, 0x12,
            0x04, 0x11, 0x43, 0x03,
            0x00, 0xff, 0x09, 0x00,
            0x08, 0x30,
            0x41, // Block Type
			0x30, 0x30, 0x30, 0x30, 0x30, // ASCII Block Number
			0x41
        };

        #endregion

        #region [Internals]

        // Defaults
        private static readonly int ISOTCP = 102; // ISOTCP Port
        private static readonly int MinPduSize = 16;
        private static readonly int MinPduSizeToRequest = 240;
        private static readonly int MaxPduSizeToRequest = 960;
        private static readonly int DefaultTimeout = 2000;
        private static readonly int IsoHSize = 7; // TPKT+COTP Header Size

        // Properties
        private int _PduSizeRequested = 480;

        // Privates
        private byte LocalTSAP_HI;
        private byte LocalTSAP_LO;
        private byte RemoteTSAP_HI;
        private byte RemoteTSAP_LO;
        private byte LastPDUType;
        private ushort ConnType = CONNTYPE_PG;
        private readonly byte[] PDU = new byte[2048];
        private MsgSocket Socket = null;

        // Events

        /// <summary>
        /// The SocketClosed event is raised when the internal socket is closed
        /// </summary>
        public event Action SocketClosed;

        /// <summary>
        /// The SocketConnectFailed event is raised when the internal socket fails to connect
        /// </summary>
        public event Action SocketConnectFailed;

        private void CreateSocket() {
            this.Socket = new MsgSocket {
                ConnectTimeout = DefaultTimeout,
                ReadTimeout = DefaultTimeout,
                WriteTimeout = DefaultTimeout
            };
            this.Socket.Closed += () => {
                SocketClosed?.Invoke();
            };
        }

        private int TCPConnect() {
            if (this._LastError == 0) {
                try {
                    this._LastError = this.Socket.Connect(this.PLCIpAddress, this.PLCPort);
                } catch {
                    this._LastError = S7Consts.errTCPConnectionFailed;
                }

                if (this._LastError != 0) {
                    SocketConnectFailed?.Invoke();
                }
            }
            return this._LastError;
        }

        private void RecvPacket(byte[] Buffer, int Start, int Size) {
            if (this.Connected) {
                this._LastError = this.Socket.Receive(Buffer, Start, Size);
            } else {
                this._LastError = S7Consts.errTCPNotConnected;
            }
        }

        private void SendPacket(byte[] Buffer, int Len) {
            if (this.Connected) {
                this._LastError = this.Socket.Send(Buffer, Len);
            } else {
                this._LastError = S7Consts.errTCPNotConnected;
            }
        }

        private void SendPacket(byte[] Buffer) {
            SendPacket(Buffer, Buffer.Length);
        }

        private int RecvIsoPacket() {
            Boolean Done = false;
            int Size = 0;
            while ((this._LastError == 0) && !Done) {
                // Get TPKT (4 bytes)
                RecvPacket(this.PDU, 0, 4);
                if (this._LastError == 0) {
                    Size = this.PDU.GetWordAt(2);
                    // Check 0 bytes Data Packet (only TPKT+COTP = 7 bytes)
                    if (Size == IsoHSize) {
                        RecvPacket(this.PDU, 4, 3); // Skip remaining 3 bytes and Done is still false
                    } else {
                        if ((Size > this._PduSizeRequested + IsoHSize) || (Size < MinPduSize)) {
                            this._LastError = S7Consts.errIsoInvalidPDU;
                        } else {
                            Done = true; // a valid Length !=7 && >16 && <247
                        }
                    }
                }
            }
            if (this._LastError == 0) {
                RecvPacket(this.PDU, 4, 3); // Skip remaining 3 COTP bytes
                this.LastPDUType = this.PDU[5];   // Stores PDU Type, we need it 
                                                  // Receives the S7 Payload          
                RecvPacket(this.PDU, 7, Size - IsoHSize);
            }

            if (this._LastError == 0) {
                return Size;
            }

            return 0;
        }

        private int ISOConnect() {
            int Size;
            this.ISO_CR[16] = this.LocalTSAP_HI;
            this.ISO_CR[17] = this.LocalTSAP_LO;
            this.ISO_CR[20] = this.RemoteTSAP_HI;
            this.ISO_CR[21] = this.RemoteTSAP_LO;

            // Sends the connection request telegram      
            SendPacket(this.ISO_CR);
            if (this._LastError == 0) {
                // Gets the reply (if any)
                Size = RecvIsoPacket();
                if (this._LastError == 0) {
                    if (Size == 22) {
                        if (this.LastPDUType != (byte)0xD0) // 0xD0 = CC Connection confirm
{
                            this._LastError = S7Consts.errIsoConnect;
                        }
                    } else {
                        this._LastError = S7Consts.errIsoInvalidPDU;
                    }
                }
            }
            return this._LastError;
        }

        private int NegotiatePduLength() {
            int Length;
            // Set PDU Size Requested
            this.S7_PN.SetWordAt(23, (ushort)this._PduSizeRequested);
            // Sends the connection request telegram
            SendPacket(this.S7_PN);
            if (this._LastError == 0) {
                Length = RecvIsoPacket();
                if (this._LastError == 0) {
                    // check S7 Error
                    if ((Length == 27) && (this.PDU[17] == 0) && (this.PDU[18] == 0))  // 20 = size of Negotiate Answer
                    {
                        // Get PDU Size Negotiated
                        this.PduSizeNegotiated = this.PDU.GetWordAt(25);
                        if (this.PduSizeNegotiated <= 0) {
                            this._LastError = S7Consts.errCliNegotiatingPDU;
                        }
                    } else {
                        this._LastError = S7Consts.errCliNegotiatingPDU;
                    }
                }
            }
            return this._LastError;
        }

        private int CpuError(ushort Error) {
            return Error switch {
                0 => 0,
                Code7AddressOutOfRange => S7Consts.errCliAddressOutOfRange,
                Code7InvalidTransportSize => S7Consts.errCliInvalidTransportSize,
                Code7WriteDataSizeMismatch => S7Consts.errCliWriteDataSizeMismatch,
                Code7ResItemNotAvailable or Code7ResItemNotAvailable1 => S7Consts.errCliItemNotAvailable,
                Code7DataOverPDU => S7Consts.errCliSizeOverPDU,
                Code7InvalidValue => S7Consts.errCliInvalidValue,
                Code7FunNotAvailable => S7Consts.errCliFunNotAvailable,
                Code7NeedPassword => S7Consts.errCliNeedPassword,
                Code7InvalidPassword => S7Consts.errCliInvalidPassword,
                Code7NoPasswordToSet or Code7NoPasswordToClear => S7Consts.errCliNoPasswordToSetOrClear,
                _ => S7Consts.errCliFunctionRefused,
            };
            ;
        }

        #endregion

        #region [Class Control]

        public S7Client(string name) : this() {
            this.Name = name;
        }

        public string Name { get; }

        public S7Client() {
            CreateSocket();
        }

        ~S7Client() {
            Disconnect();
        }

        public override string ToString() {
            return $"PLC {this.Name ?? string.Empty}@{this.PLCIpAddress ?? "0.0.0.0"}";
        }

        public int Connect() {
            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;
            if (!this.Connected) {
                TCPConnect(); // First stage : TCP Connection
                if (this._LastError == 0) {
                    ISOConnect(); // Second stage : ISOTCP (ISO 8073) Connection
                    if (this._LastError == 0) {
                        this._LastError = NegotiatePduLength(); // Third stage : S7 PDU negotiation
                    }
                }
            }
            if (this._LastError != 0) {
                Disconnect();
            } else {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int ConnectTo(string Address, int Rack, int Slot) {
            UInt16 RemoteTSAP = (UInt16)((this.ConnType << 8) + (Rack * 0x20) + Slot);
            SetConnectionParams(Address, 0x0100, RemoteTSAP);
            return Connect();
        }

        public int SetConnectionParams(string Address, ushort LocalTSAP, ushort RemoteTSAP) {
            int LocTSAP = LocalTSAP & 0x0000FFFF;
            int RemTSAP = RemoteTSAP & 0x0000FFFF;
            this.PLCIpAddress = Address;
            this.LocalTSAP_HI = (byte)(LocTSAP >> 8);
            this.LocalTSAP_LO = (byte)(LocTSAP & 0x00FF);
            this.RemoteTSAP_HI = (byte)(RemTSAP >> 8);
            this.RemoteTSAP_LO = (byte)(RemTSAP & 0x00FF);
            return 0;
        }

        public int SetConnectionType(ushort ConnectionType) {
            this.ConnType = ConnectionType;
            return 0;
        }

        public int Disconnect() {
            this.Socket?.Close();
            return 0;
        }

        public int GetParam(Int32 ParamNumber, ref int Value) {
            int Result = 0;
            switch (ParamNumber) {
                case S7Consts.p_u16_RemotePort: {
                    Value = this.PLCPort;
                    break;
                }
                case S7Consts.p_i32_PingTimeout: {
                    Value = this.ConnTimeout;
                    break;
                }
                case S7Consts.p_i32_SendTimeout: {
                    Value = this.SendTimeout;
                    break;
                }
                case S7Consts.p_i32_RecvTimeout: {
                    Value = this.RecvTimeout;
                    break;
                }
                case S7Consts.p_i32_PDURequest: {
                    Value = this.PduSizeRequested;
                    break;
                }
                default: {
                    Result = S7Consts.errCliInvalidParamNumber;
                    break;
                }
            }
            return Result;
        }

        // Set Properties for compatibility with Snap7.net.cs
        public int SetParam(Int32 ParamNumber, ref int Value) {
            int Result = 0;
            switch (ParamNumber) {
                case S7Consts.p_u16_RemotePort: {
                    this.PLCPort = Value;
                    break;
                }
                case S7Consts.p_i32_PingTimeout: {
                    this.ConnTimeout = Value;
                    break;
                }
                case S7Consts.p_i32_SendTimeout: {
                    this.SendTimeout = Value;
                    break;
                }
                case S7Consts.p_i32_RecvTimeout: {
                    this.RecvTimeout = Value;
                    break;
                }
                case S7Consts.p_i32_PDURequest: {
                    this.PduSizeRequested = Value;
                    break;
                }
                default: {
                    Result = S7Consts.errCliInvalidParamNumber;
                    break;
                }
            }
            return Result;
        }

        public delegate void S7CliCompletion(IntPtr usrPtr, int opCode, int opResult);
        public int SetAsCallBack(S7CliCompletion Completion, IntPtr usrPtr) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        #endregion

        #region [Data I/O main functions]

        public int ReadArea(S7Area Area, int DBNumber, int Start, int Amount, S7WordLength WordLen, byte[] Buffer) {
            return ReadArea((int)Area, DBNumber, Start, Amount, (int)WordLen, Buffer);
        }

        public int ReadArea(S7Area Area, int DBNumber, int Start, int Amount, S7WordLength WordLen, byte[] Buffer, ref int BytesRead) {
            return ReadArea((int)Area, DBNumber, Start, Amount, (int)WordLen, Buffer, ref BytesRead);
        }
        public int ReadArea(int Area, int DBNumber, int Start, int Amount, int WordLen, byte[] Buffer) {
            int BytesRead = 0;
            return ReadArea(Area, DBNumber, Start, Amount, WordLen, Buffer, ref BytesRead);
        }

        public int ReadArea(int Area, int DBNumber, int Start, int Amount, int WordLen, byte[] Buffer, ref int BytesRead) {
            int Address;
            int NumElements;
            int MaxElements;
            int TotElements;
            int SizeRequested;
            int Length;
            int Offset = 0;
            int WordSize = 1;

            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;
            // Some adjustment
            if (Area == (int)S7Area.CT) {
                WordLen = (int)S7WordLength.Counter;
            }

            if (Area == (int)S7Area.TM) {
                WordLen = (int)S7WordLength.Timer;
            }

            // Calc Word size          
            WordSize = WordLen.DataSizeByte();
            if (WordSize == 0) {
                return S7Consts.errCliInvalidWordLen;
            }

            if (WordLen == (int)S7WordLength.Bit) {
                Amount = 1;  // Only 1 bit can be transferred at time
            } else {
                if (WordLen is not ((int)S7WordLength.Counter) and not ((int)S7WordLength.Timer)) {
                    Amount *= WordSize;
                    WordSize = 1;
                    WordLen = (int)S7WordLength.Byte;
                }
            }

            MaxElements = (this.PduSizeNegotiated - 18) / WordSize; // 18 = Reply telegram header
            TotElements = Amount;

            while ((TotElements > 0) && (this._LastError == 0)) {
                NumElements = TotElements;
                if (NumElements > MaxElements) {
                    NumElements = MaxElements;
                }

                SizeRequested = NumElements * WordSize;

                // Setup the telegram
                Array.Copy(this.S7_RW, 0, this.PDU, 0, Size_RD);
                // Set DB Number
                this.PDU[27] = (byte)Area;
                // Set Area
                if (Area == (int)S7Area.DB) {
                    this.PDU.SetWordAt(25, (ushort)DBNumber);
                }

                // Adjusts Start and word length
                if (WordLen is ((int)S7WordLength.Bit) or ((int)S7WordLength.Counter) or ((int)S7WordLength.Timer)) {
                    Address = Start;
                    this.PDU[22] = (byte)WordLen;
                } else {
                    Address = Start << 3;
                }

                // Num elements
                this.PDU.SetWordAt(23, (ushort)NumElements);

                // Address into the PLC (only 3 bytes)           
                this.PDU[30] = (byte)(Address & 0x0FF);
                Address >>= 8;
                this.PDU[29] = (byte)(Address & 0x0FF);
                Address >>= 8;
                this.PDU[28] = (byte)(Address & 0x0FF);

                SendPacket(this.PDU, Size_RD);
                if (this._LastError == 0) {
                    Length = RecvIsoPacket();
                    if (this._LastError == 0) {
                        if (Length < 25) {
                            this._LastError = S7Consts.errIsoInvalidDataSize;
                        } else {
                            if (this.PDU[21] != 0xFF) {
                                this._LastError = CpuError(this.PDU[21]);
                            } else {
                                Array.Copy(this.PDU, 25, Buffer, Offset, SizeRequested);
                                Offset += SizeRequested;
                            }
                        }
                    }
                }
                TotElements -= NumElements;
                Start += NumElements * WordSize;
            }

            if (this._LastError == 0) {
                BytesRead = Offset;
                this.ExecutionTime = Environment.TickCount - Elapsed;
            } else {
                BytesRead = 0;
            }

            return this._LastError;
        }

        public int WriteArea(S7Area Area, int DBNumber, int Start, int Amount, S7WordLength WordLen, byte[] Buffer) {
            int BytesWritten = 0;
            return WriteArea((int)Area, DBNumber, Start, Amount, (int)WordLen, Buffer, ref BytesWritten);
        }

        public int WriteArea(S7Area Area, int DBNumber, int Start, int Amount, S7WordLength WordLen, byte[] Buffer, ref int BytesWritten) {
            return WriteArea((int)Area, DBNumber, Start, Amount, (int)WordLen, Buffer, ref BytesWritten);
        }
        public int WriteArea(int Area, int DBNumber, int Start, int Amount, int WordLen, byte[] Buffer) {
            int BytesWritten = 0;
            return WriteArea(Area, DBNumber, Start, Amount, WordLen, Buffer, ref BytesWritten);
        }

        public int WriteArea(int Area, int DBNumber, int Start, int Amount, int WordLen, byte[] Buffer, ref int BytesWritten) {
            int Address;
            int NumElements;
            int MaxElements;
            int TotElements;
            int DataSize;
            int IsoSize;
            int Length;
            int Offset = 0;
            int WordSize = 1;

            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;
            // Some adjustment
            if (Area == (int)S7Area.CT) {
                WordLen = (int)S7WordLength.Counter;
            }

            if (Area == (int)S7Area.TM) {
                WordLen = (int)S7WordLength.Timer;
            }

            // Calc Word size
            WordSize = WordLen.DataSizeByte();
            if (WordSize == 0) {
                return S7Consts.errCliInvalidWordLen;
            }

            if (WordLen == (int)S7WordLength.Bit) // Only 1 bit can be transferred at time
{
                Amount = 1;
            } else {
                if (WordLen is not ((int)S7WordLength.Counter) and not ((int)S7WordLength.Timer)) {
                    Amount *= WordSize;
                    WordSize = 1;
                    WordLen = (int)S7WordLength.Byte;
                }
            }

            MaxElements = (this.PduSizeNegotiated - 35) / WordSize; // 35 = Reply telegram header
            TotElements = Amount;

            while ((TotElements > 0) && (this._LastError == 0)) {
                NumElements = TotElements;
                if (NumElements > MaxElements) {
                    NumElements = MaxElements;
                }

                DataSize = NumElements * WordSize;
                IsoSize = Size_WR + DataSize;

                // Setup the telegram
                Array.Copy(this.S7_RW, 0, this.PDU, 0, Size_WR);
                // Whole telegram Size
                this.PDU.SetWordAt(2, (ushort)IsoSize);
                // Data Length
                Length = DataSize + 4;
                this.PDU.SetWordAt(15, (ushort)Length);
                // Function
                this.PDU[17] = (byte)0x05;
                // Set DB Number
                this.PDU[27] = (byte)Area;
                if (Area == (int)S7Area.DB) {
                    this.PDU.SetWordAt(25, (ushort)DBNumber);
                }


                // Adjusts Start and word length
                if (WordLen is ((int)S7WordLength.Bit) or ((int)S7WordLength.Counter) or ((int)S7WordLength.Timer)) {
                    Address = Start;
                    Length = DataSize;
                    this.PDU[22] = (byte)WordLen;
                } else {
                    Address = Start << 3;
                    Length = DataSize << 3;
                }

                // Num elements
                this.PDU.SetWordAt(23, (ushort)NumElements);
                // Address into the PLC
                this.PDU[30] = (byte)(Address & 0x0FF);
                Address >>= 8;
                this.PDU[29] = (byte)(Address & 0x0FF);
                Address >>= 8;
                this.PDU[28] = (byte)(Address & 0x0FF);

                // Transport Size
                this.PDU[32] = WordLen switch {
                    (int)S7WordLength.Bit => TS_ResBit,
                    (int)S7WordLength.Counter or (int)S7WordLength.Timer => TS_ResOctet,
                    _ => TS_ResByte,// byte/word/dword etc.
                };
                ;
                // Length
                this.PDU.SetWordAt(33, (ushort)Length);

                // Copies the Data
                Array.Copy(Buffer, Offset, this.PDU, 35, DataSize);

                SendPacket(this.PDU, IsoSize);
                if (this._LastError == 0) {
                    Length = RecvIsoPacket();
                    if (this._LastError == 0) {
                        if (Length == 22) {
                            if (this.PDU[21] != (byte)0xFF) {
                                this._LastError = CpuError(this.PDU[21]);
                            }
                        } else {
                            this._LastError = S7Consts.errIsoInvalidPDU;
                        }
                    }
                }
                Offset += DataSize;
                TotElements -= NumElements;
                Start += NumElements * WordSize;
            }

            if (this._LastError == 0) {
                BytesWritten = Offset;
                this.ExecutionTime = Environment.TickCount - Elapsed;
            } else {
                BytesWritten = 0;
            }

            return this._LastError;
        }

        public int ReadMultiVars(S7DataItem[] Items, int ItemsCount) {
            int Offset;
            int Length;
            int ItemSize;
            byte[] S7Item = new byte[12];
            byte[] S7ItemRead = new byte[1024];

            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;

            // Checks items
            if (ItemsCount > MaxVars) {
                return S7Consts.errCliTooManyItems;
            }

            // Fills Header
            Array.Copy(this.S7_MRD_HEADER, 0, this.PDU, 0, this.S7_MRD_HEADER.Length);
            this.PDU.SetWordAt(13, (ushort)((ItemsCount * S7Item.Length) + 2));
            this.PDU[18] = (byte)ItemsCount;
            // Fills the Items
            Offset = 19;
            for (int c = 0; c < ItemsCount; c++) {
                Array.Copy(this.S7_MRD_ITEM, S7Item, S7Item.Length);
                S7Item[3] = (byte)Items[c].WordLen;
                S7Item.SetWordAt(4, (ushort)Items[c].Amount);
                if (Items[c].Area == (int)S7Area.DB) {
                    S7Item.SetWordAt(6, (ushort)Items[c].DBNumber);
                }

                S7Item[8] = (byte)Items[c].Area;

                // Address into the PLC
                int Address = Items[c].Start;
                S7Item[11] = (byte)(Address & 0x0FF);
                Address >>= 8;
                S7Item[10] = (byte)(Address & 0x0FF);
                Address >>= 8;
                S7Item[09] = (byte)(Address & 0x0FF);

                Array.Copy(S7Item, 0, this.PDU, Offset, S7Item.Length);
                Offset += S7Item.Length;
            }

            if (Offset > this.PduSizeNegotiated) {
                return S7Consts.errCliSizeOverPDU;
            }

            this.PDU.SetWordAt(2, (ushort)Offset); // Whole size
            SendPacket(this.PDU, Offset);

            if (this._LastError != 0) {
                return this._LastError;
            }
            // Get Answer
            Length = RecvIsoPacket();
            if (this._LastError != 0) {
                return this._LastError;
            }
            // Check ISO Length
            if (Length < 22) {
                this._LastError = S7Consts.errIsoInvalidPDU; // PDU too Small
                return this._LastError;
            }
            // Check Global Operation Result
            this._LastError = CpuError(this.PDU.GetWordAt(17));
            if (this._LastError != 0) {
                return this._LastError;
            }
            // Get true ItemsCount
            int ItemsRead = this.PDU.GetByteAt(20);
            if ((ItemsRead != ItemsCount) || (ItemsRead > MaxVars)) {
                this._LastError = S7Consts.errCliInvalidPlcAnswer;
                return this._LastError;
            }
            // Get Data
            Offset = 21;
            for (int c = 0; c < ItemsCount; c++) {
                // Get the Item
                Array.Copy(this.PDU, Offset, S7ItemRead, 0, Length - Offset);
                if (S7ItemRead[0] == 0xff) {
                    ItemSize = (int)S7ItemRead.GetWordAt(2);
                    if (S7ItemRead[1] is not TS_ResOctet and not TS_ResReal and not TS_ResBit) {
                        ItemSize >>= 3;
                    }

                    Marshal.Copy(S7ItemRead, 4, Items[c].pData, ItemSize);
                    Items[c].Result = 0;
                    if (ItemSize % 2 != 0) {
                        ItemSize++; // Odd size are rounded
                    }

                    Offset = Offset + 4 + ItemSize;
                } else {
                    Items[c].Result = CpuError(S7ItemRead[0]);
                    Offset += 4; // Skip the Item header                           
                }
            }
            this.ExecutionTime = Environment.TickCount - Elapsed;
            return this._LastError;
        }

        public int WriteMultiVars(S7DataItem[] Items, int ItemsCount) {
            int Offset;
            int ParLength;
            int DataLength;
            int ItemDataSize;
            byte[] S7ParItem = new byte[this.S7_MWR_PARAM.Length];
            byte[] S7DataItem = new byte[1024];

            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;

            // Checks items
            if (ItemsCount > MaxVars) {
                return S7Consts.errCliTooManyItems;
            }
            // Fills Header
            Array.Copy(this.S7_MWR_HEADER, 0, this.PDU, 0, this.S7_MWR_HEADER.Length);
            ParLength = (ItemsCount * this.S7_MWR_PARAM.Length) + 2;
            this.PDU.SetWordAt(13, (ushort)ParLength);
            this.PDU[18] = (byte)ItemsCount;
            // Fills Params
            Offset = this.S7_MWR_HEADER.Length;
            for (int c = 0; c < ItemsCount; c++) {
                Array.Copy(this.S7_MWR_PARAM, 0, S7ParItem, 0, this.S7_MWR_PARAM.Length);
                S7ParItem[3] = (byte)Items[c].WordLen;
                S7ParItem[8] = (byte)Items[c].Area;
                S7ParItem.SetWordAt(4, (ushort)Items[c].Amount);
                S7ParItem.SetWordAt(6, (ushort)Items[c].DBNumber);
                // Address into the PLC
                int Address = Items[c].Start;
                S7ParItem[11] = (byte)(Address & 0x0FF);
                Address >>= 8;
                S7ParItem[10] = (byte)(Address & 0x0FF);
                Address >>= 8;
                S7ParItem[09] = (byte)(Address & 0x0FF);
                Array.Copy(S7ParItem, 0, this.PDU, Offset, S7ParItem.Length);
                Offset += this.S7_MWR_PARAM.Length;
            }
            // Fills Data
            DataLength = 0;
            for (int c = 0; c < ItemsCount; c++) {
                S7DataItem[0] = 0x00;
                S7DataItem[1] = Items[c].WordLen switch {
                    (int)S7WordLength.Bit => TS_ResBit,
                    (int)S7WordLength.Counter or (int)S7WordLength.Timer => TS_ResOctet,
                    _ => TS_ResByte,// byte/word/dword etc.
                };
                ;
                if (Items[c].WordLen is ((int)S7WordLength.Timer) or ((int)S7WordLength.Counter)) {
                    ItemDataSize = Items[c].Amount * 2;
                } else {
                    ItemDataSize = Items[c].Amount;
                }

                if (S7DataItem[1] is not TS_ResOctet and not TS_ResBit) {
                    S7DataItem.SetWordAt(2, (ushort)(ItemDataSize * 8));
                } else {
                    S7DataItem.SetWordAt(2, (ushort)ItemDataSize);
                }

                Marshal.Copy(Items[c].pData, S7DataItem, 4, ItemDataSize);
                if (ItemDataSize % 2 != 0) {
                    S7DataItem[ItemDataSize + 4] = 0x00;
                    ItemDataSize++;
                }
                Array.Copy(S7DataItem, 0, this.PDU, Offset, ItemDataSize + 4);
                Offset = Offset + ItemDataSize + 4;
                DataLength = DataLength + ItemDataSize + 4;
            }

            // Checks the size
            if (Offset > this.PduSizeNegotiated) {
                return S7Consts.errCliSizeOverPDU;
            }

            this.PDU.SetWordAt(2, (ushort)Offset); // Whole size
            this.PDU.SetWordAt(15, (ushort)DataLength); // Whole size
            SendPacket(this.PDU, Offset);

            RecvIsoPacket();
            if (this._LastError == 0) {
                // Check Global Operation Result
                this._LastError = CpuError(this.PDU.GetWordAt(17));
                if (this._LastError != 0) {
                    return this._LastError;
                }
                // Get true ItemsCount
                int ItemsWritten = this.PDU.GetByteAt(20);
                if ((ItemsWritten != ItemsCount) || (ItemsWritten > MaxVars)) {
                    this._LastError = S7Consts.errCliInvalidPlcAnswer;
                    return this._LastError;
                }

                for (int c = 0; c < ItemsCount; c++) {
                    if (this.PDU[c + 21] == 0xFF) {
                        Items[c].Result = 0;
                    } else {
                        Items[c].Result = CpuError((ushort)this.PDU[c + 21]);
                    }
                }
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }
            return this._LastError;
        }

        #endregion

        #region [Data I/O lean functions]

        public int DBRead(int DBNumber, int Start, int Size, byte[] Buffer) {
            return ReadArea(S7Area.DB, DBNumber, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int DBWrite(int DBNumber, int Start, int Size, byte[] Buffer) {
            return WriteArea(S7Area.DB, DBNumber, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int MBRead(int Start, int Size, byte[] Buffer) {
            return ReadArea(S7Area.MK, 0, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int MBWrite(int Start, int Size, byte[] Buffer) {
            return WriteArea(S7Area.MK, 0, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int EBRead(int Start, int Size, byte[] Buffer) {
            return ReadArea(S7Area.PE, 0, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int EBWrite(int Start, int Size, byte[] Buffer) {
            return WriteArea(S7Area.PE, 0, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int ABRead(int Start, int Size, byte[] Buffer) {
            return ReadArea(S7Area.PA, 0, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int ABWrite(int Start, int Size, byte[] Buffer) {
            return WriteArea(S7Area.PA, 0, Start, Size, S7WordLength.Byte, Buffer);
        }

        public int TMRead(int Start, int Amount, ushort[] Buffer) {
            byte[] sBuffer = new byte[Amount * 2];
            int Result = ReadArea(S7Area.TM, 0, Start, Amount, S7WordLength.Timer, sBuffer);
            if (Result == 0) {
                for (int c = 0; c < Amount; c++) {
                    Buffer[c] = (ushort)((sBuffer[(c * 2) + 1] << 8) + sBuffer[c * 2]);
                }
            }
            return Result;
        }

        public int TMWrite(int Start, int Amount, ushort[] Buffer) {
            byte[] sBuffer = new byte[Amount * 2];
            for (int c = 0; c < Amount; c++) {
                sBuffer[(c * 2) + 1] = (byte)((Buffer[c] & 0xFF00) >> 8);
                sBuffer[c * 2] = (byte)(Buffer[c] & 0x00FF);
            }
            return WriteArea(S7Area.TM, 0, Start, Amount, S7WordLength.Timer, sBuffer);
        }

        public int CTRead(int Start, int Amount, ushort[] Buffer) {
            byte[] sBuffer = new byte[Amount * 2];
            int Result = ReadArea(S7Area.CT, 0, Start, Amount, S7WordLength.Counter, sBuffer);
            if (Result == 0) {
                for (int c = 0; c < Amount; c++) {
                    Buffer[c] = (ushort)((sBuffer[(c * 2) + 1] << 8) + sBuffer[c * 2]);
                }
            }
            return Result;
        }

        public int CTWrite(int Start, int Amount, ushort[] Buffer) {
            byte[] sBuffer = new byte[Amount * 2];
            for (int c = 0; c < Amount; c++) {
                sBuffer[(c * 2) + 1] = (byte)((Buffer[c] & 0xFF00) >> 8);
                sBuffer[c * 2] = (byte)(Buffer[c] & 0x00FF);
            }
            return WriteArea(S7Area.CT, 0, Start, Amount, S7WordLength.Counter, sBuffer);
        }

        #endregion

        #region [Directory functions]

        public int ListBlocks(ref S7BlocksList List) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        private string SiemensTimestamp(long EncodedDate) {
            DateTime DT = new DateTime(1984, 1, 1).AddSeconds(EncodedDate * 86400);
#if WINDOWS_UWP || NETFX_CORE || CORE_CLR
            return DT.ToString(System.Globalization.DateTimeFormatInfo.CurrentInfo.ShortDatePattern);
#else
            return DT.ToShortDateString();
#endif
        }

        public int GetAgBlockInfo(int BlockType, int BlockNum, ref S7BlockInfo Info) {
            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;

            this.S7_BI[30] = (byte)BlockType;
            // Block Number
            this.S7_BI[31] = (byte)((BlockNum / 10000) + 0x30);
            BlockNum %= 10000;
            this.S7_BI[32] = (byte)((BlockNum / 1000) + 0x30);
            BlockNum %= 1000;
            this.S7_BI[33] = (byte)((BlockNum / 100) + 0x30);
            BlockNum %= 100;
            this.S7_BI[34] = (byte)((BlockNum / 10) + 0x30);
            BlockNum %= 10;
            this.S7_BI[35] = (byte)((BlockNum / 1) + 0x30);

            SendPacket(this.S7_BI);

            if (this._LastError == 0) {
                int Length = RecvIsoPacket();
                if (Length > 32) // the minimum expected
                {
                    ushort Result = this.PDU.GetWordAt(27);
                    if (Result == 0) {
                        Info.BlkFlags = this.PDU[42];
                        Info.BlkLang = this.PDU[43];
                        Info.BlkType = this.PDU[44];
                        Info.BlkNumber = this.PDU.GetWordAt(45);
                        Info.LoadSize = this.PDU.GetDIntAt(47);
                        Info.CodeDate = SiemensTimestamp(this.PDU.GetWordAt(59));
                        Info.IntfDate = SiemensTimestamp(this.PDU.GetWordAt(65));
                        Info.SBBLength = this.PDU.GetWordAt(67);
                        Info.LocalData = this.PDU.GetWordAt(71);
                        Info.MC7Size = this.PDU.GetWordAt(73);
                        Info.Author = this.PDU.GetCharsAt(75, 8).Trim(new char[] { (char)0 });
                        Info.Family = this.PDU.GetCharsAt(83, 8).Trim(new char[] { (char)0 });
                        Info.Header = this.PDU.GetCharsAt(91, 8).Trim(new char[] { (char)0 });
                        Info.Version = this.PDU[99];
                        Info.CheckSum = this.PDU.GetWordAt(101);
                    } else {
                        this._LastError = CpuError(Result);
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;

        }

        public int GetPgBlockInfo(ref S7BlockInfo Info, byte[] Buffer, int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int ListBlocksOfType(int BlockType, ushort[] List, ref int ItemsCount) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        #endregion

        #region [Blocks functions]

        public int Upload(int BlockType, int BlockNum, byte[] UsrData, ref int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int FullUpload(int BlockType, int BlockNum, byte[] UsrData, ref int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int Download(int BlockNum, byte[] UsrData, int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int Delete(int BlockType, int BlockNum) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int DBGet(int DBNumber, byte[] UsrData, ref int Size) {
            S7BlockInfo BI = new S7BlockInfo();
            int Elapsed = Environment.TickCount;
            this.ExecutionTime = 0;

            this._LastError = GetAgBlockInfo(Block_DB, DBNumber, ref BI);

            if (this._LastError == 0) {
                int DBSize = BI.MC7Size;
                if (DBSize <= UsrData.Length) {
                    Size = DBSize;
                    this._LastError = DBRead(DBNumber, 0, DBSize, UsrData);
                    if (this._LastError == 0) {
                        Size = DBSize;
                    }
                } else {
                    this._LastError = S7Consts.errCliBufferTooSmall;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int DBFill(int DBNumber, int FillChar) {
            S7BlockInfo BI = new S7BlockInfo();
            int Elapsed = Environment.TickCount;
            this.ExecutionTime = 0;

            this._LastError = GetAgBlockInfo(Block_DB, DBNumber, ref BI);

            if (this._LastError == 0) {
                byte[] Buffer = new byte[BI.MC7Size];
                for (int c = 0; c < BI.MC7Size; c++) {
                    Buffer[c] = (byte)FillChar;
                }

                this._LastError = DBWrite(DBNumber, 0, BI.MC7Size, Buffer);
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        #endregion

        #region [Date/Time functions]

        public int GetPlcDateTime(ref DateTime DT) {
            int Length;
            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;

            SendPacket(this.S7_GET_DT);
            if (this._LastError == 0) {
                Length = RecvIsoPacket();
                if (Length > 30) // the minimum expected
                {
                    if ((this.PDU.GetWordAt(27) == 0) && (this.PDU[29] == 0xFF)) {
                        DT = this.PDU.GetDateTimeAt(35);
                    } else {
                        this._LastError = S7Consts.errCliInvalidPlcAnswer;
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }

            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int SetPlcDateTime(DateTime DT) {
            int Length;
            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;

            this.S7_SET_DT.SetDateTimeAt(31, DT);
            SendPacket(this.S7_SET_DT);
            if (this._LastError == 0) {
                Length = RecvIsoPacket();
                if (Length > 30) // the minimum expected
                {
                    if (this.PDU.GetWordAt(27) != 0) {
                        this._LastError = S7Consts.errCliInvalidPlcAnswer;
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int SetPlcSystemDateTime() {
            return SetPlcDateTime(DateTime.Now);
        }

        #endregion

        #region [System Info functions]

        public int GetOrderCode(ref S7OrderCode Info) {
            S7SZL SZL = new S7SZL();
            int Size = 1024;
            SZL.Data = new byte[Size];
            int Elapsed = Environment.TickCount;
            this._LastError = ReadSZL(0x0011, 0x000, ref SZL, ref Size);
            if (this._LastError == 0) {
                Info.Code = SZL.Data.GetCharsAt(2, 20);
                Info.V1 = SZL.Data[Size - 3];
                Info.V2 = SZL.Data[Size - 2];
                Info.V3 = SZL.Data[Size - 1];
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int GetCpuInfo(ref S7CpuInfo Info) {
            S7SZL SZL = new S7SZL();
            int Size = 1024;
            SZL.Data = new byte[Size];
            int Elapsed = Environment.TickCount;
            this._LastError = ReadSZL(0x001C, 0x000, ref SZL, ref Size);
            if (this._LastError == 0) {
                Info.ModuleTypeName = SZL.Data.GetCharsAt(172, 32);
                Info.SerialNumber = SZL.Data.GetCharsAt(138, 24);
                Info.ASName = SZL.Data.GetCharsAt(2, 24);
                Info.Copyright = SZL.Data.GetCharsAt(104, 26);
                Info.ModuleName = SZL.Data.GetCharsAt(36, 24);
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int GetCpInfo(ref S7CpInfo Info) {
            S7SZL SZL = new S7SZL();
            int Size = 1024;
            SZL.Data = new byte[Size];
            int Elapsed = Environment.TickCount;
            this._LastError = ReadSZL(0x0131, 0x001, ref SZL, ref Size);
            if (this._LastError == 0) {
                Info.MaxPduLength = this.PDU.GetIntAt(2);
                Info.MaxConnections = this.PDU.GetIntAt(4);
                Info.MaxMpiRate = this.PDU.GetDIntAt(6);
                Info.MaxBusRate = this.PDU.GetDIntAt(10);
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int ReadSZL(int ID, int Index, ref S7SZL SZL, ref int Size) {
            int Length;
            int DataSZL;
            int Offset = 0;
            bool Done = false;
            bool First = true;
            byte Seq_in = 0x00;
            ushort Seq_out = 0x0000;

            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;
            SZL.Header.LENTHDR = 0;

            do {
                if (First) {
                    this.S7_SZL_FIRST.SetWordAt(11, ++Seq_out);
                    this.S7_SZL_FIRST.SetWordAt(29, (ushort)ID);
                    this.S7_SZL_FIRST.SetWordAt(31, (ushort)Index);
                    SendPacket(this.S7_SZL_FIRST);
                } else {
                    this.S7_SZL_NEXT.SetWordAt(11, ++Seq_out);
                    this.S7_SZL_NEXT[24] = (byte)Seq_in;
                    SendPacket(this.S7_SZL_NEXT);
                }
                if (this._LastError != 0) {
                    return this._LastError;
                }

                Length = RecvIsoPacket();
                if (this._LastError == 0) {
                    if (First) {
                        if (Length > 32) // the minimum expected
                        {
                            if ((this.PDU.GetWordAt(27) == 0) && (this.PDU[29] == (byte)0xFF)) {
                                // Gets Amount of this slice
                                DataSZL = this.PDU.GetWordAt(31) - 8; // Skips extra params (ID, Index ...)
                                Done = this.PDU[26] == 0x00;
                                Seq_in = (byte)this.PDU[24]; // Slice sequence
                                SZL.Header.LENTHDR = this.PDU.GetWordAt(37);
                                SZL.Header.N_DR = this.PDU.GetWordAt(39);
                                Array.Copy(this.PDU, 41, SZL.Data, Offset, DataSZL);
                                //                                SZL.Copy(PDU, 41, Offset, DataSZL);
                                Offset += DataSZL;
                                SZL.Header.LENTHDR += SZL.Header.LENTHDR;
                            } else {
                                this._LastError = S7Consts.errCliInvalidPlcAnswer;
                            }
                        } else {
                            this._LastError = S7Consts.errIsoInvalidPDU;
                        }
                    } else {
                        if (Length > 32) // the minimum expected
                        {
                            if ((this.PDU.GetWordAt(27) == 0) && (this.PDU[29] == (byte)0xFF)) {
                                // Gets Amount of this slice
                                DataSZL = this.PDU.GetWordAt(31);
                                Done = this.PDU[26] == 0x00;
                                Seq_in = (byte)this.PDU[24]; // Slice sequence
                                Array.Copy(this.PDU, 37, SZL.Data, Offset, DataSZL);
                                Offset += DataSZL;
                                SZL.Header.LENTHDR += SZL.Header.LENTHDR;
                            } else {
                                this._LastError = S7Consts.errCliInvalidPlcAnswer;
                            }
                        } else {
                            this._LastError = S7Consts.errIsoInvalidPDU;
                        }
                    }
                }
                First = false;
            }
            while (!Done && (this._LastError == 0));
            if (this._LastError == 0) {
                Size = SZL.Header.LENTHDR;
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }
            return this._LastError;
        }

        public int ReadSZLList(ref S7SZLList List, ref Int32 ItemsCount) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        #endregion

        #region [Control functions]

        public int PlcHotStart() {
            this._LastError = 0;
            int Elapsed = Environment.TickCount;

            SendPacket(this.S7_HOT_START);
            if (this._LastError == 0) {
                int Length = RecvIsoPacket();
                if (Length > 18) // 18 is the minimum expected
                {
                    if (this.PDU[19] != pduStart) {
                        this._LastError = S7Consts.errCliCannotStartPLC;
                    } else {
                        if (this.PDU[20] == pduAlreadyStarted) {
                            this._LastError = S7Consts.errCliAlreadyRun;
                        } else {
                            this._LastError = S7Consts.errCliCannotStartPLC;
                        }
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int PlcColdStart() {
            this._LastError = 0;
            int Elapsed = Environment.TickCount;

            SendPacket(this.S7_COLD_START);
            if (this._LastError == 0) {
                int Length = RecvIsoPacket();
                if (Length > 18) // 18 is the minimum expected
                {
                    if (this.PDU[19] != pduStart) {
                        this._LastError = S7Consts.errCliCannotStartPLC;
                    } else {
                        if (this.PDU[20] == pduAlreadyStarted) {
                            this._LastError = S7Consts.errCliAlreadyRun;
                        } else {
                            this._LastError = S7Consts.errCliCannotStartPLC;
                        }
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int PlcStop() {
            this._LastError = 0;
            int Elapsed = Environment.TickCount;

            SendPacket(this.S7_STOP);
            if (this._LastError == 0) {
                int Length = RecvIsoPacket();
                if (Length > 18) // 18 is the minimum expected
                {
                    if (this.PDU[19] != pduStop) {
                        this._LastError = S7Consts.errCliCannotStopPLC;
                    } else {
                        if (this.PDU[20] == pduAlreadyStopped) {
                            this._LastError = S7Consts.errCliAlreadyStop;
                        } else {
                            this._LastError = S7Consts.errCliCannotStopPLC;
                        }
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int PlcCopyRamToRom(UInt32 Timeout) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int PlcCompress(UInt32 Timeout) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int PlcGetStatus(ref Int32 Status) {
            this._LastError = 0;
            int Elapsed = Environment.TickCount;

            SendPacket(this.S7_GET_STAT);
            if (this._LastError == 0) {
                int Length = RecvIsoPacket();
                if (Length > 30) // the minimum expected
                {
                    ushort Result = this.PDU.GetWordAt(27);
                    if (Result == 0) {
                        switch (this.PDU[44]) {
                            case S7Consts.S7CpuStatusUnknown:
                            case S7Consts.S7CpuStatusRun:
                            case S7Consts.S7CpuStatusStop: {
                                Status = this.PDU[44];
                                break;
                            }
                            default: {
                                // Since RUN status is always 0x08 for all CPUs and CPs, STOP status
                                // sometime can be coded as 0x03 (especially for old cpu...)
                                Status = S7Consts.S7CpuStatusStop;
                                break;
                            }
                        }
                    } else {
                        this._LastError = CpuError(Result);
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        #endregion

        #region [Security functions]
        public int SetSessionPassword(string Password) {
            byte[] pwd = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
            int Length;
            this._LastError = 0;
            int Elapsed = Environment.TickCount;
            // Encodes the Password
            pwd.SetCharsAt(0, Password);
            pwd[0] = (byte)(pwd[0] ^ 0x55);
            pwd[1] = (byte)(pwd[1] ^ 0x55);
            for (int c = 2; c < 8; c++) {
                pwd[c] = (byte)(pwd[c] ^ 0x55 ^ pwd[c - 2]);
            }
            Array.Copy(pwd, 0, this.S7_SET_PWD, 29, 8);
            // Sends the telegrem
            SendPacket(this.S7_SET_PWD);
            if (this._LastError == 0) {
                Length = RecvIsoPacket();
                if (Length > 32) // the minimum expected
                {
                    ushort Result = this.PDU.GetWordAt(27);
                    if (Result != 0) {
                        this._LastError = CpuError(Result);
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            }

            return this._LastError;
        }

        public int ClearSessionPassword() {
            int Length;
            this._LastError = 0;
            int Elapsed = Environment.TickCount;
            SendPacket(this.S7_CLR_PWD);
            if (this._LastError == 0) {
                Length = RecvIsoPacket();
                if (Length > 30) // the minimum expected
                {
                    ushort Result = this.PDU.GetWordAt(27);
                    if (Result != 0) {
                        this._LastError = CpuError(Result);
                    }
                } else {
                    this._LastError = S7Consts.errIsoInvalidPDU;
                }
            }
            return this._LastError;
        }

        public int GetProtection(ref S7Protection Protection) {
            S7Client.S7SZL SZL = new S7Client.S7SZL();
            int Size = 256;
            SZL.Data = new byte[Size];
            this._LastError = ReadSZL(0x0232, 0x0004, ref SZL, ref Size);
            if (this._LastError == 0) {
                Protection.sch_schal = SZL.Data.GetWordAt(2);
                Protection.sch_par = SZL.Data.GetWordAt(4);
                Protection.sch_rel = SZL.Data.GetWordAt(6);
                Protection.bart_sch = SZL.Data.GetWordAt(8);
                Protection.anl_sch = SZL.Data.GetWordAt(10);
            }
            return this._LastError;
        }
        #endregion

        #region [Low Level]

        public int IsoExchangeBuffer(byte[] Buffer, ref Int32 Size) {
            this._LastError = 0;
            this.ExecutionTime = 0;
            int Elapsed = Environment.TickCount;
            Array.Copy(this.TPKT_ISO, 0, this.PDU, 0, this.TPKT_ISO.Length);
            this.PDU.SetWordAt(2, (ushort)(Size + this.TPKT_ISO.Length));
            try {
                Array.Copy(Buffer, 0, this.PDU, this.TPKT_ISO.Length, Size);
            } catch {
                return S7Consts.errIsoInvalidPDU;
            }
            SendPacket(this.PDU, this.TPKT_ISO.Length + Size);
            if (this._LastError == 0) {
                int Length = RecvIsoPacket();
                if (this._LastError == 0) {
                    Array.Copy(this.PDU, this.TPKT_ISO.Length, Buffer, 0, Length - this.TPKT_ISO.Length);
                    Size = Length - this.TPKT_ISO.Length;
                }
            }
            if (this._LastError == 0) {
                this.ExecutionTime = Environment.TickCount - Elapsed;
            } else {
                Size = 0;
            }

            return this._LastError;
        }

        #endregion

        #region [Async functions (not implemented)]

        public int AsReadArea(int Area, int DBNumber, int Start, int Amount, int WordLen, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsWriteArea(int Area, int DBNumber, int Start, int Amount, int WordLen, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsDBRead(int DBNumber, int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsDBWrite(int DBNumber, int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsMBRead(int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsMBWrite(int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsEBRead(int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsEBWrite(int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsABRead(int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsABWrite(int Start, int Size, byte[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsTMRead(int Start, int Amount, ushort[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsTMWrite(int Start, int Amount, ushort[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsCTRead(int Start, int Amount, ushort[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsCTWrite(int Start, int Amount, ushort[] Buffer) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsListBlocksOfType(int BlockType, ushort[] List) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsReadSZL(int ID, int Index, ref S7SZL Data, ref Int32 Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsReadSZLList(ref S7SZLList List, ref Int32 ItemsCount) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsUpload(int BlockType, int BlockNum, byte[] UsrData, ref int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsFullUpload(int BlockType, int BlockNum, byte[] UsrData, ref int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int ASDownload(int BlockNum, byte[] UsrData, int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsPlcCopyRamToRom(UInt32 Timeout) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsPlcCompress(UInt32 Timeout) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsDBGet(int DBNumber, byte[] UsrData, ref int Size) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public int AsDBFill(int DBNumber, int FillChar) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        public bool CheckAsCompletion(ref int opResult) {
            opResult = 0;
            return false;
        }

        public int WaitAsCompletion(int Timeout) {
            return S7Consts.errCliFunctionNotImplemented;
        }

        #endregion

        #region [Info Functions / Properties]

        public string ErrorText(int Error) {
            return Error switch {
                0 => "OK",
                S7Consts.errTCPSocketCreation => "SYS: Error creating the Socket",
                S7Consts.errTCPConnectionTimeout => "TCP: Connection Timeout",
                S7Consts.errTCPConnectionFailed => "TCP: Connection Error",
                S7Consts.errTCPReceiveTimeout => "TCP: Data receive Timeout",
                S7Consts.errTCPDataReceive => "TCP: Error receiving Data",
                S7Consts.errTCPSendTimeout => "TCP: Data send Timeout",
                S7Consts.errTCPDataSend => "TCP: Error sending Data",
                S7Consts.errTCPConnectionReset => "TCP: Connection reset by the Peer",
                S7Consts.errTCPNotConnected => "CLI: Client not connected",
                S7Consts.errTCPUnreachableHost => "TCP: Unreachable host",
                S7Consts.errIsoConnect => "ISO: Connection Error",
                S7Consts.errIsoInvalidPDU => "ISO: Invalid PDU received",
                S7Consts.errIsoInvalidDataSize => "ISO: Invalid Buffer passed to Send/Receive",
                S7Consts.errCliNegotiatingPDU => "CLI: Error in PDU negotiation",
                S7Consts.errCliInvalidParams => "CLI: Invalid param(s) supplied",
                S7Consts.errCliJobPending => "CLI: Job pending",
                S7Consts.errCliTooManyItems => "CLI: Too many items (>20) in multi read/write",
                S7Consts.errCliInvalidWordLen => "CLI: Invalid WordLength",
                S7Consts.errCliPartialDataWritten => "CLI: Partial data written",
                S7Consts.errCliSizeOverPDU => "CPU: Total data exceeds the PDU size",
                S7Consts.errCliInvalidPlcAnswer => "CLI: Invalid CPU answer",
                S7Consts.errCliAddressOutOfRange => "CPU: Address out of range",
                S7Consts.errCliInvalidTransportSize => "CPU: Invalid Transport size",
                S7Consts.errCliWriteDataSizeMismatch => "CPU: Data size mismatch",
                S7Consts.errCliItemNotAvailable => "CPU: Item not available",
                S7Consts.errCliInvalidValue => "CPU: Invalid value supplied",
                S7Consts.errCliCannotStartPLC => "CPU: Cannot start PLC",
                S7Consts.errCliAlreadyRun => "CPU: PLC already RUN",
                S7Consts.errCliCannotStopPLC => "CPU: Cannot stop PLC",
                S7Consts.errCliCannotCopyRamToRom => "CPU: Cannot copy RAM to ROM",
                S7Consts.errCliCannotCompress => "CPU: Cannot compress",
                S7Consts.errCliAlreadyStop => "CPU: PLC already STOP",
                S7Consts.errCliFunNotAvailable => "CPU: Function not available",
                S7Consts.errCliUploadSequenceFailed => "CPU: Upload sequence failed",
                S7Consts.errCliInvalidDataSizeRecvd => "CLI: Invalid data size received",
                S7Consts.errCliInvalidBlockType => "CLI: Invalid block type",
                S7Consts.errCliInvalidBlockNumber => "CLI: Invalid block number",
                S7Consts.errCliInvalidBlockSize => "CLI: Invalid block size",
                S7Consts.errCliNeedPassword => "CPU: Function not authorized for current protection level",
                S7Consts.errCliInvalidPassword => "CPU: Invalid password",
                S7Consts.errCliNoPasswordToSetOrClear => "CPU: No password to set or clear",
                S7Consts.errCliJobTimeout => "CLI: Job Timeout",
                S7Consts.errCliFunctionRefused => "CLI: Function refused by CPU (Unknown error)",
                S7Consts.errCliPartialDataRead => "CLI: Partial data read",
                S7Consts.errCliBufferTooSmall => "CLI: The buffer supplied is too small to accomplish the operation",
                S7Consts.errCliDestroying => "CLI: Cannot perform (destroying)",
                S7Consts.errCliInvalidParamNumber => "CLI: Invalid Param Number",
                S7Consts.errCliCannotChangeParam => "CLI: Cannot change this param now",
                S7Consts.errCliFunctionNotImplemented => "CLI: Function not implemented",
                _ => "CLI: Unknown error (0x" + Convert.ToString(Error, 16) + ")",
            };
            ;
        }

        public int LastError() {
            return this._LastError;
        }

        public int RequestedPduLength() {
            return this._PduSizeRequested;
        }

        public int NegotiatedPduLength() {
            return this.PduSizeNegotiated;
        }

        public int ExecTime() {
            return this.ExecutionTime;
        }

        public int ExecutionTime { get; private set; } = 0;

        public int PduSizeNegotiated { get; private set; } = 0;

        public int PduSizeRequested {
            get => this._PduSizeRequested;
            set {
                if (value < MinPduSizeToRequest) {
                    value = MinPduSizeToRequest;
                }

                if (value > MaxPduSizeToRequest) {
                    value = MaxPduSizeToRequest;
                }

                this._PduSizeRequested = value;
            }
        }

        public string PLCIpAddress { get; private set; }

        public int PLCPort { get; set; } = ISOTCP;

        public int ConnTimeout {
            get => this.Socket.ConnectTimeout;
            set => this.Socket.ConnectTimeout = value;
        }

        public int RecvTimeout {
            get => this.Socket.ReadTimeout;
            set => this.Socket.ReadTimeout = value;
        }

        public int SendTimeout {
            get => this.Socket.WriteTimeout;
            set => this.Socket.WriteTimeout = value;
        }

        public bool Connected => (this.Socket != null) && this.Socket.Connected;

        #endregion
    }
}