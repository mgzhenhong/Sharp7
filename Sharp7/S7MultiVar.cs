using System;
using System.Runtime.InteropServices;

namespace Sharp7
{
    public class S7MultiVar
    {
        #region [MultiRead/Write Helper]
        private readonly S7Client FClient;
        private readonly GCHandle[] Handles = new GCHandle[S7Client.MaxVars];
        private int Count;
        private readonly S7Client.S7DataItem[] Items = new S7Client.S7DataItem[S7Client.MaxVars];

        public int[] Results { get; } = new int[S7Client.MaxVars];

        private bool AdjustWordLength(int Area, ref int WordLen, ref int Amount, ref int Start) {
            // Calc Word size          
            int WordSize = WordLen.DataSizeByte();
            if (WordSize == 0) {
                return false;
            }

            if (Area == (int)S7Area.CT) {
                WordLen = (int)S7WordLength.Counter;
            }

            if (Area == (int)S7Area.TM) {
                WordLen = (int)S7WordLength.Timer;
            }

            if (WordLen == (int)S7WordLength.Bit) {
                Amount = 1;  // Only 1 bit can be transferred at time
            } else {
                if (WordLen is not ((int)S7WordLength.Counter) and not ((int)S7WordLength.Timer)) {
                    Amount *= WordSize;
                    Start *= 8;
                    WordLen = (int)S7WordLength.Byte;
                }
            }
            return true;
        }

        public S7MultiVar(S7Client Client) {
            this.FClient = Client;
            for (int c = 0; c < S7Client.MaxVars; c++) {
                this.Results[c] = S7Consts.errCliItemNotAvailable;
            }
        }
        ~S7MultiVar() {
            Clear();
        }

        public bool Add<T>(S7Consts.S7Tag Tag, ref T[] Buffer, int Offset) {
            return Add(Tag.Area, Tag.WordLen, Tag.DBNumber, Tag.Start, Tag.Elements, ref Buffer, Offset);
        }

        public bool Add<T>(S7Consts.S7Tag Tag, ref T[] Buffer) {
            return Add(Tag.Area, Tag.WordLen, Tag.DBNumber, Tag.Start, Tag.Elements, ref Buffer);
        }

        public bool Add<T>(Int32 Area, Int32 WordLen, Int32 DBNumber, Int32 Start, Int32 Amount, ref T[] Buffer) {
            return Add(Area, WordLen, DBNumber, Start, Amount, ref Buffer, 0);
        }

        public bool Add<T>(Int32 Area, Int32 WordLen, Int32 DBNumber, Int32 Start, Int32 Amount, ref T[] Buffer, int Offset) {
            if (this.Count < S7Client.MaxVars) {
                if (AdjustWordLength(Area, ref WordLen, ref Amount, ref Start)) {
                    this.Items[this.Count].Area = Area;
                    this.Items[this.Count].WordLen = WordLen;
                    this.Items[this.Count].Result = (int)S7Consts.errCliItemNotAvailable;
                    this.Items[this.Count].DBNumber = DBNumber;
                    this.Items[this.Count].Start = Start;
                    this.Items[this.Count].Amount = Amount;
                    GCHandle handle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);

                    if (IntPtr.Size == 4) {
                        this.Items[this.Count].pData = (IntPtr)(handle.AddrOfPinnedObject().ToInt32() + (Offset * Marshal.SizeOf(typeof(T))));
                    } else {
                        this.Items[this.Count].pData = (IntPtr)(handle.AddrOfPinnedObject().ToInt64() + (Offset * Marshal.SizeOf(typeof(T))));
                    }

                    this.Handles[this.Count] = handle;
                    this.Count++;
                    return true;
                }

                return false;
            }

            return false;
        }

        public int Read() {
            int FunctionResult;
            int GlobalResult;
            try {
                if (this.Count > 0) {
                    FunctionResult = this.FClient.ReadMultiVars(this.Items, this.Count);
                    if (FunctionResult == 0) {
                        for (int c = 0; c < S7Client.MaxVars; c++) {
                            this.Results[c] = this.Items[c].Result;
                        }
                    }

                    GlobalResult = FunctionResult;
                } else {
                    GlobalResult = S7Consts.errCliFunctionRefused;
                }
            } finally {
                Clear(); // handles are no more needed and MUST be freed
            }
            return GlobalResult;
        }

        public int Write() {
            int FunctionResult;
            int GlobalResult;
            try {
                if (this.Count > 0) {
                    FunctionResult = this.FClient.WriteMultiVars(this.Items, this.Count);
                    if (FunctionResult == 0) {
                        for (int c = 0; c < S7Client.MaxVars; c++) {
                            this.Results[c] = this.Items[c].Result;
                        }
                    }

                    GlobalResult = FunctionResult;
                } else {
                    GlobalResult = S7Consts.errCliFunctionRefused;
                }
            } finally {
                Clear(); // handles are no more needed and MUST be freed
            }
            return GlobalResult;
        }

        public void Clear() {
            for (int c = 0; c < this.Count; c++) {
                this.Handles[c].Free();
            }
            this.Count = 0;
        }
        #endregion
    }
}