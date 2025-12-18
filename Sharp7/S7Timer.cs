using System;
using System.Collections.Generic;

namespace Sharp7
{
    public class S7Timer
    {
        #region S7Timer

        public S7Timer(byte[] buff, int position) {
            if (position + 12 < buff.Length) {
                SetTimer(new List<byte>(buff).GetRange(position, 12).ToArray());
            }
        }

        public S7Timer(byte[] buff) {
            SetTimer(buff);
        }

        private void SetTimer(byte[] buff) {
            if (buff.Length != 12) {
                this.PT = new TimeSpan(0);
                this.ET = new TimeSpan(0);
            } else {
                Int32 resPT;
                resPT = buff[0]; resPT <<= 8;
                resPT += buff[1]; resPT <<= 8;
                resPT += buff[2]; resPT <<= 8;
                resPT += buff[3];
                this.PT = new TimeSpan(0, 0, 0, 0, resPT);

                Int32 resET;
                resET = buff[4]; resET <<= 8;
                resET += buff[5]; resET <<= 8;
                resET += buff[6]; resET <<= 8;
                resET += buff[7];
                this.ET = new TimeSpan(0, 0, 0, 0, resET);

                this.IN = (buff[8] & 0x01) == 0x01;
                this.Q = (buff[8] & 0x02) == 0x02;
            }
        }
        public TimeSpan PT { get; private set; }

        public TimeSpan ET { get; private set; }

        public bool IN { get; private set; }

        public bool Q { get; private set; }

        #endregion
    }
}