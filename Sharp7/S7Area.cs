namespace Sharp7
{
    public enum S7Area
    {
        PE = 0x81,    // I区, 输入过程映像区（Process Inputs）
        PA = 0x82,    // Q区, 输出过程映像区（Process Outputs）
        MK = 0x83,    // M区, 位存储区（Memory Flags）
        DB = 0x84,    // 数据块（Data Blocks）
        CT = 0x1C,    // Counters
        TM = 0x1D,    // Timers
    }
}