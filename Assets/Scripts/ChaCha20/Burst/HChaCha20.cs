using Unity.Burst;

namespace Crypto.Burst
{
    [BurstCompile]
    public unsafe struct HChaCha20
    {
        private const int ROUNDS = 20;
        public fixed byte output[32];
        public fixed uint state[16];

        private static uint ROTL(uint a, uint b) => ((a << (int)(b)) | (a >> (32 - (int)(b))));

        private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = ROTL(d, 16);
            c += d; b ^= c; b = ROTL(b, 12);
            a += b; d ^= a; d = ROTL(d, 8);
            c += d; b ^= c; b = ROTL(b, 7);
        }

        [BurstCompile]
        public static void Encode(HChaCha20 *instance, byte *key, byte *nonce)
        {
            instance->state[0] = (uint)'e' | (uint)'x' << 8 | (uint)'p' << 16 | (uint)'a' << 24; // expa
            instance->state[1] = (uint)'n' | (uint)'d' << 8 | (uint)' ' << 16 | (uint)'3' << 24; // nd 3
            instance->state[2] = (uint)'2' | (uint)'-' << 8 | (uint)'b' << 16 | (uint)'y' << 24; // 2-by
            instance->state[3] = (uint)'t' | (uint)'e' << 8 | (uint)' ' << 16 | (uint)'k' << 24; // te k

            instance->state[4] = (uint)key[0] | (uint)key[1] << 8 | (uint)key[2] << 16 | (uint)key[3] << 24;
            instance->state[5] = (uint)key[4] | (uint)key[5] << 8 | (uint)key[6] << 16 | (uint)key[7] << 24;
            instance->state[6] = (uint)key[8] | (uint)key[9] << 8 | (uint)key[10] << 16 | (uint)key[11] << 24;
            instance->state[7] = (uint)key[12] | (uint)key[13] << 8 | (uint)key[14] << 16 | (uint)key[15] << 24;
            instance->state[8] = (uint)key[16] | (uint)key[17] << 8 | (uint)key[18] << 16 | (uint)key[19] << 24;
            instance->state[9] = (uint)key[20] | (uint)key[21] << 8 | (uint)key[22] << 16 | (uint)key[23] << 24;
            instance->state[10] = (uint)key[24] | (uint)key[25] << 8 | (uint)key[26] << 16 | (uint)key[27] << 24;
            instance->state[11] = (uint)key[28] | (uint)key[29] << 8 | (uint)key[30] << 16 | (uint)key[31] << 24;

            instance->state[12] = (uint)nonce[0] | (uint)nonce[1] << 8 | (uint)nonce[2] << 16 | (uint)nonce[3] << 24;
            instance->state[13] = (uint)nonce[4] | (uint)nonce[5] << 8 | (uint)nonce[6] << 16 | (uint)nonce[7] << 24;
            instance->state[14] = (uint)nonce[8] | (uint)nonce[9] << 8 | (uint)nonce[10] << 16 | (uint)nonce[11] << 24;
            instance->state[15] = (uint)nonce[12] | (uint)nonce[13] << 8 | (uint)nonce[14] << 16 | (uint)nonce[15] << 24;

            for (var i = 0; i < ROUNDS; i += 2)
            {
                QR(ref instance->state[0], ref instance->state[4], ref instance->state[8], ref instance->state[12]); // column 0
                QR(ref instance->state[1], ref instance->state[5], ref instance->state[9], ref instance->state[13]); // column 1
                QR(ref instance->state[2], ref instance->state[6], ref instance->state[10], ref instance->state[14]); // column 2
                QR(ref instance->state[3], ref instance->state[7], ref instance->state[11], ref instance->state[15]); // column 3
                // Even round
                QR(ref instance->state[0], ref instance->state[5], ref instance->state[10], ref instance->state[15]); // diagonal 1 (main diagonal)
                QR(ref instance->state[1], ref instance->state[6], ref instance->state[11], ref instance->state[12]); // diagonal 2
                QR(ref instance->state[2], ref instance->state[7], ref instance->state[8], ref instance->state[13]); // diagonal 3
                QR(ref instance->state[3], ref instance->state[4], ref instance->state[9], ref instance->state[14]); // diagonal 4
            }

            instance->output[0] = (byte)(instance->state[0] & 0xff);
            instance->output[1] = (byte)((instance->state[0] >> 8) & 0xff);
            instance->output[2] = (byte)((instance->state[0] >> 16) & 0xff);
            instance->output[3] = (byte)((instance->state[0] >> 24) & 0xff);
            instance->output[4] = (byte)(instance->state[1] & 0xff);
            instance->output[5] = (byte)((instance->state[1] >> 8) & 0xff);
            instance->output[6] = (byte)((instance->state[1] >> 16) & 0xff);
            instance->output[7] = (byte)((instance->state[1] >> 24) & 0xff);
            instance->output[8] = (byte)(instance->state[2] & 0xff);
            instance->output[9] = (byte)((instance->state[2] >> 8) & 0xff);
            instance->output[10] = (byte)((instance->state[2] >> 16) & 0xff);
            instance->output[11] = (byte)((instance->state[2] >> 24) & 0xff);
            instance->output[12] = (byte)(instance->state[3] & 0xff);
            instance->output[13] = (byte)((instance->state[3] >> 8) & 0xff);
            instance->output[14] = (byte)((instance->state[3] >> 16) & 0xff);
            instance->output[15] = (byte)((instance->state[3] >> 24) & 0xff);

            instance->output[16] = (byte)(instance->state[12] & 0xff);
            instance->output[17] = (byte)((instance->state[12] >> 8) & 0xff);
            instance->output[18] = (byte)((instance->state[12] >> 16) & 0xff);
            instance->output[19] = (byte)((instance->state[12] >> 24) & 0xff);
            instance->output[20] = (byte)(instance->state[13] & 0xff);
            instance->output[21] = (byte)((instance->state[13] >> 8) & 0xff);
            instance->output[22] = (byte)((instance->state[13] >> 16) & 0xff);
            instance->output[23] = (byte)((instance->state[13] >> 24) & 0xff);
            instance->output[24] = (byte)(instance->state[14] & 0xff);
            instance->output[25] = (byte)((instance->state[14] >> 8) & 0xff);
            instance->output[26] = (byte)((instance->state[14] >> 16) & 0xff);
            instance->output[27] = (byte)((instance->state[14] >> 24) & 0xff);
            instance->output[28] = (byte)(instance->state[15] & 0xff);
            instance->output[29] = (byte)((instance->state[15] >> 8) & 0xff);
            instance->output[30] = (byte)((instance->state[15] >> 16) & 0xff);
            instance->output[31] = (byte)((instance->state[15] >> 24) & 0xff);
        }
    }
}