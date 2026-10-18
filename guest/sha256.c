// SHA-256 of a message held in .data; exit code = first byte of the digest.
// SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad.

typedef unsigned int u32;
typedef unsigned char u8;

static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(u32 h[8], const u8 block[64]) {
    u32 w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (u32)block[4 * i] << 24 | (u32)block[4 * i + 1] << 16 | (u32)block[4 * i + 2] << 8 | block[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = hh + S1 + ch + K[i] + w[i];
        u32 S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const u8 *msg, u32 len, u8 out[32]) {
    u32 h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    u8 block[64];
    u32 i = 0;
    for (; i + 64 <= len; i += 64)
        compress(h, msg + i);
    // final block(s): remaining bytes, 0x80, zeros, 64-bit big-endian bit length
    u32 r = len - i;
    for (u32 j = 0; j < 64; j++)
        block[j] = j < r ? msg[i + j] : (j == r ? 0x80 : 0);
    if (r >= 56) {
        compress(h, block);
        for (u32 j = 0; j < 64; j++)
            block[j] = 0;
    }
    unsigned long long bits = (unsigned long long)len * 8;
    for (int j = 0; j < 8; j++)
        block[63 - j] = (u8)(bits >> (8 * j));
    compress(h, block);
    for (int j = 0; j < 32; j++)
        out[j] = (u8)(h[j / 4] >> (24 - 8 * (j % 4)));
}

u8 MSG[] = "abc";            // .data, not const: the compiler cannot precompute the hash
volatile u32 LEN = 3;
u8 DIGEST[32];               // .bss: the full digest stays in RAM for inspection

int main(void) {
    sha256(MSG, LEN, DIGEST);
    return DIGEST[0];        // 0xba = 186
}
