// bcrypt_compat.c — PRF как в PyCryptodome _bcrypt_hash(..., invert=False)
#include <stdint.h>
#include <string.h>
#include "blf.h"

#ifdef __cplusplus
extern "C" {
#endif

    static void enc_ecb_8(blf_ctx* c, uint8_t* b) {
        uint32_t L = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
            ((uint32_t)b[2] << 8) | (uint32_t)b[3];
        uint32_t R = ((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) |
            ((uint32_t)b[6] << 8) | (uint32_t)b[7];
        Blowfish_encipher(c, &L, &R);
        b[0] = (uint8_t)(L >> 24); b[1] = (uint8_t)(L >> 16);
        b[2] = (uint8_t)(L >> 8); b[3] = (uint8_t)(L);
        b[4] = (uint8_t)(R >> 24); b[5] = (uint8_t)(R >> 16);
        b[6] = (uint8_t)(R >> 8); b[7] = (uint8_t)(R);
    }

    // --- EksBlowfishSetup: salt, key; затем 2^cost: key -> salt ---
    static void eks_setup(blf_ctx* c,
        const uint8_t* salt, int salt_len,
        const uint8_t* key, int key_len,
        int cost)
    {
        Blowfish_initstate(c);

        // ВАЖНО: сначала SALT как data, KEY как key (OpenBSD порядок)
        Blowfish_expandstate(c, salt, (u_int16_t)salt_len, key, (u_int16_t)key_len);

        uint32_t rounds = 1u << cost; // cost=6 => 64
        for (uint32_t i = 0; i < rounds; i++) {
            Blowfish_expand0state(c, salt, (u_int16_t)salt_len);
            Blowfish_expand0state(c, key, (u_int16_t)key_len);
        }
    }

#ifdef _WIN32
    __declspec(dllexport)
#endif
        int __cdecl bcrypt_hash_compat_v3(
            const uint8_t* pw512, int pwLen,     // 64: SHA-512(password)
            const uint8_t* salt512, int saltLen,   // 64: SHA-512(salt)
            int cost,
            uint8_t out32[32])
    {
        if (!pw512 || !salt512 || !out32) return -2;
        if (pwLen != 64 || saltLen != 64) return -1;

        blf_ctx st;
        // Порядок как выше: salt, key
        eks_setup(&st, salt512, 64, pw512, 64, cost);

        static const uint8_t ctext32[] = "OxychromaticBlowfishSwatDynamite"; // 32 байта
        uint8_t buf[32];
        memcpy(buf, ctext32, 32);

        // 64 раза шифруем 32-байтный буфер по 8 байт (ECB)
        for (int r = 0; r < 64; r++)
            for (int i = 0; i < 32; i += 8)
                enc_ecb_8(&st, buf + i);

        // Выход = разворот КАЖДОГО 32-битного слова (точно как в твоём Python)
        for (int i = 0; i < 32; i += 4) {
            out32[i + 0] = buf[i + 3];
            out32[i + 1] = buf[i + 2];
            out32[i + 2] = buf[i + 1];
            out32[i + 3] = buf[i + 0];
        }
        return 0;
    }

#ifdef __cplusplus
}
#endif
