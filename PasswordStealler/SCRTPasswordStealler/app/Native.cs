using SecureCRTCompat;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecureCRTCompat
{
    internal static class Win32
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int GetModuleFileName(IntPtr hModule, StringBuilder sb, int nSize);

        internal static string GetLoadedPath(string dllName)
        {
            var h = GetModuleHandle(dllName);
            if (h == IntPtr.Zero) return "<not loaded>";
            var sb = new StringBuilder(1024);
            GetModuleFileName(h, sb, sb.Capacity);
            return sb.ToString();
        }
    }
}

internal static class Native
    {
        [DllImport(
    @"C:\Users\Danil\Desktop\GitProjects\.NetSCRTDecryptor\SCRTPasswordStealler\SCRTPasswordStealler\native_kdf\bcryptkdf_v3.dll",
    CallingConvention = CallingConvention.Cdecl,
    EntryPoint = "bcrypt_hash_compat_v3")]
        public static extern int bcrypt_hash_compat_v3(
    byte[] pw512, int pwLen,
    byte[] salt512, int saltLen,
    int cost,
    [Out] byte[] out32);
    }

    public static class Bytes
    {
        public static byte[] FromHex(string hex)
        {
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
            if ((hex.Length & 1) != 0) throw new ArgumentException("Hex length must be even");
            byte[] r = new byte[hex.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        public static string ToHex(byte[] data) =>
            BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();

        public static int ReadInt32LE(byte[] buf, int ofs = 0)
        {
            // little-endian без зависимости от архитектуры
            return buf[ofs + 0]
                 | (buf[ofs + 1] << 8)
                 | (buf[ofs + 2] << 16)
                 | (buf[ofs + 3] << 24);
        }
        public static uint ReadUInt32LE(byte[] buf, int ofs = 0)
        {
            return (uint)(buf[ofs + 0]
                | (buf[ofs + 1] << 8)
                | (buf[ofs + 2] << 16)
                | (buf[ofs + 3] << 24));
        }
    }

    public static class BcryptCompat
    {
        /// <summary>
        /// PRF = твой Python bcrypt_hash:
        ///   p' = SHA512(password), s' = SHA512(salt)
        ///   digest = EKS-Blowfish(cost=6), 64× encrypt "OxychromaticBlowfishSwatDynamite" (64 байт)
        ///   берём первые 32 байта и разворачиваем каждое 32-бит слово.
        /// Реализовано через нативную bcryptkdf.dll.
        /// </summary>
        public static byte[] BcryptHash(byte[] password, byte[] salt, int cost = 6)
        {
            using var sha = SHA512.Create();
            byte[] p = sha.ComputeHash(password);
            byte[] s = sha.ComputeHash(salt);
            var out32 = new byte[32];

            int rc = Native.bcrypt_hash_compat_v3(p, p.Length, s, s.Length, cost, out32);
 
        if (rc != 0) throw new InvalidOperationException($"bcrypt_hash_compat_v3 rc={rc}");
        if (rc != 0) throw new InvalidOperationException($"bcrypt_hash_compat failed, rc={rc}");
            return out32;
        }

        /// <summary>
        /// Каркас PBKDF2 с кастомным PRF (hLen=32 для нашего PRF).
        /// </summary>
        public static byte[] PBKDF2_CustomPrf(
            Func<byte[], byte[], byte[]> prf,
            byte[] password, byte[] salt, int dkLen, int iterations)
        {
            const int hLen = 32;
            int l = (int)Math.Ceiling(dkLen / (double)hLen);
            byte[] dk = new byte[l * hLen];

            for (int block = 1; block <= l; block++)
            {
                // S || INT_32_BE(block)
                byte[] saltBlock = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);
                saltBlock[^4] = (byte)(block >> 24);
                saltBlock[^3] = (byte)(block >> 16);
                saltBlock[^2] = (byte)(block >> 8);
                saltBlock[^1] = (byte)(block);

                byte[] u = prf(password, saltBlock);
                byte[] t = (byte[])u.Clone();

                for (int i = 1; i < iterations; i++)
                {
                    u = prf(password, u);
                    for (int j = 0; j < t.Length; j++) t[j] ^= u[j];
                }

                Buffer.BlockCopy(t, 0, dk, (block - 1) * hLen, hLen);
            }

            return dk.Take(dkLen).ToArray();
        }

        /// <summary>
        /// Точный аналог твоей python-функции bcrypt_pbkdf2 со «striding».
        /// </summary>
        public static byte[] PBKDF2_Bcrypt(byte[] password, byte[] salt, int keyLength, int rounds, int cost = 6)
        {
            const int BCRYPT_BLOCKS = 8;
            const int BCRYPT_HASHSIZE = BCRYPT_BLOCKS * 4; // 32
            int strideN = (keyLength + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE; // ceil(keyLen/32)
            int outLen = strideN * BCRYPT_HASHSIZE;

            byte[] full = PBKDF2_CustomPrf(
                (p, s) => BcryptHash(p, s, cost),
                password, salt, outLen, rounds);

            byte[] result = new byte[keyLength];

            for (int i = 0; i < keyLength; i++)
            {
                // ВАЖНО: именно так, как в твоём Python
                int src = (i / strideN) + BCRYPT_HASHSIZE * (i % strideN);

                // (необязательно, но полезно на время отладки)
                if ((uint)src >= (uint)full.Length)
                    throw new IndexOutOfRangeException($"stride mapping bug: src={src}, fullLen={full.Length}");

                result[i] = full[src];
            }
            return result;
        }
    }

    public sealed class SecureCRTCryptoV2
    {
        private readonly byte[] _configPassphraseUtf8;

        public SecureCRTCryptoV2(string configPassphrase = "")
        {
            _configPassphraseUtf8 = Encoding.UTF8.GetBytes(configPassphrase ?? "");
        }

        /// <summary>
        /// Полный порт Python decrypt():
        ///  - prefix "02": ключ = SHA256(passphrase), IV=0^16
        ///  - prefix "03": первые 16 байт = salt, KDF=bcrypt_pbkdf2(pass, salt, 48, 16) -> key||iv
        ///  Далее: AES-256-CBC (без PKCS7), структура [lenLE(4) | plaintext | sha256(32) | pad]
        /// </summary>
        /// 



        public string Decrypt(string hexCiphertext, string prefix = "03")
        {
            if (hexCiphertext is null) throw new ArgumentNullException(nameof(hexCiphertext));
            byte[] all = Bytes.FromHex(hexCiphertext);

            SymmetricAlgorithm aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            ICryptoTransform decryptor;

            if (prefix == "02")
            {
                // key = SHA256(pass), iv = zeros
                using var sha = SHA256.Create();
                byte[] key = sha.ComputeHash(_configPassphraseUtf8);
                byte[] iv = new byte[16]; // zeros
                aes.Key = key;
                aes.IV = iv;
                decryptor = aes.CreateDecryptor();
            }
            else if (prefix == "03")
            {
                if (all.Length < 16) throw new ArgumentException("Bad ciphertext: too short!");
                byte[] salt = all.Take(16).ToArray();
                byte[] ciphertextBytes = all.Skip(16).ToArray();

                // KDF: bcrypt_pbkdf2(pass, salt, 32 + 16, rounds=16)
                byte[] kiv = BcryptCompat.PBKDF2_Bcrypt(_configPassphraseUtf8, salt, 32 + 16, rounds: 16, cost: 6);

                byte[] key = kiv[..32];
                byte[] iv = kiv[32..];

                aes.Key = key;
                aes.IV = iv;
                decryptor = aes.CreateDecryptor();

                // заменяем all на чистый шифротекст без соли
                all = ciphertextBytes;
                Console.WriteLine($"salt = {Bytes.ToHex(salt)}");
                Console.WriteLine($"key  = {Bytes.ToHex(kiv.AsSpan(0, 32).ToArray())}");
                Console.WriteLine($"iv   = {Bytes.ToHex(kiv.AsSpan(32, 16).ToArray())}");
            }
            else
            {
                throw new NotImplementedException($"Unknown prefix: {prefix}");
            }

            if (all.Length % 16 != 0) throw new ArgumentException("Bad ciphertext: not a multiple of block size.");
            byte[] padded = decryptor.TransformFinalBlock(all, 0, all.Length);

            if (padded.Length < 4) throw new ArgumentException("Bad ciphertext: too short for length.");

            uint lenU = Bytes.ReadUInt32LE(padded, 0);

            // Проверим правдоподобность длины без переполнений:
            long payloadLen = 4L + (long)lenU + 32L; // 4 (len) + L + 32 (sha256)
            if (payloadLen < 4L + 32L || payloadLen > int.MaxValue)
                throw new ArgumentException("Bad ciphertext: incorrect plaintext length.");

            // Паддинг «как в Python»: минимум полблока (8), иначе добавляем блок
            long mod = payloadLen % 16L;
            long expectedPad = (16L - mod);
            if (expectedPad == 16L) expectedPad = 16L;  // ровно кратно блоку → всё равно 16 байт паддинга
            if (expectedPad < 8L) expectedPad += 16L;

            if (padded.Length != payloadLen + expectedPad)
                throw new ArgumentException("Bad ciphertext: incorrect padding/length.");

            // Теперь можно безопасно выделять буферы
            int plaintextLen = checked((int)lenU);
            byte[] plaintext = new byte[plaintextLen];
            Buffer.BlockCopy(padded, 4, plaintext, 0, plaintextLen);

            byte[] checksum = new byte[32];
            Buffer.BlockCopy(padded, 4 + plaintextLen, checksum, 0, 32);

            // Проверка sha256
            using var sha256 = SHA256.Create();
            byte[] actualDigest = sha256.ComputeHash(plaintext);
            if (!actualDigest.SequenceEqual(checksum))
                throw new ArgumentException("Bad ciphertext: incorrect sha256 checksum.");

            return Encoding.UTF8.GetString(plaintext);
        }
    }

    // ===== пример использования =====
    internal static class Demo
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"Is64BitProcess = {Environment.Is64BitProcess}");

            // пример: префикс 03 (salt||ciphertext в hex)
            var crypto = new SecureCRTCryptoV2(configPassphrase: "");
            
            try
            {
                string hex = "ea49b80997c45628cc8300fa9c60894eb79803dba1d8f8168cee7587d8314681fe4db810d5032af958177e61a331a49e6849f4038b360320d1be6016e951ebfc9728192a256f8b9dbcee49ec65e14157" /* сюда HEX без пробелов; если у тебя префикс хранится вне HEX, передай prefix="03" */;
                // пример вызова:
                string clear = crypto.Decrypt(hex, prefix: "03");
          
                Console.WriteLine(clear);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
            }
        }
    
}
