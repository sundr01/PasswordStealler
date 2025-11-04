using SecureCRTCompat;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SCRTPasswordStealler.iniParser;
using System.Net.NetworkInformation;

internal static class Root
{


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

        public static byte[] BcryptHash(byte[] password, byte[] salt, int cost = 6)
        {
            using var sha = SHA512.Create();
            byte[] p = sha.ComputeHash(password);
            byte[] s = sha.ComputeHash(salt);
            var out32 = new byte[32];

            int rc = BcryptCompatManagedSalfe.bcrypt_hash_compat_v3(p, p.Length, s, s.Length, cost, out32);

            if (rc != 0) throw new InvalidOperationException($"bcrypt_hash_compat_v3 rc={rc}");
            if (rc != 0) throw new InvalidOperationException($"bcrypt_hash_compat failed, rc={rc}");
            return out32;
        }

        /// <summary>
        /// Каркас PBKDF2 с кастомным PRF 
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
              
                int src = (i / strideN) + BCRYPT_HASHSIZE * (i % strideN);

        


                result[i] = full[src];
            }
            return result;
        }
    }

    public sealed class SecureCRTCryptoV2
    {
        private readonly byte[] _configPassphraseUtf8;

        public SecureCRTCryptoV2(string configPassphrase)
        {
            _configPassphraseUtf8 = Encoding.UTF8.GetBytes(configPassphrase);
        }

        /// <summary>
        ///  - prefix "02": ключ = SHA256(passphrase), IV=0^16
        ///  - prefix "03": первые 16 байт = salt, KDF=bcrypt_pbkdf2(pass, salt, 48, 16) -> key||iv
        ///   AES-256-CBC (без PKCS7), структура [lenLE(4) | plaintext | sha256(32) | pad]
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
                //Console.WriteLine($"salt = {Bytes.ToHex(salt)}");
                //Console.WriteLine($"key  = {Bytes.ToHex(kiv.AsSpan(0, 32).ToArray())}");
                //Console.WriteLine($"iv   = {Bytes.ToHex(kiv.AsSpan(32, 16).ToArray())}");
            }
            else
            {
                throw new NotImplementedException($"Unknown prefix: {prefix}");
            }

            if (all.Length % 16 != 0) throw new ArgumentException("Bad ciphertext: not a multiple of block size.");
            byte[] padded = decryptor.TransformFinalBlock(all, 0, all.Length);

            if (padded.Length < 4) throw new ArgumentException("Bad ciphertext: too short for length.");

            uint lenU = Bytes.ReadUInt32LE(padded, 0);


            long payloadLen = 4L + (long)lenU + 32L; 
            if (payloadLen < 4L + 32L || payloadLen > int.MaxValue)
                throw new ArgumentException("Bad ciphertext: incorrect plaintext length.");

            
            long mod = payloadLen % 16L;
            long expectedPad = (16L - mod);
            if (expectedPad == 16L) expectedPad = 16L; 
            if (expectedPad < 8L) expectedPad += 16L;

            if (padded.Length != payloadLen + expectedPad)
                throw new ArgumentException("Bad ciphertext: incorrect padding/length.");


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


    internal static class Demo
    {
        static void Main(string[] args)
        {
            //Console.WriteLine($"Is64BitProcess = {Environment.Is64BitProcess}");
            string pathToIniFolder = "";
            string masterPassword = "";
            string prefix = "03";

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-p" && i + 1 < args.Length)
                {
                    pathToIniFolder = args[i + 1];
                    i++;
                }
                else if (args[i] == "-master" && i + 1 < args.Length)
                {
                    masterPassword = args[i + 1];
                    i++;
                }
                else if (args[i] == "-prefix" && i + 1 < args.Length)
                {
                    prefix = args[i + 1];
                    i++;
                }
            }
            //Directoyies directoyies = new Directoyies("");
            IniFilesPath files = new IniFilesPath(pathToIniFolder);
            List<Connection> connections = files.ParserConnections();
            

            var crypto = new SecureCRTCryptoV2(masterPassword);

            try
            {
                foreach(Connection connection in connections)
                {
                    string hex = connection.password;

                    string clear = crypto.Decrypt(hex, prefix);

                    Console.WriteLine(clear);
                }
                
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
            }
        }

    }
    }
