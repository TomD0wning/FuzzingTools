using System;
using System.IO;
using System.Net;
using Newtonsoft.Json.Linq;

namespace FuzzingTools
{
    class MutationalJsonFuzzer
    {

        public static void JsonFuzzer()
        {

            string Url = "http://192.168.0.36/Vulnerable.ashx";//args[0];
            string RequestFile = "/Volumes/Macintosh HD/Users/Tom/Projects/FuzzingTools/VulnCSharpRequestJson.json";//""args[1];
            string[] Request = null;



            using (StreamReader rdr = new StreamReader(File.OpenRead(RequestFile)))
            {
                Request = rdr.ReadToEnd().Split('\n');

                string json = Request[Request.Length - 1];
                JObject obj = JObject.Parse(json);


                Console.WriteLine("Fuzzing POT requests to URL: {0}", Url);

                IterateAndFuzz(Url, obj);

            }

        }

        private static void IterateAndFuzz(string url, JObject obj)
        {
            foreach (var pair in (JObject)obj.DeepClone())
            {
                if (pair.Value.Type == JTokenType.String || pair.Value.Type == JTokenType.Integer)
                {
                    Console.WriteLine("Fuzzing key: {0}", pair.Key);

                    if (pair.Value.Type == JTokenType.Integer)
                        Console.WriteLine("converting int to string to fuzz");

                    JToken oldVal = pair.Value;
                    obj[pair.Key] = pair.Value.ToString() + "'";

                    if (Fuzz(url, obj.Root))
                    {
                        Console.WriteLine("\nSQL injection vector: {0}", pair.Key);
                    }
                    else
                    {
                        Console.WriteLine("\t{0} does not seem vulnerable", pair.Key);
                    }

                    obj[pair.Key] = oldVal;

                }

            }
        }

        private static bool Fuzz(string url, JToken root)
        {
            byte[] data = System.Text.Encoding.ASCII.GetBytes(root.ToString());
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentLength = data.Length;
            req.ContentType = "application/javascript";

            using (Stream stream = req.GetRequestStream())
                stream.Write(data, 0, data.Length);

            try
            {
                req.GetResponse();
            }
            catch (WebException e)
            {
                string resp = String.Empty;
                using (StreamReader r = new StreamReader(e.Response.GetResponseStream()))
                    r.ReadToEnd();
                return (resp.Contains("syntax error") || resp.Contains("unterminated"));
            }
            return false;

        }

    }
}