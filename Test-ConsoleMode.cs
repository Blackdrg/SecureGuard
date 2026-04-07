// Console test program to verify SecureGuard core functionality works
// This runs without GUI to prove the backend works

using System;
using System.Net;
using System.IO;
using System.Threading;
using SecureGuard.Core;

namespace SecureGuard.ConsoleTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("  SecureGuard Console Test Mode");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            // Test 1: Logger
            Console.Write("[TEST 1] Logger: ");
            try
            {
                Core.Logger.Log("Info", "Test log message");
                Console.WriteLine("PASS");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            // Test 2: Configuration
            Console.Write("[TEST 2] Configuration: ");
            try
            {
                var config = new SecureConfigManager();
                Console.WriteLine("PASS");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            // Test 3: Start local web server
            Console.Write("[TEST 3] Web Server (port 8765): ");
            try
            {
                var server = new LocalWebServer(8765);
                server.Start();
                Thread.Sleep(500);
                
                // Test if server is responding
                var request = WebRequest.Create("http://localhost:8765/api/status");
                request.Timeout = 5000;
                var response = (HttpWebResponse)request.GetResponse();
                
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Console.WriteLine("PASS");
                    Console.WriteLine("       Server responding at http://localhost:8765");
                }
                else
                {
                    Console.WriteLine("FAIL - Unexpected status: " + response.StatusCode);
                }
                
                server.Stop();
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            // Test 4: Signature database
            Console.Write("[TEST 4] Signature Database: ");
            try
            {
                var db = new SignatureDatabase();
                Console.WriteLine("PASS");
                Console.WriteLine("       " + db.GetSignatureCount() + " signatures loaded");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            // Test 5: Quarantine manager
            Console.Write("[TEST 5] Quarantine Manager: ");
            try
            {
                var qm = new QuarantineManager();
                Console.WriteLine("PASS");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            // Test 6: Threat log
            Console.Write("[TEST 6] Threat Log: ");
            try
            {
                var log = new ThreatLogManager();
                Console.WriteLine("PASS");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            // Test 7: Hash computation
            Console.Write("[TEST 7] Hash Utility: ");
            try
            {
                var hash = Core.Hashing.ComputeMD5("test");
                Console.WriteLine("PASS");
                Console.WriteLine("       MD5('test') = " + hash);
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAIL - " + ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("===========================================");
            Console.WriteLine("  All core tests completed!");
            Console.WriteLine("===========================================");
            Console.WriteLine();
            Console.WriteLine("To access the web dashboard:");
            Console.WriteLine("  1. Run: Run-SecureGuard.bat");
            Console.WriteLine("  2. Open: http://localhost:8765");
            Console.WriteLine();
        }
    }
}

