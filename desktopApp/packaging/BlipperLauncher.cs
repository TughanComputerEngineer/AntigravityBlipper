using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("AntigravityBlipper")]
[assembly: AssemblyDescription("AntigravityBlipper Zero-Trust Desktop Launcher")]
[assembly: AssemblyCompany("AntigravityBlipper")]
[assembly: AssemblyProduct("AntigravityBlipper")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace AntigravityBlipperLauncher
{
    internal static class Program
    {
        private const string EmbeddedResourceName = "blipper.jar";
        private const int LoopbackHookPort = 49871;

        [STAThread]
        private static int Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                if (IsAlreadyRunningOnLoopback())
                {
                    MessageBox.Show(
                        "AntigravityBlipper zaten arka planda çalışıyor!\n\n" +
                        "Sağ alt sistem tepsisindeki (System Tray) mavi şimşek ikonuna tıklayarak Kontrol Panelini açabilirsiniz.",
                        "AntigravityBlipper Aktif",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );
                    return 0;
                }

                string javawExe = LocateJava21Javaw();
                if (string.IsNullOrEmpty(javawExe) || !File.Exists(javawExe))
                {
                    MessageBox.Show(
                        "Java 21 (OpenJDK 21 / Android Studio JBR) bulunamadı!\n\n" +
                        "Lütfen Android Studio JBR veya OpenJDK 21 kurulu olduğundan emin olun.",
                        "AntigravityBlipper — Java 21 Gerekli",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return 1;
                }

                string jarPath = ResolveOrExtractJar();
                string runtimeDir = Path.GetDirectoryName(jarPath) ?? Environment.CurrentDirectory;

                var psi = new ProcessStartInfo
                {
                    FileName = javawExe,
                    Arguments = "-Dfile.encoding=UTF-8 -jar \"" + jarPath + "\"",
                    WorkingDirectory = runtimeDir,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process.Start(psi);
                return 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "AntigravityBlipper başlatılırken hata oluştu:\n\n" + ex.Message,
                    "AntigravityBlipper Başlatma Hatası",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }
        }

        private static bool IsAlreadyRunningOnLoopback()
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect("127.0.0.1", LoopbackHookPort, null, null);
                    bool connected = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(250));
                    if (connected && client.Connected)
                    {
                        client.EndConnect(result);
                        return true;
                    }
                }
            }
            catch
            {
                // Port not open -> not running yet
            }
            return false;
        }

        private static string ResolveOrExtractJar()
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string siblingBuildJar = Path.Combine(exeDir, "desktopApp", "build", "libs", "blipper-desktop-1.0.0.jar");
            if (File.Exists(siblingBuildJar))
            {
                return siblingBuildJar;
            }

            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream res = asm.GetManifestResourceStream(EmbeddedResourceName))
            {
                if (res == null)
                {
                    throw new FileNotFoundException("Gömülü uygulama paketi (blipper.jar) bulunamadı.");
                }

                byte[] jarBytes;
                using (var ms = new MemoryStream())
                {
                    res.CopyTo(ms);
                    jarBytes = ms.ToArray();
                }

                string hashPrefix;
                using (var sha = SHA256.Create())
                {
                    byte[] digest = sha.ComputeHash(jarBytes);
                    var sb = new StringBuilder(16);
                    for (int i = 0; i < 8; i++)
                    {
                        sb.Append(digest[i].ToString("x2"));
                    }
                    hashPrefix = sb.ToString();
                }

                string cacheDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AntigravityBlipper",
                    "runtime"
                );
                Directory.CreateDirectory(cacheDir);

                string targetJar = Path.Combine(cacheDir, "blipper-desktop-" + hashPrefix + ".jar");
                if (!File.Exists(targetJar) || new FileInfo(targetJar).Length != jarBytes.Length)
                {
                    string tempJar = targetJar + ".tmp-" + Guid.NewGuid().ToString("N");
                    File.WriteAllBytes(tempJar, jarBytes);
                    if (File.Exists(targetJar))
                    {
                        File.Delete(targetJar);
                    }
                    File.Move(tempJar, targetJar);
                }

                return targetJar;
            }
        }

        private static string LocateJava21Javaw()
        {
            string studioJbr = @"C:\Program Files\Android\Android Studio\jbr";
            if (IsJava21OrNewerHome(studioJbr))
            {
                return Path.Combine(studioJbr, "bin", "javaw.exe");
            }

            string envJavaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
            if (!string.IsNullOrWhiteSpace(envJavaHome) && IsJava21OrNewerHome(envJavaHome))
            {
                return Path.Combine(envJavaHome, "bin", "javaw.exe");
            }

            string[] searchRoots = new[]
            {
                @"C:\Program Files\Eclipse Adoptium",
                @"C:\Program Files\Java",
                @"C:\Program Files\Microsoft",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".jdks")
            };

            foreach (string root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string dir in Directory.GetDirectories(root))
                    {
                        if (IsJava21OrNewerHome(dir))
                        {
                            return Path.Combine(dir, "bin", "javaw.exe");
                        }
                    }
                }
                catch
                {
                    // Ignore inaccessible directories
                }
            }

            return null;
        }

        private static bool IsJava21OrNewerHome(string jdkHome)
        {
            if (string.IsNullOrWhiteSpace(jdkHome)) return false;
            string javaw = Path.Combine(jdkHome, "bin", "javaw.exe");
            if (!File.Exists(javaw)) return false;

            string releaseFile = Path.Combine(jdkHome, "release");
            if (!File.Exists(releaseFile)) return true;

            try
            {
                foreach (string line in File.ReadAllLines(releaseFile, Encoding.UTF8))
                {
                    if (line.StartsWith("JAVA_VERSION=\"", StringComparison.OrdinalIgnoreCase))
                    {
                        string ver = line.Substring("JAVA_VERSION=\"".Length).TrimEnd('"');
                        string majorPart = ver.Split('.')[0];
                        int major;
                        if (int.TryParse(majorPart, out major))
                        {
                            return major >= 21;
                        }
                    }
                }
            }
            catch
            {
                return true;
            }
            return false;
        }
    }
}
