using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Logging;
using VL.Core;
using VL.Core.Import;
using VL.Lib.IO;

namespace System.Windows.FiletypeAssociation
{
    /// <summary>
    /// Sets the *effective* default handler for a file extension on Windows 10/11 by writing a
    /// valid, hash-protected UserChoice key for the current user (the reverse-engineered SetUserFTA
    /// algorithm). Unlike SetFileAssociations, this overrides an existing UserChoice. Runs while
    /// Execute is true.
    ///
    /// Note: this relies on undocumented Windows internals. It works for normal extensions but not
    /// for types guarded by the UserChoice Protection Driver (UCPD.sys), e.g. browsers and .pdf.
    /// Must run as the interactive user.
    /// </summary>
    [ProcessNode]
    public class SetFiletypeAssociationProtected
    {
        [DllImport("Shell32.dll")]
        private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

        private const int SHCNE_ASSOCCHANGED = 0x8000000;
        private const int SHCNF_FLUSH = 0x1000;

        // Built into Windows as part of the UserChoice hash algorithm (Win10 1803+).
        private const string UserExperience =
            "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}";

        private readonly ILogger _logger;
        private bool   _success;
        private string _writtenHash = "";
        private string _lastError   = "";

        /// <summary>Initializes the node and acquires a logger from the node context.</summary>
        public SetFiletypeAssociationProtected(NodeContext nodeContext)
        {
            _logger = nodeContext.GetLogger();
        }

        /// <summary>
        /// Forces the *effective* default app for a file extension on Windows 10/11 by writing the
        /// hash-protected UserChoice key for the current user. Unlike SetFiletypeAssociation, this
        /// overrides an existing default that the user already picked. Works for normal extensions
        /// (e.g. .vl), but NOT for types Windows guards specially such as browsers and .pdf.
        /// Runs while Execute is true - connect a bang.
        /// </summary>
        /// <param name="success">True if the new default was written and Windows accepted it.</param>
        /// <param name="writtenHash">The Base64 UserChoice hash that was written (diagnostics only).</param>
        /// <param name="lastError">Message of the last error, or empty if the last apply succeeded.</param>
        /// <param name="applicationFilePath">Path to the program that should open the file, e.g. the vvvv.exe.</param>
        /// <param name="extension">File extension to associate, with the leading dot, e.g. '.vl'.</param>
        /// <param name="progId">Internal identifier registered for this file type, e.g. 'vvvv'. Any unique name; reuse the same one to update an existing association.</param>
        /// <param name="fileTypeDescription">Friendly name shown for the file type in Explorer, e.g. 'vvvv gamma document'.</param>
        /// <param name="arguments">What is passed to the program after the .exe path. Use %1 as the placeholder for the double-clicked file. Default "%1" just opens the file; e.g. '-o "%1"' adds a flag in front.</param>
        /// <param name="execute">While true, (re)applies the association every frame. Connect a bang to do it once.</param>
        public void Update(
            out bool   success,
            out string writtenHash,
            out string lastError,
            Path       applicationFilePath = default,
            string     extension           = ".vl",
            string     progId              = "vvvv",
            string     fileTypeDescription = "",
            string     arguments           = "\"%1\"",
            bool       execute             = false)
        {
            if (execute)
            {
                _success     = false;
                _writtenHash = "";
                _lastError   = "";
                try
                {
                    Apply(extension, progId, fileTypeDescription, applicationFilePath?.ToString() ?? "", arguments);
                }
                catch (Exception ex)
                {
                    _lastError = ex.Message;
                    _logger.LogError(ex, "SetAssociationProtected failed for {Extension} -> {ProgId}: {Message}",
                        extension, progId, ex.Message);
                }
            }

            success     = _success;
            writtenHash = _writtenHash;
            lastError   = _lastError;
        }

        private void Apply(string extension, string progId, string description, string app, string arguments)
        {
            var command = $"\"{app}\" {arguments}";
            _logger.LogInformation(
                "SetAssociationProtected: extension={Extension}, progId={ProgId}, command={Command}",
                extension, progId, command);

            // 1) Register the ProgId and its open command, and offer it as a choice for the extension.
            SetKeyDefaultValue(@"Software\Classes\" + progId, description);
            SetKeyDefaultValue($@"Software\Classes\{progId}\shell\open\command", command);
            SetKeyDefaultValue(@"Software\Classes\" + extension, progId);

            // 2) Write the protected UserChoice that actually decides the default.
            var sid = WindowsIdentity.GetCurrent().User!.Value;
            _logger.LogDebug("Current user SID = {Sid}", sid);

            var fileExtsPath = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{extension}";
            using var extKey = Registry.CurrentUser.CreateSubKey(fileExtsPath, writable: true);

            // The existing UserChoice carries a Deny-"SetValue" ACE for the current user. Use
            // DeleteSubKey (not DeleteSubKeyTree): it removes the key and its values in a single
            // operation via the DELETE right, which the user still holds. DeleteSubKeyTree instead
            // deletes each value individually, and RegDeleteValue needs SetValue rights, which are
            // denied. The Deny ACE is not inherited from the parent, so the recreated key is writable.
            extKey.DeleteSubKey("UserChoice", throwOnMissingSubKey: false);
            _logger.LogDebug(@"Removed any existing HKCU\{Path}\UserChoice", fileExtsPath);

            using var ucKey = extKey.CreateSubKey("UserChoice", writable: true);
            ucKey.SetValue("ProgId", progId, RegistryValueKind.String);

            // Compute the hash from the key's own last-write time (rounded to the minute by the
            // algorithm). Writing Hash bumps the last-write time, so re-check and correct once in
            // case the writes straddled a minute boundary.
            var ft   = GetLastWriteTime(ucKey);
            var hash = GenerateUserChoiceHash(extension, sid, progId, ft);
            ucKey.SetValue("Hash", hash, RegistryValueKind.String);

            var ftAfter = GetLastWriteTime(ucKey);
            if (Minute(ftAfter) != Minute(ft))
            {
                hash = GenerateUserChoiceHash(extension, sid, progId, ftAfter);
                ucKey.SetValue("Hash", hash, RegistryValueKind.String);
                _logger.LogDebug("Re-wrote hash after minute boundary.");
            }

            _writtenHash = hash;
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, IntPtr.Zero, IntPtr.Zero);

            // 3) Verify Windows accepts it (it silently reverts an invalid UserChoice).
            using (var verify = extKey.OpenSubKey("UserChoice"))
            {
                var storedProgId = verify?.GetValue("ProgId") as string;
                var storedHash   = verify?.GetValue("Hash") as string;
                _success = string.Equals(storedProgId, progId, StringComparison.OrdinalIgnoreCase)
                           && storedHash == hash;
            }

            if (_success)
                _logger.LogInformation(
                    "SetAssociationProtected: UserChoice written and verified. {Extension} -> {ProgId}, hash={Hash}",
                    extension, progId, _writtenHash);
            else
                _logger.LogWarning(
                    "SetAssociationProtected: UserChoice did not stick - Windows may have rejected the hash for {Extension}.",
                    extension);
        }

        private string GenerateUserChoiceHash(string extension, string sid, string progId, FILETIME ft)
        {
            // Round to the minute: FILETIME -> SYSTEMTIME (zero seconds/ms) -> FILETIME.
            FileTimeToSystemTime(in ft, out var st);
            st.wSecond = 0;
            st.wMilliseconds = 0;
            SystemTimeToFileTime(in st, out var ftRounded);

            var input = (extension + sid + progId
                         + ftRounded.dwHighDateTime.ToString("x8")
                         + ftRounded.dwLowDateTime.ToString("x8")
                         + UserExperience).ToLowerInvariant();

            var bytes = Encoding.Unicode.GetBytes(input + "\0"); // include null terminator like the native impl
            return HashString(bytes);
        }

        // Reverse-engineered UserChoice hash. Ported from Mozilla's WindowsUserChoice.cpp (MPL 2.0),
        // itself based on PS-SFTA / SetUserFTA. Constants are part of the Windows algorithm.
        private static string HashString(byte[] bytes)
        {
            const int blockSize = 8; // 2 DWORDs
            int blockCount = bytes.Length / blockSize; // incomplete blocks are ignored
            if (blockCount == 0)
                throw new InvalidOperationException("UserChoice hash input too short");

            var md5 = MD5.HashData(bytes);
            uint md0 = BitConverter.ToUInt32(md5, 0);
            uint md1 = BitConverter.ToUInt32(md5, 4);

            uint[][] c0 =
            {
                new[] { md0 | 1, 0xCF98B111u, 0x87085B9Fu, 0x12CEB96Du, 0x257E1D83u },
                new[] { md1 | 1, 0xA27416F5u, 0xD38396FFu, 0x7C932B89u, 0xBFA49F69u }
            };
            uint[][] c1 =
            {
                new[] { md0 | 1, 0xEF0569FBu, 0x689B6B9Fu, 0x79F8A395u, 0xC3EFEA97u },
                new[] { md1 | 1, 0xC31713DBu, 0xDDCD1F0Fu, 0x59C3AF2Du, 0x35BD1EC9u }
            };

            uint h0 = 0, h1 = 0, h0Acc = 0, h1Acc = 0;
            unchecked
            {
                for (int i = 0; i < blockCount; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        var a = c0[j];
                        var b = c1[j];
                        uint input = BitConverter.ToUInt32(bytes, (i * 2 + j) * 4);

                        h0 += input;
                        h0 *= a[0];
                        h0 = WordSwap(h0) * a[1];
                        h0 = WordSwap(h0) * a[2];
                        h0 = WordSwap(h0) * a[3];
                        h0 = WordSwap(h0) * a[4];
                        h0Acc += h0;

                        h1 += input;
                        h1 = WordSwap(h1) * b[1] + h1 * b[0];
                        h1 = (h1 >> 16) * b[2] + h1 * b[3];
                        h1 = WordSwap(h1) * b[4] + h1;
                        h1Acc += h1;
                    }
                }
            }

            var outBytes = new byte[8];
            BitConverter.GetBytes(h0 ^ h1).CopyTo(outBytes, 0);
            BitConverter.GetBytes(h0Acc ^ h1Acc).CopyTo(outBytes, 4);
            return Convert.ToBase64String(outBytes);
        }

        private static uint WordSwap(uint v) => (v >> 16) | (v << 16);

        private static long Minute(FILETIME ft) =>
            ((long)ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 600_000_000L; // 100ns ticks per minute

        private void SetKeyDefaultValue(string keyPath, string value)
        {
            using var key = Registry.CurrentUser.CreateSubKey(keyPath);
            var current = key.GetValue(null) as string;
            if (current != value)
            {
                key.SetValue(null, value);
                _logger.LogDebug(@"Set HKCU\{KeyPath} (default) = '{Value}' (was '{Old}')", keyPath, value, current ?? "<null>");
            }
            else
            {
                _logger.LogDebug(@"HKCU\{KeyPath} (default) already = '{Value}', skipped", keyPath, value);
            }
        }

        private static FILETIME GetLastWriteTime(RegistryKey key)
        {
            int rc = RegQueryInfoKey(key.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, out var ft);
            if (rc != 0)
                throw new InvalidOperationException($"RegQueryInfoKey failed with code {rc}");
            return ft;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEMTIME
        {
            public ushort wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds;
        }

        [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKeyW")]
        private static extern int RegQueryInfoKey(
            SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
            IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen,
            IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
            IntPtr lpcbSecurityDescriptor, out FILETIME lpftLastWriteTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FileTimeToSystemTime(in FILETIME lpFileTime, out SYSTEMTIME lpSystemTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SystemTimeToFileTime(in SYSTEMTIME lpSystemTime, out FILETIME lpFileTime);
    }
}
