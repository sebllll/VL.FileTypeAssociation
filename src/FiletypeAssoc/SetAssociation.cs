using Microsoft.Win32;
using System;
using Microsoft.Extensions.Logging;
using VL.Core;
using VL.Core.Import;

namespace FiletypeAssoc
{
    /// <summary>
    /// Sets a Windows file type association for the current user by writing the relevant keys
    /// under HKEY_CURRENT_USER\Software\Classes and notifying the shell. Triggered on the rising
    /// edge of Set.
    /// </summary>
    [ProcessNode]
    public class SetFileAssociations
    {
        /// <summary>
        /// needed so that Explorer windows get refreshed after the registry is updated
        /// </summary>
        [System.Runtime.InteropServices.DllImport("Shell32.dll")]
        private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

        private const int SHCNE_ASSOCCHANGED = 0x8000000;
        private const int SHCNF_FLUSH = 0x1000;

        private readonly ILogger _logger;
        private bool   _lastSet;
        private bool   _madeChanges;
        private string _lastError = "";

        /// <summary>Initializes the node and acquires a logger from the node context.</summary>
        public SetFileAssociations(NodeContext nodeContext)
        {
            _logger = nodeContext.GetLogger();
        }

        /// <summary>
        /// Set a FileType Association for the current user. Triggers on the rising edge of <paramref name="set"/>.
        /// </summary>
        /// <param name="madeChanges">True if the last apply actually wrote to the registry.</param>
        /// <param name="lastError">Error message from the last failed apply, or empty on success.</param>
        /// <param name="extension">File extension to associate, including the leading dot, e.g. '.foo'.</param>
        /// <param name="progId">Programmatic identifier (ProgId) to register for the extension, e.g. 'MyApp.foo'.</param>
        /// <param name="fileTypeDescription">Human-readable description shown for the file type.</param>
        /// <param name="applicationFilePath">Full path to the executable that opens the file.</param>
        /// <param name="set">Bang to apply the association. Triggers on rising edge only.</param>
        public void Update(
            out bool   madeChanges,
            out string lastError,
            string     extension           = ".foo",
            string     progId              = "MyApp.foo",
            string     fileTypeDescription = "",
            string     applicationFilePath = "",
            bool       set                 = false)
        {
            if (set && !_lastSet)
            {
                _lastError = "";
                try
                {
                    _logger.LogInformation(
                        "SetAssociation: extension={Extension}, progId={ProgId}, description={Description}, app={App}",
                        extension, progId, fileTypeDescription, applicationFilePath);

                    bool changed = false;
                    changed |= SetKeyDefaultValue(@"Software\Classes\" + extension, progId);
                    changed |= SetKeyDefaultValue(@"Software\Classes\" + progId, fileTypeDescription);
                    changed |= SetKeyDefaultValue($@"Software\Classes\{progId}\shell\open\command", "\"" + applicationFilePath + "\" \"%1\"");

                    if (changed)
                    {
                        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, IntPtr.Zero, IntPtr.Zero);
                        _logger.LogInformation("SetAssociation: registry updated, notified shell via SHChangeNotify.");
                    }
                    else
                    {
                        _logger.LogInformation("SetAssociation: no changes needed, registry already up to date.");
                    }

                    _madeChanges = changed;
                }
                catch (Exception ex)
                {
                    _madeChanges = false;
                    _lastError   = ex.Message;
                    _logger.LogError(ex, "SetAssociation failed for {Extension} -> {ProgId}: {Message}", extension, progId, ex.Message);
                }
            }
            _lastSet = set;

            madeChanges = _madeChanges;
            lastError   = _lastError;
        }

        private bool SetKeyDefaultValue(string keyPath, string value)
        {
            using (var key = Registry.CurrentUser.CreateSubKey(keyPath))
            {
                var current = key.GetValue(null) as string;
                if (current != value)
                {
                    key.SetValue(null, value);
                    _logger.LogDebug(@"Set HKCU\{KeyPath} (default) = '{Value}' (was '{Old}')", keyPath, value, current ?? "<null>");
                    return true;
                }

                _logger.LogDebug(@"HKCU\{KeyPath} (default) already = '{Value}', skipped", keyPath, value);
                return false;
            }
        }
    }
}
