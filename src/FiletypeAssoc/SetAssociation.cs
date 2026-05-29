using Microsoft.Win32;
using System;
using Microsoft.Extensions.Logging;
using VL.Core;
using VL.Core.Import;
using VL.Lib.IO;

namespace System.Windows.FiletypeAssociation
{
    /// <summary>
    /// Registers a file type for the current user by writing the classic association keys under
    /// HKEY_CURRENT_USER\Software\Classes. This sets the *fallback* handler: it works when the user
    /// has not yet chosen a default, but will NOT override a default the user already picked. To
    /// force the effective default, use SetFiletypeAssociationProtected instead.
    /// Runs while Execute is true - connect a bang.
    /// </summary>
    [ProcessNode]
    public class SetFiletypeAssociation
    {
        /// <summary>
        /// needed so that Explorer windows get refreshed after the registry is updated
        /// </summary>
        [System.Runtime.InteropServices.DllImport("Shell32.dll")]
        private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

        private const int SHCNE_ASSOCCHANGED = 0x8000000;
        private const int SHCNF_FLUSH = 0x1000;

        private readonly ILogger _logger;
        private bool   _madeChanges;
        private string _lastError = "";

        /// <summary>Initializes the node and acquires a logger from the node context.</summary>
        public SetFiletypeAssociation(NodeContext nodeContext)
        {
            _logger = nodeContext.GetLogger();
        }

        /// <summary>
        /// Registers the fallback file type association for the current user.
        /// Runs while <paramref name="execute"/> is true - connect a bang.
        /// </summary>
        /// <param name="madeChanges">True if this apply actually changed something in the registry (false if it was already set).</param>
        /// <param name="lastError">Message of the last error, or empty if the last apply succeeded.</param>
        /// <param name="applicationFilePath">Path to the program that should open the file, e.g. the vvvv.exe.</param>
        /// <param name="extension">File extension to associate, with the leading dot, e.g. '.foo'.</param>
        /// <param name="progId">Internal identifier registered for this file type, e.g. 'MyApp.foo'. Any unique name; reuse the same one to update an existing association.</param>
        /// <param name="fileTypeDescription">Friendly name shown for the file type in Explorer, e.g. 'My Foo document'.</param>
        /// <param name="execute">While true, (re)applies the association every frame. Connect a bang to do it once.</param>
        public void Update(
            out bool   madeChanges,
            out string lastError,
            Path       applicationFilePath = default,
            string     extension           = ".foo",
            string     progId              = "MyApp.foo",
            string     fileTypeDescription = "",
            bool       execute             = false)
        {
            if (execute)
            {
                _lastError = "";
                try
                {
                    var app = applicationFilePath?.ToString() ?? "";
                    _logger.LogInformation(
                        "SetAssociation: extension={Extension}, progId={ProgId}, description={Description}, app={App}",
                        extension, progId, fileTypeDescription, app);

                    bool changed = false;
                    changed |= SetKeyDefaultValue(@"Software\Classes\" + extension, progId);
                    changed |= SetKeyDefaultValue(@"Software\Classes\" + progId, fileTypeDescription);
                    changed |= SetKeyDefaultValue($@"Software\Classes\{progId}\shell\open\command", "\"" + app + "\" \"%1\"");

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
