using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;
using VL.Core;
using VL.Core.Import;

namespace System.Windows.FiletypeAssociation
{
    /// <summary>
    /// Asks Windows what is associated with a file extension or protocol - the program that opens it,
    /// its friendly name, default icon, content type, etc. Pick the kind of info with the Association
    /// pin. Runs while Execute is true - connect a bang.
    /// </summary>
    [ProcessNode]
    public class GetFiletypeAssociation
    {
        private readonly ILogger _logger;
        private string _result    = "";
        private string _lastError = "";

        /// <summary>Initializes the node and acquires a logger from the node context.</summary>
        public GetFiletypeAssociation(NodeContext nodeContext)
        {
            _logger = nodeContext.GetLogger();
        }

        /// <summary>
        /// Looks up the requested association info for an extension or protocol.
        /// Runs while <paramref name="execute"/> is true - connect a bang.
        /// </summary>
        /// <param name="result">The looked-up value from the last successful query, or empty.</param>
        /// <param name="lastError">Message of the last error (e.g. when no association exists), or empty on success.</param>
        /// <param name="association">Which piece of info to return: Executable = path to the opening program, FriendlyAppName = its display name, DefaultIcon, ContentType (MIME), Command, etc.</param>
        /// <param name="extension">File extension to look up, with the leading dot, e.g. '.txt'. Can also be a protocol like 'http'.</param>
        /// <param name="execute">While true, queries every frame. Connect a bang to do it once.</param>
        public void Update(
            out string result,
            out string lastError,
            AssocStr   association = AssocStr.Executable,
            string     extension   = ".foo",
            bool       execute     = false)
        {
            if (execute)
            {
                _lastError = "";
                try
                {
                    _result = AssocQueryString(association, extension);
                }
                catch (Exception ex)
                {
                    _lastError = ex.Message;
                    _logger.LogError(ex, "GetFiletypeAssociation failed for {Association}, {Extension}: {Message}", association, extension, ex.Message);
                }
            }

            result    = _result;
            lastError = _lastError;
        }

        /// <summary>
        /// Returns the association string of the requested kind for the given extension or protocol.
        /// </summary>
        /// <param name="association">Which associated string to retrieve (e.g. Executable, FriendlyAppName, DefaultIcon).</param>
        /// <param name="extension">File extension (e.g. '.txt') or protocol to query.</param>
        public string AssocQueryString(AssocStr association, string extension)
        {
            const int S_OK = 0;
            const int S_FALSE = 1;

            uint length = 0;
            uint ret = AssocQueryString(AssocF.None, association, extension, null, null, ref length);
            if (ret != S_FALSE)
            {
                _logger.LogWarning(
                    "AssocQueryString({Association}, {Extension}): length probe returned 0x{Ret:X8} (expected S_FALSE) - no association found.",
                    association, extension, ret);
                throw new InvalidOperationException("Could not determine associated string");
            }

            var sb = new StringBuilder((int)length); // (length-1) will probably work too as the marshaller adds null termination
            ret = AssocQueryString(AssocF.None, association, extension, null, sb, ref length);
            if (ret != S_OK)
            {
                _logger.LogWarning(
                    "AssocQueryString({Association}, {Extension}): value query returned 0x{Ret:X8} (expected S_OK).",
                    association, extension, ret);
                throw new InvalidOperationException("Could not determine associated string");
            }

            var result = sb.ToString();
            _logger.LogDebug("AssocQueryString({Association}, {Extension}) = '{Result}'", association, extension, result);
            return result;
        }


        [DllImport("Shlwapi.dll", CharSet = CharSet.Unicode)]
        public static extern uint AssocQueryString(
        AssocF flags,
        AssocStr str,
        string pszAssoc,
        string pszExtra,
        [Out] StringBuilder pszOut,
        ref uint pcchOut
    );

        [Flags]
        public enum AssocF
        {
            None = 0,
            Init_NoRemapCLSID = 0x1,
            Init_ByExeName = 0x2,
            Open_ByExeName = 0x2,
            Init_DefaultToStar = 0x4,
            Init_DefaultToFolder = 0x8,
            NoUserSettings = 0x10,
            NoTruncate = 0x20,
            Verify = 0x40,
            RemapRunDll = 0x80,
            NoFixUps = 0x100,
            IgnoreBaseClass = 0x200,
            Init_IgnoreUnknown = 0x400,
            Init_Fixed_ProgId = 0x800,
            Is_Protocol = 0x1000,
            Init_For_File = 0x2000
        }

        public enum AssocStr
        {
            Command = 1,
            Executable,
            FriendlyDocName,
            FriendlyAppName,
            NoOpen,
            ShellNewValue,
            DDECommand,
            DDEIfExec,
            DDEApplication,
            DDETopic,
            InfoTip,
            QuickTip,
            TileInfo,
            ContentType,
            DefaultIcon,
            ShellExtension,
            DropTarget,
            DelegateExecute,
            Supported_Uri_Protocols,
            ProgID,
            AppID,
            AppPublisher,
            AppIconReference,
            Max
        }
    }
}
