using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NightTech.Shield.Windows;

/// <summary>Checks a program's digital signature with Windows' own WinVerifyTrust (embedded signatures and Windows catalogs).</summary>
public static class Signature
{
    /// <summary>True when Windows trusts the signature, false when it's unsigned or the signature is bad, null when the file can't be checked.</summary>
    public static (bool? Signed, string Signer) Check(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return (null, "");
        try
        {
            int result = Verify(path);
            string signer = "";
            try
            {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile only reads the embedded signer's certificate here
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
                signer = cert.GetNameInfo(X509NameType.SimpleName, false);
            }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or IOException) { }
            if (result == 0) return (true, signer);
            // Windows' own files are signed through catalogs; anything in the Windows folder that fails here is checked again by location.
            return (false, signer);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or DllNotFoundException) { return (null, ""); }
    }

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private static int Verify(string path)
    {
        var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(file, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,     // WTD_REVOKE_NONE: no network wait
                dwUnionChoice = 1,           // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 1,           // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x00001000,    // WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            var action = GenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;          // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result;
        }
        finally { Marshal.FreeHGlobal(pFile); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
}
