using System;
using System.IO;
using VirusChecker.COMInterop;

namespace VirusChecker
{
    public enum ScanResult
    {

        VirusNotFound,
        VirusFound,
        FileDoesNotExist
    }

    public class Scanner : IDisposable
    {
        private readonly string _appName;
        private IntPtr _amsiContext = IntPtr.Zero;
        private IntPtr _amsiSession = IntPtr.Zero;

        public Scanner(string appName)
        {
            _appName = appName;
        }
        
        public ScanResult Scan(string path)
        {
            if (AMSI.NativeMethods.AmsiInitialize("VirusScanner", out _amsiContext) == 0)
            {
                if (AMSI.NativeMethods.AmsiOpenSession(_amsiContext, out _amsiSession) == 0)
                {
                    if (!File.Exists(path))
                        return ScanResult.FileDoesNotExist;
                    
                    var bytes = File.ReadAllBytes(path);
                    if (AMSI.NativeMethods.AmsiScanBuffer(_amsiContext, bytes, (ulong)bytes.LongLength, path, _amsiSession, out var result) == 0)
                    {
                        switch (result)
                        {
                            case AMSI.AMSI_RESULT.AMSI_RESULT_NOT_DETECTED:
                            case AMSI.AMSI_RESULT.AMSI_RESULT_CLEAN:
                                return ScanResult.VirusNotFound;
                            case AMSI.AMSI_RESULT.AMSI_RESULT_DETECTED:
                                return ScanResult.VirusFound;
                            default:
                                throw new ArgumentOutOfRangeException();
                        }
                    }
                    
                    AMSI.NativeMethods.AmsiCloseSession(_amsiContext, _amsiSession);
                }

            }
            
            throw new Exception("Unable to initialise AMSI Interface");
        }

        private void ReleaseUnmanagedResources()
        {
            AMSI.NativeMethods.AmsiUninitialize(_amsiContext);
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        ~Scanner()
        {
            ReleaseUnmanagedResources();
        }
    }
}
