package blah;

import static com.sun.jna.Library.OPTION_FUNCTION_MAPPER;
import static com.sun.jna.Library.OPTION_TYPE_MAPPER;

import java.util.HashMap;
import java.util.Map;

import com.sun.jna.Native;
import com.sun.jna.PointerType;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIFunctionMapper;
import com.sun.jna.win32.W32APITypeMapper;

import blah.Wincrypt.*;

/** 
 * Cryptui.dll Interface.
 */
public interface Cryptui extends StdCallLibrary {
    public static final String LIBRARY_NAME = "Cryptui";

    Cryptui INSTANCE = (Cryptui) Native.loadLibrary(LIBRARY_NAME, Cryptui.class, Options.UNICODE_OPTIONS);

    /**
     *  https://msdn.microsoft.com/en-us/library/windows/desktop/aa380288(v=vs.85).aspx
     */
    CERT_CONTEXT CryptUIDlgSelectCertificateFromStore(HANDLE hCertStore, int hwnd, String title,
            String displayName, int dontUseColumn, int flags, PointerType reserved);

    public interface Options {
        Map<String, Object> UNICODE_OPTIONS = new HashMap<String, Object>() {
            {
                put(OPTION_TYPE_MAPPER, W32APITypeMapper.UNICODE);
                put(OPTION_FUNCTION_MAPPER, W32APIFunctionMapper.UNICODE);
            }
        };
    }
    
}