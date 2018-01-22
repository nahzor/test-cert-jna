package blah;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import blah.Wincrypt.*;

/** 
 * Crypt32.dll Interface.
 */
public interface Crypt32 extends StdCallLibrary {
	public static final String LIBRARY_NAME = "Crypt32";

	Crypt32 INSTANCE = Native.loadLibrary(LIBRARY_NAME, Crypt32.class, W32APIOptions.DEFAULT_OPTIONS);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560(v=vs.85
	 * ).aspx
	 */
	HANDLE CertOpenSystemStore(Pointer hCryptProv, String psStoreName);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa380281(v=vs.85).
	 * aspx
	 */
	boolean CryptSignMessage(CRYPT_SIGN_MESSAGE_PARA pSignPara, boolean fDetachedSignature, int cToBeSigned,
			PointerByReference rgpbToBeSigned, IntByReference rgcbToBeSigned, Pointer pbSignedBlob,
			IntByReference pcbSignedBlob);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa376078(v=vs.85
	 * ).aspx
	 */
	boolean CertGetCertificateChain(Pointer hChainEngine, CERT_CONTEXT.ByReference pCertContext, Pointer pTime,
			Pointer hAdditionalStore, CERT_CHAIN_PARA.ByReference pChainPara, int dwFlags, Pointer pvReserved,
			PCERT_CHAIN_CONTEXT ppChainContext);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa376075(v=vs.85
	 * ).aspx
	 */
	boolean CertFreeCertificateContext(CERT_CONTEXT pCertContext);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa376026(v=vs.85
	 * ).aspx
	 */
	boolean CertCloseStore(HANDLE hCertStore, int dwFlags);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa376556(v=vs.85
	 * ).aspx
	 */
	int CertNameToStr(int dwCertEncodingType, Pointer pName, int dwStrType, char[] certName, int csz);

	/*
	 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa377163(v=vs.85
	 * ).aspx
	 */
	boolean CertVerifyCertificateChainPolicy(int pszPolicyOID, PCERT_CHAIN_CONTEXT pChainContext,
			CERT_CHAIN_POLICY_PARA.ByReference pPolicyPara, CERT_CHAIN_POLICY_STATUS.ByReference pPolicyStatus);

} // Crypt32
