
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import blah.Advapi32;
import blah.Crypt32;
import blah.Cryptui;
import blah.Wincrypt;
import blah.Wincrypt.*;

public class TestCertJna {
   public static void main(String[] args) {
	   
//	   certChainTest();
	   createSSCert();
	   
   }
   
   public static void createSSCert() {
		String pszCertificateSubjectName = "CN=Test Subject";
		int err = 0;
		IntByReference dwSize =  new IntByReference();
		boolean n2s1 = Crypt32.INSTANCE.CertStrToName(
			Wincrypt.X509_ASN_ENCODING,
			pszCertificateSubjectName,
			2,
			Pointer.NULL,
			Pointer.NULL,
		    dwSize,
		    Pointer.NULL
		);
		
		Pointer p = new Memory(dwSize.getValue()*2);
		boolean n2s2 = Crypt32.INSTANCE.CertStrToName(
			Wincrypt.X509_ASN_ENCODING,
			pszCertificateSubjectName,
			2,
			Pointer.NULL,
			p,
			dwSize,
			Pointer.NULL
		);

		DATA_BLOB sib = new DATA_BLOB();
		sib.cbData = dwSize.getValue();
		sib.pbData = p;

		String pszKeyContainerName = "Test Container Name";
		
		int CRYPT_NEWKEYSET     =    0x00000008;
		int CRYPT_MACHINE_KEYSET = 0x00000020;
		
		PointerByReference p1 = new PointerByReference();
		boolean context = Advapi32.INSTANCE.CryptAcquireContext(
				p1,
				pszKeyContainerName,
				null,
				1,
				CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET
			);

		Pointer ptr = p1.getPointer();
		HANDLE hProv = new HANDLE(ptr);
		
		CRYPT_KEY_PROV_INFO kpi = new CRYPT_KEY_PROV_INFO();
		kpi.pwszContainerName = pszKeyContainerName;
		kpi.pwszProvName = "Microsoft Base Cryptographic Provider v1.0";
		kpi.dwProvType = 1;
		kpi.dwFlags = 1;
		kpi.dwKeySpec = 1;
		
		PointerByReference hKey = new PointerByReference();
		boolean keygen = Advapi32.INSTANCE.CryptGenKey(hProv, 1, 1, hKey);
				
		CERT_EXTENSIONS exts = new CERT_EXTENSIONS();

		CERT_CONTEXT.ByReference pc = Crypt32.INSTANCE.CertCreateSelfSignCertificate(
			hProv,
			sib,
			0,
			kpi,
			null,
			null,
			null,
			exts
		);
		
		System.out.println(pc.toString());
		
		}
   
   public static void certChainTest() {
	   System.out.println("test");
	   
	   // Works
	   HANDLE handle = Crypt32.INSTANCE.CertOpenSystemStore(Pointer.NULL, "MY");
	   
           System.out.println(handle);
           
	   // Works
		CERT_CONTEXT context = Cryptui.INSTANCE.CryptUIDlgSelectCertificateFromStore(handle, 0,
				"", "", 2, 0, null);
		
                System.out.println(context);
                
		CERT_CHAIN_CONTEXT pChainContext = new CERT_CHAIN_CONTEXT();
		CERT_CHAIN_PARA pChainPara = new CERT_CHAIN_PARA();
		
		pChainPara.cbSize = pChainPara.size();
		pChainPara.RequestedUsage.dwType = Wincrypt.USAGE_MATCH_TYPE_AND;
		pChainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
		pChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = null;
		pChainPara.RequestedIssuancePolicy.Usage.cUsageIdentifier = 0;
		pChainPara.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = null;

		pChainPara.dwUrlRetrievalTimeout = 0;
		pChainPara.fCheckRevocationFreshnessTime = false;
		pChainPara.dwRevocationFreshnessTime = 0;
		pChainPara.pftCacheResync.dwHighDateTime = 0;
		pChainPara.pftCacheResync.dwLowDateTime = 0;

		pChainPara.pStrongSignPara = null;

		// Does not work
		Crypt32.INSTANCE.CertGetCertificateChain(null, context, null, null, pChainPara, 0, null, pChainContext);

                System.out.println(pChainContext);
                
		CERT_CHAIN_POLICY_PARA ChainPolicyPara = new CERT_CHAIN_POLICY_PARA();
		CERT_CHAIN_POLICY_STATUS PolicyStatus = new CERT_CHAIN_POLICY_STATUS();

		ChainPolicyPara.cbSize = ChainPolicyPara.size();
		ChainPolicyPara.dwFlags = 0;

		PolicyStatus.cbSize = PolicyStatus.size();

		// Works
		boolean result = Crypt32.INSTANCE.CertVerifyCertificateChainPolicy(Wincrypt.CERT_CHAIN_POLICY_BASE, pChainContext,
				ChainPolicyPara, PolicyStatus);
		
                System.out.println(result);
                System.out.println(PolicyStatus);
                
		System.out.println("test");
   }
}
