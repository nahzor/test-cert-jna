package blah;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Union;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.GUID;
import com.sun.jna.platform.win32.WTypes.LPSTR;
import com.sun.jna.platform.win32.WTypes.LPWSTR;
import com.sun.jna.platform.win32.WinCrypt.DATA_BLOB;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.PointerByReference;

import java.util.Arrays;
import java.util.List;

/**
 * Ported from WinCrypt.h.
 */
public interface Wincrypt {

	/**
	 * Message Encoding Types
	 * 
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa376511(v=vs.85).aspx">MSDN</a>
	 */
	int CRYPT_ASN_ENCODING = 0x00000001;

	/**
	 * Message Encoding Types
	 * 
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa376511(v=vs.85).aspx">MSDN</a>
	 */
	int CRYPT_NDR_ENCODING = 0x00000002;

	/**
	 * Message Encoding Types
	 * 
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa376511(v=vs.85).aspx">MSDN</a>
	 */
	int X509_ASN_ENCODING = 0x00000001;

	/**
	 * Message Encoding Types
	 * 
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa376511(v=vs.85).aspx">MSDN</a>
	 */
	int X509_NDR_ENCODING = 0x00000002;

	/**
	 * Message Encoding Types
	 * 
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa376511(v=vs.85).aspx">MSDN</a>
	 */
	int PKCS_7_ASN_ENCODING = 0x00010000;

	/**
	 * Message Encoding Types
	 * 
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa376511(v=vs.85).aspx">MSDN</a>
	 */
	int PKCS_7_NDR_ENCODING = 0x00020000;

	/**
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa377593(v=vs.85).aspx">MSDN</a>
	 */
	int USAGE_MATCH_TYPE_AND = 0x00000000;

	/**
	 * @see <a href=
	 *      "https://msdn.microsoft.com/en-us/library/windows/desktop/aa377593(v=vs.85).aspx">MSDN</a>
	 */
	int USAGE_MATCH_TYPE_OR = 0x00000001;

	/**
	 * CryptSetProvParam
	 */
	int PP_CLIENT_HWND = 1;

	/**
	 * Certificate name string types
	 */
	int CERT_SIMPLE_NAME_STR = 1;
	int CERT_OID_NAME_STR = 2;
	int CERT_X500_NAME_STR = 3;
	int CERT_XML_NAME_STR = 4;

	/**
	 * Predefined verify chain policies
	 */
	int CERT_CHAIN_POLICY_BASE = 1;

	/**
	 * Following are the definitions of various algorithm object identifiers RSA
	 */
	String szOID_RSA_SHA1RSA = "1.2.840.113549.1.1.5";

	public static class CERT_TRUST_STATUS extends Structure {

		public int dwErrorStatus;
		public int dwInfoStatus;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwErrorStatus", "dwInfoStatus");
		}
	}

	public static class CTL_ENTRY extends Structure {
		public DATA_BLOB SubjectIdentifier; // For example, its hash
		public int cAttribute;
		public CRYPT_ATTRIBUTE.ByReference rgAttribute; // OPTIONAL

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("SubjectIdentifier", "cAttribute", "rgAttribute");
		}

		public static class ByReference extends CTL_ENTRY implements Structure.ByReference {
		}
	}

	public static class CERT_REVOCATION_CRL_INFO extends Structure {
		public int cbSize;
		public CRL_CONTEXT.ByReference pBaseCRLContext;
		public CRL_CONTEXT.ByReference pDeltaCRLContext;
		public CRL_ENTRY.ByReference pCrlEntry;
		public boolean fDeltaCrlEntry;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "pBaseCRLContext", "pDeltaCRLContext", "pCrlEntry", "fDeltaCrlEntry");
		}

		public static class ByReference extends CTL_ENTRY implements Structure.ByReference {
		}
	}

	public static class CERT_REVOCATION_INFO extends Structure {
		public int cbSize;
		public int dwRevocationResult;
		public LPSTR pszRevocationOid;
		public LPVOID pvOidSpecificInfo;
		public boolean fHasFreshnessTime;
		public int dwFreshnessTime;
		public CERT_REVOCATION_CRL_INFO.ByReference pCrlInfo;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "dwRevocationResult", "pszRevocationOid", "pvOidSpecificInfo",
					"fHasFreshnessTime", "dwFreshnessTime", "pCrlInfo");
		}

		public static class ByReference extends CTL_ENTRY implements Structure.ByReference {
		}
	}

	public static class CERT_CHAIN_ELEMENT extends Structure {

		public int cbSize;
		public CERT_CONTEXT.ByReference pCertContext;
		public CERT_TRUST_STATUS TrustStatus;
		public CERT_REVOCATION_INFO.ByReference pRevocationInfo;

		public CERT_ENHKEY_USAGE.ByReference pIssuanceUsage; // If NULL, any
		public CERT_ENHKEY_USAGE.ByReference pApplicationUsage; // If NULL, any

		public Pointer pwszExtendedErrorInfo; // If NULL, none

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "pCertContext", "TrustStatus", "pRevocationInfo", "pIssuanceUsage",
					"pApplicationUsage", "pwszExtendedErrorInfo");
		}

		public static class ByReference extends CERT_CHAIN_ELEMENT implements Structure.ByReference {
		}
	}

	public static class CTL_INFO extends Structure {
		public int dwVersion;
		public CERT_ENHKEY_USAGE SubjectUsage;
		public CRYPTOAPI_BLOB ListIdentifier;
		public CRYPTOAPI_BLOB SequenceNumber;
		public FILETIME ThisUpdate;
		public FILETIME NextUpdate;
		public CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
		public int cCTLEntry;
		public CTL_ENTRY.ByReference rgCTLEntry;
		public int cExtension;
		public CERT_EXTENSION.ByReference rgExtension;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwVersion", "SubjectUsage", "ListIdentifier", "SequenceNumber", "ThisUpdate",
					"NextUpdate", "SubjectAlgorithm", "cCTLEntry", "rgCTLEntry", "cExtension", "rgExtension");
		}

		public static class ByReference extends CERT_CHAIN_ELEMENT implements Structure.ByReference {
		}
	}

	public static class CTL_CONTEXT extends Structure {
		public int dwMsgAndCertEncodingType;
		public byte[] pbCtlEncoded;
		public int cbCtlEncoded;
		public CTL_INFO.ByReference pCtlInfo;
		public HANDLE hCertStore;
		public HANDLE hCryptMsg;
		public byte[] pbCtlContent;
		public int cbCtlContent;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwMsgAndCertEncodingType", "pbCtlEncoded", "cbCtlEncoded", "pCtlInfo", "hCertStore",
					"hCryptMsg", "pbCtlContent", "cbCtlContent");
		}

		public static class ByReference extends CERT_CHAIN_ELEMENT implements Structure.ByReference {
		}
	}

	public static class CERT_TRUST_LIST_INFO extends Structure {

		public int cbSize;
		public CTL_ENTRY.ByReference pCtlEntry;
		public CTL_CONTEXT.ByReference pCtlContext;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "pCtlEntry", "pCtlContext");
		}

		public static class ByReference extends CERT_TRUST_LIST_INFO implements Structure.ByReference {
		}
	}

	public static class CERT_ENHKEY_USAGE extends Structure {
		public int cUsageIdentifier;
		public LPSTR.ByReference rgpszUsageIdentifier;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cUsageIdentifier", "rgpszUsageIdentifier");
		}

		public static class ByReference extends CERT_ENHKEY_USAGE implements Structure.ByReference {
		}
	}

	public static class CERT_USAGE_MATCH extends Structure {

		public int dwType;
		public CERT_ENHKEY_USAGE Usage;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwType", "Usage");
		}

		public static class ByReference extends CERT_USAGE_MATCH implements Structure.ByReference {
		}
	}

	public static class CERT_STRONG_SIGN_SERIALIZED_INFO extends Structure {
		DWORD dwFlags;
		LPWSTR pwszCNGSignHashAlgids;
		LPWSTR pwszCNGPubKeyMinBitLengths;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwFlags", "pwszCNGSignHashAlgids", "pwszCNGPubKeyMinBitLengths");
		}

		public static class ByReference extends CERT_STRONG_SIGN_SERIALIZED_INFO implements Structure.ByReference {
		}
	}

	public static class DUMMYUNIONNAME extends Union {
		Pointer pvInfo;
		CERT_STRONG_SIGN_SERIALIZED_INFO.ByReference pSerializedInfo;
		LPSTR pszOID;
	}

	public static class CERT_STRONG_SIGN_PARA extends Structure {
		public int cbSize;
		public int dwInfoChoice;

		public DUMMYUNIONNAME union;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "dwInfoChoice", "union");
		}

		public static class ByReference extends CERT_STRONG_SIGN_PARA implements Structure.ByReference {
		}
	}

	public static class PCERT_CHAIN_PARA extends Structure {

		public CERT_CHAIN_PARA.ByReference certChainPara;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("certChainPara");
		}

		public static class ByReference extends PCERT_CHAIN_PARA implements Structure.ByReference {
		}

		public static class ByValue extends PCERT_CHAIN_PARA implements Structure.ByValue {
		}
	}


	public static class CERT_CHAIN_PARA extends Structure {

		public int cbSize;
		public CERT_USAGE_MATCH RequestedUsage;
		
		public CERT_USAGE_MATCH RequestedIssuancePolicy;
		public int dwUrlRetrievalTimeout;
		public boolean fCheckRevocationFreshnessTime;
		public int dwRevocationFreshnessTime;
		public FILETIME pftCacheResync;
		public CERT_STRONG_SIGN_PARA.ByReference pStrongSignPara;
		public int dwStrongSignFlags;

		@Override
		protected List<String> getFieldOrder() {
			//			return Arrays.asList("cbSize", "RequestedUsage");
			return Arrays.asList("cbSize", "RequestedUsage","RequestedIssuancePolicy","dwUrlRetrievalTimeout","fCheckRevocationFreshnessTime",
					"dwRevocationFreshnessTime","pftCacheResync","pStrongSignPara","dwStrongSignFlags");
		}

		public static class ByReference extends CERT_CHAIN_PARA implements Structure.ByReference {

		}
	}

	public static class CERT_CHAIN_POLICY_STATUS extends Structure {
		public int cbSize;
		public int dwError;
		public int lChainIndex;
		public int lElementIndex;
		public Pointer pvExtraPolicyStatus; // pszPolicyOID specific

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "dwError", "lChainIndex", "lElementIndex", "pvExtraPolicyStatus");
		}

		public static class ByReference extends CERT_CHAIN_POLICY_STATUS implements Structure.ByReference {
		}
	}

	public static class PCERT_SIMPLE_CHAIN extends Structure {

		public CERT_SIMPLE_CHAIN.ByReference certSimpleChain;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("certSimpleChain");
		}

		public static class ByReference extends PCERT_SIMPLE_CHAIN implements Structure.ByReference {
		}

		public static class ByValue extends PCERT_SIMPLE_CHAIN implements Structure.ByValue {
		}
	}

	public static class CERT_SIMPLE_CHAIN extends Structure {

		public int cbSize;
		public CERT_TRUST_STATUS TrustStatus;
		public int cElement;
		public CERT_CHAIN_ELEMENT.ByReference rgpElement;
		public CERT_TRUST_LIST_INFO.ByReference pTrustListInfo;

		public BOOL fHasRevocationFreshnessTime;
		public int dwRevocationFreshnessTime; // seconds

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "TrustStatus", "cElement", "rgpElement", "pTrustListInfo",
					"fHasRevocationFreshnessTime", "dwRevocationFreshnessTime");
		}

		public static class ByReference extends CERT_SIMPLE_CHAIN implements Structure.ByReference {
		}
	}

	public static class CERT_CHAIN_POLICY_PARA extends Structure {
		public int cbSize;
		public int dwFlags;
		public Pointer pvExtraPolicyPara; // pszPolicyOID specific

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "dwFlags", "pvExtraPolicyPara");
		}

		public static class ByReference extends CERT_CHAIN_POLICY_PARA implements Structure.ByReference {
		}
	}

	public static class CERT_CHAIN_CONTEXT extends Structure {
		public int cbSize;
		public CERT_TRUST_STATUS TrustStatus;
		public int cChain;
		public PCERT_SIMPLE_CHAIN rgpChain;
		public int cLowerQualityChainContext;
		public PCERT_CHAIN_CONTEXT rgpLowerQualityChainContext;
		public boolean fHasRevocationFreshnessTime;
		public int dwRevocationFreshnessTime;
		public int dwCreateFlags;
		public GUID ChainId;

		public static class ByReference extends CERT_CHAIN_CONTEXT implements Structure.ByReference {
		}

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "TrustStatus", "cChain", "rgpChain", "cLowerQualityChainContext",
					"rgpLowerQualityChainContext", "fHasRevocationFreshnessTime", "dwRevocationFreshnessTime",
					"dwCreateFlags", "ChainId");
		}
	}

	public static class CERT_CONTEXT extends Structure {

		public int dwCertEncodingType;
		public Pointer pbCertEncoded;
		public int cbCertEncoded;
		public CERT_INFO.ByReference pCertInfo;
		public Pointer hCertStore;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwCertEncodingType", "pbCertEncoded", "cbCertEncoded", "pCertInfo", "hCertStore");
		}

		public static class ByReference extends CERT_CONTEXT implements Structure.ByReference {
		}
	}

	public static class PCERT_CONTEXT extends Structure {

		public CERT_CONTEXT.ByReference certContext;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("certContext");
		}

		public static class ByReference extends PCERT_CONTEXT implements Structure.ByReference {
		}

		public static class ByValue extends PCERT_CONTEXT implements Structure.ByValue {
		}
	}

	public static class PCERT_CHAIN_CONTEXT extends Structure {

		public CERT_CHAIN_CONTEXT.ByReference certChainContext;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("certChainContext");
		}

		public static class ByReference extends PCERT_CHAIN_CONTEXT implements Structure.ByReference {
		}

		public static class ByValue extends PCERT_CHAIN_CONTEXT implements Structure.ByValue {
		}
	}

	public static class CERT_EXTENSION extends Structure {

		public String pszObjId;
		public boolean fCritical;
		public CRYPTOAPI_BLOB Value;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("pszObjId", "fCritical", "Value");
		}

		public static class ByReference extends CERT_EXTENSION implements Structure.ByReference {
		}
	}

	public static class CERT_EXTENSIONS extends Structure {

		public int cExtension;
		public CERT_EXTENSION.ByReference rgExtension;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cExtension", "rgExtension");
		}

		public static class ByReference extends CERT_EXTENSIONS implements Structure.ByReference {
		}
	}

	public static class CERT_INFO extends Structure {

		public int dwVersion;
		public CRYPTOAPI_BLOB SerialNumber;
		public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
		public CRYPTOAPI_BLOB Issuer;
		public FILETIME NotBefore;
		public FILETIME NotAfter;
		public CRYPTOAPI_BLOB Subject;
		public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
		public CRYPT_BIT_BLOB IssuerUniqueId;
		public CRYPT_BIT_BLOB SubjectUniqueId;
		public int cExtension;
		public CERT_EXTENSION.ByReference rgExtension;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwVersion", "SerialNumber", "SignatureAlgorithm", "Issuer", "NotBefore", "NotAfter",
					"Subject", "SubjectPublicKeyInfo", "IssuerUniqueId", "SubjectUniqueId", "cExtension",
					"rgExtension");
		}

		public static class ByReference extends CERT_INFO implements Structure.ByReference {
		}
	}

	public static class CERT_PUBLIC_KEY_INFO extends Structure {

		public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
		public CRYPT_BIT_BLOB PublicKey;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("Algorithm", "PublicKey");
		}

		public static class ByReference extends CERT_PUBLIC_KEY_INFO implements Structure.ByReference {
		}
	}

	public static class CRL_CONTEXT extends Structure {

		public int dwCertEncodingType;
		public Pointer pbCrlEncoded;
		public int cbCrlEncoded;
		public CRL_INFO.ByReference pCrlInfo;
		public Pointer hCertStore;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwCertEncodingType", "pbCrlEncoded", "cbCrlEncoded", "pCrlInfo", "hCertStore");
		}

		public static class ByReference extends CRL_CONTEXT implements Structure.ByReference {
		}
	}

	public static class CRL_ENTRY extends Structure {

		public CRYPTOAPI_BLOB SerialNumber;
		public FILETIME RevocationDate;
		public int cExtension;
		public CERT_EXTENSION.ByReference rgExtension;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("SerialNumber", "RevocationDate", "cExtension", "rgExtension");
		}

		public static class ByReference extends CRL_ENTRY implements Structure.ByReference {
		}
	}

	public static class CRL_INFO extends Structure {

		public int dwVersion;
		public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
		public CRYPTOAPI_BLOB Issuer;
		public FILETIME ThisUpdate;
		public FILETIME NextUpdate;
		public int cCRLEntry;
		public CRL_ENTRY.ByReference rgCRLEntry;
		public int cExtension;
		public CERT_EXTENSION.ByReference rgExtension;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwVersion", "SignatureAlgorithm", "Issuer", "ThisUpdate", "NextUpdate", "cCRLEntry",
					"rgCRLEntry", "cExtension", "rgExtension");
		}

		public static class ByReference extends CRL_INFO implements Structure.ByReference {
		}
	}

	public static class CRYPT_ALGORITHM_IDENTIFIER extends Structure {

		public String pszObjId;
		public CRYPTOAPI_BLOB Parameters;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("pszObjId", "Parameters");
		}

		public static class ByReference extends CRYPT_ALGORITHM_IDENTIFIER implements Structure.ByReference {
		}
	}

	public static class CRYPT_ATTRIBUTE extends Structure {

		public String pszObjId;
		public int cValue;
		public CRYPTOAPI_BLOB.ByReference rgValue;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("pszObjId", "cValue", "rgValue");
		}

		public static class ByReference extends CRYPT_ATTRIBUTE implements Structure.ByReference {
		}
	}

	public static class CRYPT_BIT_BLOB extends Structure {

		public int cbData;
		public Pointer pbData;
		public int cUnusedBits;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbData", "pbData", "cUnusedBits");
		}

		public static class ByReference extends CRYPT_BIT_BLOB implements Structure.ByReference {
		}
	}

	public static class CRYPTOAPI_BLOB extends Structure {

		public int cbData;
		public Pointer pbData;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbData", "pbData");
		}

		public static class ByReference extends CRYPTOAPI_BLOB implements Structure.ByReference {
		}
	}

	public static class CRYPT_KEY_PROV_INFO extends Structure {

		public WString pwszContainerName;
		public WString pwszProvName;
		public int dwProvType;
		public int dwFlags;
		public int cProvParam;
		public CRYPT_KEY_PROV_PARAM.ByReference[] rgProvParam = new CRYPT_KEY_PROV_PARAM.ByReference[1];
		public int dwKeySpec;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("pwszContainerName", "pwszProvName", "dwProvType", "dwFlags", "cProvParam",
					"rgProvParam", "dwKeySpec");
		}

		public static class ByReference extends CRYPT_KEY_PROV_INFO implements Structure.ByReference {
		}
	}

	public static class CRYPT_KEY_PROV_PARAM extends Structure {

		public int dwParam;
		public byte[] pbData;
		public int cbData;
		public int dwFlags;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwParam", "pbData", "cbData", "dwFlags");
		}

		public static class ByReference extends CRYPT_KEY_PROV_PARAM implements Structure.ByReference {
		}
	}

	public static class CRYPT_SIGN_MESSAGE_PARA extends Structure {

		public int cbSize;
		public int dwMsgEncodingType;
		public PCERT_CONTEXT pSigningCert;
		public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
		public Pointer pvHashAuxInfo;
		public int cMsgCert;
		public PCERT_CONTEXT.ByReference rgpMsgCert;
		public int cMsgCrl;
		public CRL_CONTEXT.ByReference rgpMsgCrl;
		public int cAuthAttr;
		public CRYPT_ATTRIBUTE.ByReference rgAuthAttr;
		public int cUnauthAttr;
		public CRYPT_ATTRIBUTE.ByReference rgUnauthAttr;
		public int dwFlags;
		public int dwInnerContentType;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("cbSize", "dwMsgEncodingType", "pSigningCert", "HashAlgorithm", "pvHashAuxInfo",
					"cMsgCert", "rgpMsgCert", "cMsgCrl", "rgpMsgCrl", "cAuthAttr", "rgAuthAttr", "cUnauthAttr",
					"rgUnauthAttr", "dwFlags", "dwInnerContentType");
		}

		public static class ByReference extends CRYPT_SIGN_MESSAGE_PARA implements Structure.ByReference {
		}
	}

	public static class FILETIME extends Structure {

		public int dwLowDateTime;
		public int dwHighDateTime;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList("dwLowDateTime", "dwHighDateTime");
		}

		public static class ByReference extends FILETIME implements Structure.ByReference {
		}

		public static class ByValue extends FILETIME implements Structure.ByValue {
		}
	}
}
