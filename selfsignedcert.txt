// ConsoleApplication3.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <WinCrypt.h>
#include <iostream>

//-------------------------------------------------------------------
//    Define the name of the store where the needed certificate
//    can be found. 

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

int main()
{
	wchar_t* pszCertificateSubjectName = (wchar_t*)"CN=Test Subject";

	DWORD dwSize = 0;
	if (!CertStrToName(
		X509_ASN_ENCODING,
		pszCertificateSubjectName,
		CERT_OID_NAME_STR,
		NULL,
		NULL,
		&dwSize,
		NULL
	))
	{
		return 1;
	}

	PBYTE p = (PBYTE)_alloca(dwSize);

	if (!CertStrToName(
		X509_ASN_ENCODING,
		pszCertificateSubjectName,
		CERT_OID_NAME_STR,
		NULL,
		p,
		&dwSize,
		NULL
	))
	{
		return 1;
	}

	CERT_NAME_BLOB sib;
	sib.cbData = dwSize;
	sib.pbData = p;

	wchar_t* pszKeyContainerName = (wchar_t*)"Test Container Name";

	HCRYPTPROV hProv = NULL;
	if (!CryptAcquireContext(
		&hProv,
		pszKeyContainerName,
		MS_DEF_PROV,
		PROV_RSA_FULL,
		CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET
	))
	{
		if (GetLastError() == NTE_EXISTS)
		{
			if (!CryptAcquireContext(
				&hProv,
				pszKeyContainerName,
				MS_DEF_PROV,
				PROV_RSA_FULL,
				CRYPT_MACHINE_KEYSET
			))
			{
				return 1;
			}
		}
	}

	HCRYPTKEY hKey;
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey))
	{
		CryptReleaseContext(hProv, 0);
		return 1;
	}

	CRYPT_KEY_PROV_INFO kpi;
	ZeroMemory(&kpi, sizeof(kpi));
	kpi.pwszContainerName = pszKeyContainerName;
	kpi.pwszProvName = (LPWSTR)MS_DEF_PROV;
	kpi.dwProvType = PROV_RSA_FULL;
	kpi.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
	kpi.dwKeySpec = AT_KEYEXCHANGE;

	SYSTEMTIME et;
	GetSystemTime(&et);
	et.wYear += 10;

	CERT_EXTENSIONS exts;
	ZeroMemory(&exts, sizeof(exts));

	PCCERT_CONTEXT pc = CertCreateSelfSignCertificate(
		hProv,
		&sib,
		0,
		&kpi,
		NULL,
		NULL,
		&et,
		&exts
	);
	if (!pc)
	{
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		return 1;
	}



}

