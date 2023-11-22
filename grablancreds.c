#include <Windows.h>
#include <Wlanapi.h>
#include <wtypes.h>
#include <oleauto.h>
#include <objbase.h>
#include <wchar.h>
#include <tchar.h>
#include <stdio.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

#define SET_GETGUID_FLAG 1
#define SET_GETCREDS_FLAG 2

void displayHelpMsg(void);
LPWSTR returnMsgBuffer(DWORD error);


int main(void)
{
    int argvCount;
    int switchFlag = 0;

    LPWSTR *argvLst = CommandLineToArgvW(GetCommandLineW(), &argvCount);

    if (argvCount < 2)
        displayHelpMsg();

    if (wcscmp(argvLst[1], L"--dumpguid") == 0)
    {
        wprintf(L"[*] Dumping wireless LAN interface GUID to stdout...\n\n");
        switchFlag++;
    }
    else if (wcscmp(argvLst[1], L"--dumpxml") == 0)
    {
        wprintf(L"[*] Dumping profile data (credentials) from the wireless LAN interface...\n\n");
        switchFlag += 2;
    }
    else if (wcscmp(argvLst[1], L"-h") == 0 || wcscmp(argvLst[1], L"--help") == 0)
    {
        displayHelpMsg();
    }
    else
    {
        wprintf(L"Unsupported option: \"%s\"\n", argvLst[1]);

        exit(0);
    }

    HANDLE wHandle;
    DWORD wVersion, wResult;

    wVersion = wResult = 0;

    // NULL = use default security settings, COINIT = use single threaded apartment
    HRESULT hRes = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    if (FAILED(hRes))
    {
        printf("Failed to initialize the component object model! Could not create STA! ERROR => %lu\n", wResult);
        CoUninitialize();

        exit(1);
    } 

    // open handle to the wireless interface
    wResult = WlanOpenHandle(WLAN_API_VERSION, NULL, &wVersion, &wHandle);

    if (wResult != ERROR_SUCCESS)
    {
        DWORD error = GetLastError();

        wprintf(L"Failed to open a handle to the wireless LAN interface! ERROR => %s\n", returnMsgBuffer(error));
        
        WlanCloseHandle(wHandle, NULL);
        CoUninitialize();
        
        exit(1);
    }

    PWLAN_INTERFACE_INFO_LIST pInterfaceList = NULL;
    wResult = WlanEnumInterfaces(wHandle, NULL, &pInterfaceList);

    if (wResult != ERROR_SUCCESS)
    {
        DWORD error = GetLastError();

        wprintf(L"Failed to enumerate wireless LAN interfaces on the current system! ERROR => %s\n", returnMsgBuffer(error));

        WlanCloseHandle(wHandle, NULL);
        CoUninitialize();

        exit(1);
    }

    // GUID handling
    WCHAR guidStore[38 + 1]; // len of GUID + null terminator
    HRESULT catchGUID;

    // start custom logic
    int breakAt = 0;

    switch (switchFlag)
    {
        case SET_GETGUID_FLAG:
            breakAt++;

            break;

        case SET_GETCREDS_FLAG:
            breakAt += 2;

            break;
    }

    // enumerate through captured interfaces
    for (DWORD i = 0; i < pInterfaceList->dwNumberOfItems; i++)
    {
        PWLAN_INTERFACE_INFO pInfo = &(pInterfaceList->InterfaceInfo[i]);

        catchGUID = StringFromGUID2(&(pInfo->InterfaceGuid), guidStore, sizeof(guidStore));
        
        if (FAILED(catchGUID))
        {
            printf("Failed to covert GUID to appropriate string representation!\n");

            continue;
        }

        if (breakAt == SET_GETGUID_FLAG)
        {
            _tprintf(_T("Name: %ls\n\t** GUID: %ls\n\n"), pInfo->strInterfaceDescription, guidStore);
            
            return 1;
        }

        PWLAN_PROFILE_INFO_LIST pProfileInfo = NULL;
        wResult = WlanGetProfileList(wHandle, &(pInfo->InterfaceGuid), NULL, &pProfileInfo);

        if (wResult != ERROR_SUCCESS)
        {
            DWORD error = GetLastError();

            wprintf(L"Failed to obtain the proper profile listing for the wireless LAN interface! ERROR => %s\n", returnMsgBuffer(error));

            WlanFreeMemory(pInfo);
            WlanFreeMemory(pInterfaceList);
            WlanFreeMemory(pProfileInfo);

            WlanCloseHandle(wHandle, NULL);
            CoUninitialize();
        }

        WCHAR *pXML = (WCHAR *) malloc((4096 + 1) * sizeof(WCHAR));
        
        if (pXML == NULL)
        {
            printf("Failed to allocated enough memory to store target profile XML data!\n");

            exit(1);
        }

        // if set to 0 the key will be encrypted
        DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
        DWORD access = WLAN_READ_ACCESS;

        PWLAN_PROFILE_INFO pLanInfo = &(pProfileInfo->ProfileInfo[i]);

        wResult = WlanGetProfile(wHandle, &(pInfo->InterfaceGuid), pLanInfo->strProfileName, NULL, &pXML, &flags, &access);

        if (wResult != ERROR_SUCCESS)
        {
            DWORD error = GetLastError();

            wprintf(L"Failed to get final information pertaining to the wireless LAN interface entity! ERROR => %s\n", returnMsgBuffer(error));
        }
        else
        {
            if (breakAt == SET_GETCREDS_FLAG)
                _tprintf(_T("NETWORK NAME: %ls\nXML: {\n%ls\n}\n"), pLanInfo->strProfileName, pXML);
        }
    }

    WlanFreeMemory(pInterfaceList);
    WlanCloseHandle(wHandle, NULL);

    CoUninitialize();

    return 0; 
}


void displayHelpMsg(void)
{
    char *helpMsg = "grablancreds.exe (CRABGRABBER)";
    size_t msgSz = strlen(helpMsg);

    printf("%s\n", helpMsg);

    for (int i = 0; i < msgSz; i++)
    {
        printf("=");

        if (i == msgSz)
            break;
    }

    printf("\n\n");

    printf
    (
        "--dumpguid\tdump the wireless LAN interface GUID string to stdout\n"
        "--dumpxml\tdump the XML data buffer containing LAN credentials to stdout\n"
    );

    exit(0);
}


LPWSTR returnMsgBuffer(DWORD error)
{
    LPWSTR msgBuffer = NULL;

    DWORD res = FormatMessageW
    (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msgBuffer,
        0,
        NULL
    );

    LocalFree(msgBuffer);

    return msgBuffer;
}