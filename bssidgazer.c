// BSSIDGAZER 2023.
#include <Windows.h>
#include <wlanapi.h>
#include <oleauto.h>
#include <objbase.h>
#include <ctype.h>
#include <wtypes.h>
#include <rpcdce.h>
#include <tchar.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "shell32.lib")

int HIDDEN_CONTRUCTS = 0;
int VISIBLE_CONSTRUCTS = 0;

#define GRACEFUL_EXIT_ALL \
            WlanCloseHandle(wHandle, NULL);\
            CoUninitialize();\
            \
            exit(1);\


LPWSTR returnMsgBuffer(DWORD error);
LPWSTR processWlanPhyType(DWORD phyType);
WCHAR *convertUllTimestamp(ULONGLONG timestamp);

int obtainWirelessChannel(ULONG frequency);

void printUlRateSetArray(USHORT *rateSet, size_t sz);
void handleWirelessInfo(PWLAN_BSS_ENTRY pwBSSID_entry);
void handlePotentialErrors(DWORD wResult, HANDLE wHandle);

void printIEEncryptionMethod(const UCHAR *ieData, DWORD ieSz);
void parseInformationElementData(const UCHAR *ieData, DWORD ieSz);

// display basic help options
void displayHelpMsg(void);


int main(int argc, char *argv[])
{
    int argcCount;
    LPWSTR *argvLst = CommandLineToArgvW(GetCommandLineW(), &argcCount);

    const char *wlanGUID = NULL;

    if (argcCount < 2)
    {
        displayHelpMsg();
    }
    else
    {
        if (wcscmp(argvLst[1], L"--setguid") == 0)
        {
            // check for existence of GUID
            if (!argvLst[2])
            {
                printf("ERROR: Missing wireless LAN interface GUID!\n");
                
                return -1;
            }
            else
            {
                // check for proper GUID
                // checkGUIDParams(GUID guid);

                wlanGUID = argv[2]; // lazy workaround to avoid converting LPWSTR to const char *

                printf("[+] Set WLAN GUID to \"%hs\"\n", wlanGUID);
            }
        }
        else if (wcscmp(argvLst[1], L"-h") == 0 || wcscmp(argvLst[1], L"--help") == 0)
        {
            displayHelpMsg();
        }
        else
        {
            wprintf(L"Unsupported option: \"%s\"\n", argvLst[1]);
            
            return -1;
        }
    }

    DWORD wResult, wVersion;

    HRESULT hRes;
    HANDLE wHandle;

    hRes = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    if (FAILED(hRes))
    {
        printf("Failed to initialize the component object model! Could not create STA!\n");
        CoUninitialize();

        exit(1);
    }

    // include ALL BSS types, do not restrict ANY
    DOT11_BSS_TYPE bssid_type = dot11_BSS_type_any;

    BOOL security_enabled = (VARIANT_BOOL)-1; // set to false for open networks only, useful for rogue AP
    PWLAN_BSS_LIST bssList = NULL;

    GUID lGUID;
    RPC_STATUS rpcStat = UuidFromStringA((RPC_CSTR)wlanGUID, &lGUID);

    if (rpcStat != RPC_S_OK)
    {
        wprintf(L"ERROR: %ls\n", returnMsgBuffer(GetLastError()));
        CoUninitialize();

        exit(1);
    }

    wResult = WlanOpenHandle(WLAN_API_VERSION, NULL, &wVersion, &wHandle);
    handlePotentialErrors(wResult, wHandle);

    wResult = WlanGetNetworkBssList(wHandle, &lGUID, NULL, bssid_type, security_enabled, NULL, &bssList);
    handlePotentialErrors(wResult, wHandle);

    for (DWORD a = 0; a < bssList->dwNumberOfItems; a++)
    {
        PWLAN_BSS_ENTRY bssEntry = &(bssList->wlanBssEntries[a]);

        handleWirelessInfo(bssEntry);
    }

    WlanFreeMemory(bssList);
    WlanCloseHandle(wHandle, NULL);

    printf("\nVISIBLE NETWORKS: %d\n"
            "HIDDEN NETWORKS: %d\n"
            "TOTAL: %d\n", 
            
            VISIBLE_CONSTRUCTS, 
            HIDDEN_CONTRUCTS,
            (VISIBLE_CONSTRUCTS + HIDDEN_CONTRUCTS));

    return 0;
}


void handleWirelessInfo(PWLAN_BSS_ENTRY pwBSSID_entry)
{
    UCHAR *dot11_ucSSID = pwBSSID_entry->dot11Ssid.ucSSID;

    // BSSID type (infrastructure, or independent)
    LPWSTR uBSSIDtype = NULL;

    if (strlen(dot11_ucSSID) > 0)
    {
        dot11_ucSSID = dot11_ucSSID;
        VISIBLE_CONSTRUCTS++;
    }
    else if (pwBSSID_entry->dot11Ssid.uSSIDLength == 0)
    {
        dot11_ucSSID = "** HIDDEN NETWORK";
        HIDDEN_CONTRUCTS++;
    }

    DWORD dot11_uBSSIDType = pwBSSID_entry->dot11BssType;

    switch (dot11_uBSSIDType)
    {
        // WPA3? No.
        case dot11_BSS_type_infrastructure:
            uBSSIDtype = L"Infrastructure\0";

        // WPA2? No.
        case dot11_BSS_type_independent:
            uBSSIDtype = L"Independent\0";
    }

    wprintf(
        L"-------------------------------------------------\n"
        L"%hs >> (%02x:%02x:%02x:%02x:%02x:%02x)\n"
        L"\tLAN ID (Interface): %lu\n"
        L"\tBSSID TYPE: %s\n"
        L"\tBSSID PHY TYPE: %s\n"
        L"\tRSSI: %ld\n"
        L"\tLINK QUALITY: %lu\n"
        L"\tREGDOMAIN: %s\n"
        L"\tBEACON INT: %hums\n"
        L"\tTIMESTAMP: %s\n"
        L"\tHOST TS: %s\n"
        L"\tCAPABILITY: %hu\n"
        L"\tFREQUENCY: %.3f GHz\n"
        L"\tCHANNEL: %d\n"
        L"\tIE SIZE: %lu bytes\n",

        // DOT11_SSID
        // The SSID of the access point (AP) or peer station associated with the BSS
        dot11_ucSSID,

        // DOT11_MAC_ADDRESS
        pwBSSID_entry->dot11Bssid[0],
        pwBSSID_entry->dot11Bssid[1],
        pwBSSID_entry->dot11Bssid[2],
        pwBSSID_entry->dot11Bssid[3],
        pwBSSID_entry->dot11Bssid[4],
        pwBSSID_entry->dot11Bssid[5],

        // The identifier (ID) of the PHY that the wireless LAN interface used to detect the BSS network.
        pwBSSID_entry->uPhyId,

        // The BSS network type. The data type for this member is a DOT11_BSS_TYPE enumeration value.
        uBSSIDtype,

        // BSSID PHY TYPE
        // create function to handle different options
        // https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-phy-type
        processWlanPhyType(pwBSSID_entry->dot11BssPhyType),

        /*
            The received signal strength indicator (RSSI) value, in units of decibels referenced to
            1.0 milliwatts (dBm), as detected by the wireless LAN interface driver for the AP
            or peer station.
        */
        pwBSSID_entry->lRssi,

        /*
            The link quality reported by the wireless LAN interface driver. The link quality value ranges from
            0 through 100. A value of 100 specifies the highest link quality
        */
        pwBSSID_entry->uLinkQuality,

        /*
            A value that specifies whether the AP or peer station is operating within
            the regulatory domain as identified by the country/region.
        */
        pwBSSID_entry->bInRegDomain ? L"NOT SUPPORTED" : L"SUPPORTED",

        /*
            The value of the Beacon Interval field from the 802.11 Beacon or Probe Response
            frame received by the wireless LAN interface.
        */
        pwBSSID_entry->usBeaconPeriod,

        /*
            The value of the Timestamp field from the 802.11 Beacon or
            Probe Response frame received by the wireless LAN interface.
        */
        convertUllTimestamp(pwBSSID_entry->ullTimestamp),

        /*
            The host timestamp value that records when wireless LAN interface
            received the Beacon or Probe Response frame. This member is a count of
            100-nanosecond intervals since January 1, 1601.
        */
        convertUllTimestamp(pwBSSID_entry->ullHostTimestamp) == convertUllTimestamp(pwBSSID_entry->ullTimestamp) ? L"SAME" : L"DIFFERENT",

        /*
             The value of the Capability Information field from the 802.11 Beacon or
             Probe Response frame received by the wireless LAN interface. This value is
             a set of bit flags defining the capability.

             https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry
        */

        // create function to handle BIT flags
        pwBSSID_entry->usCapabilityInformation,

        /*
            The channel center frequency of the band on which the 802.11
            Beacon or Probe Response frame was received. The value of ulChCenterFrequency
            is in units of kilohertz (kHz).
        */
        (float)pwBSSID_entry->ulChCenterFrequency / 1000000,

        /*
            The wireless channel that the current access point is operating on.
            This value is calculated below.

            Note: The channel calculation for 5GHz wireless networks needs revisioning
        */
        obtainWirelessChannel(pwBSSID_entry->ulChCenterFrequency),

        // size of all the Information Elements combined from the data blob
        pwBSSID_entry->ulIeSize
    );

    /*
        An array of supported data transfer rates. 
        DOT11_RATE_SET_MAX_LENGTH is defined in windot11.h to have a value of 126.
    */
    printf("\tRATESET: {\n\t\t");
    printUlRateSetArray
    (
        pwBSSID_entry->wlanRateSet.usRateSet,
        sizeof(pwBSSID_entry->wlanRateSet.usRateSet) / sizeof(pwBSSID_entry->wlanRateSet.usRateSet[0])    
    );
    printf("\t}\n");
}

/*
    We can determine the PHY type based on the actual rate set when 
    the rateset is show as ???
*/
void printUlRateSetArray(USHORT *rateSet, size_t sz)
{
    float rateMbps;

    for (size_t i = 0; i < sz; i++)
    {
        rateMbps = (rateSet[i] & 0x7FFF) * 0.5;

        if (rateSet[i] > 0)
            printf("%.1fMbps, ", rateMbps);
    }

    printf("\n");
}


WCHAR *convertUllTimestamp(ULONGLONG timestamp)
{
    FILETIME ft; // filetime structure (windows format)

    // keep lower 32 bits
    ft.dwLowDateTime = (DWORD)timestamp;

    // extract the 32 bits (high order) of the timestamp value
    // long >= 32 bits | unsigned long is 64 bits
    ft.dwHighDateTime = (DWORD)(timestamp >> 32);

    SYSTEMTIME sysTime; // store converted system time

    // convert filetime value to system time value
    if (!FileTimeToSystemTime(&ft, &sysTime))
    {
        printf("Failed to convert ULONGLONG UllTimestamp to system time format!\n");

        // instead of exiting possibly just set a NONE value
        return L"NONE";
    }

    WCHAR timeFmt[256];

    int res;

    if ((res = GetTimeFormatEx(NULL, 0, &sysTime, NULL, timeFmt, sizeof(timeFmt) / sizeof(timeFmt[0]))) == 0)
    {
        DWORD error = GetLastError();
        wprintf(L"ERROR: %s\n", returnMsgBuffer(error));

        exit(1);
    }

    return timeFmt;
}


int obtainWirelessChannel(ULONG frequency)
{
    // handle 2.5GHz
    if (frequency >= 2412000 && frequency <= 2484000)
    {
        // The division by 5000 is performed to determine 
        // how many 5 MHz increments the frequency is above the base frequency
        // +1 because the channels for the 2.4GHz frequency start at 1
        return (frequency - 2412000) / 5000 + 1;
    }
    // handle 5Ghz (inaccurate results)
    /*
        To accurately calculate the channel number in the 5 GHz band, you need to consider
        the channel width and frequency assignments defined by the regulatory domain and 
        the specific wireless standard being used.

        Since the channel widths in the 5 GHz band can vary, there is no universal fixed 
        value to use in the calculation. The correct channel width and frequency 
        assignments depend on the specific wireless standard and the regulatory domain.
    */
    else if (frequency >= 5000000 && frequency <= 6000000)
    {
        return (frequency - 5000000) / 5000 + 36;
    }

    return 0;
}


LPWSTR processWlanPhyType(DWORD phyType)
{
    switch (phyType)
    {
        // Frequency Hopping Spread Spectrum (can be bt device)
        case dot11_phy_type_fhss:
            return L"FHSS";

        // Direct Sequence Spread Spectrum
        case dot11_phy_type_dsss:
            return L"802.11b (DSSS)";
        
        // Infrared Baseband
        case dot11_phy_type_irbaseband:
            return L"IR BASEBAND";
        
        // Orthogonal Frequency Division Multiplexing (802.11a)
        case dot11_phy_type_ofdm:
            return L"802.11a (OFDM)";

        // High Rate Direct Sequence Spread Spectrum
        case dot11_phy_type_hrdsss:
            return L"HRDSSS";

        // Extended Range (802.11g)
        case dot11_phy_type_erp:
            return L"802.11g (ER)";

        case dot11_phy_type_ht:
            return L"802.11n";

        // Very High Throughput (802.11ac)
        case dot11_phy_type_vht:
            return L"802.11ac (VHT)";

        case dot11_phy_type_any:
            return L"Unknown";

        default:
            return L"???";
    }

    return 0;
}


void handlePotentialErrors(DWORD wResult, HANDLE wHandle)
{
    switch (wResult)
    {
        case ERROR_INVALID_HANDLE:
        {
            printf("ERROR: Client handle not found within the handle table!\n");

            GRACEFUL_EXIT_ALL
        }

        case ERROR_INVALID_PARAMETER:
        {
            printf("ERROR: Version or client handle is NULL || reserved is ! NULL!\n");
            
            GRACEFUL_EXIT_ALL
        }

        case ERROR_NOT_ENOUGH_MEMORY:
        {
            printf("ERROR: Not enough memory to create the client context!\n");
            
            GRACEFUL_EXIT_ALL
        }

        case ERROR_REMOTE_SESSION_LIMIT_EXCEEDED:
        {
            printf("ERROR: Too many handles have been issued by the server!\n");
            
            GRACEFUL_EXIT_ALL
        }

        case ERROR_NDIS_DOT11_POWER_STATE_INVALID:
        {
            printf("ERROR: Radio associated with the LAN interface was turned off!\n");

            GRACEFUL_EXIT_ALL
        }

        case ERROR_NOT_FOUND:
        {
            printf("ERROR: The element was not found. GUID is invalid!\n");

            GRACEFUL_EXIT_ALL
        }

        case ERROR_NOT_SUPPORTED:
        {
            printf("ERROR: The request is not supported! WLAN AutoConfig service might be disabled.\n");
            
            GRACEFUL_EXIT_ALL
        }

        case ERROR_SERVICE_NOT_ACTIVE:
        {
            printf("ERROR: The WLAN AutoConfig service has not been started!\n");
            
            GRACEFUL_EXIT_ALL
        }

        default: 
            break;
    }
}


void displayHelpMsg(void)
{
    char *helpStr = "BSSIDGAZER (WireEye 2023) Basic wireless recon submodule";
    size_t helpLen = strlen(helpStr);

    printf("%s\n", helpStr);

    for (int x = 0; x < helpLen; x++)
    {
        printf("=");

        if (x == helpLen)
        {
            break;
        }
    }

    printf("\n\n");
    printf("--setguid <GUID>\twireless LAN interface GUID to use when viewing stored 802.11 data\n");

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