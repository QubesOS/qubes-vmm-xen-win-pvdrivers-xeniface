#include <windows.h>

BOOL APIENTRY DllMain(HMODULE module,
                      DWORD reasonForCall,
                      LPVOID reserved)
{
    switch (reasonForCall)
    {
    case DLL_PROCESS_ATTACH:
        break;
    
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
