#include <windows.h>
#include <wininet.h>
#include <stdio.h>

// Link with wininet.lib
#pragma comment(lib, "wininet.lib")

void DownloadFile(const char* server, const char* resource, const char* username, const char* password, const char* filePath) {
    HINTERNET hInternet, hConnect, hRequest;
    DWORD dwBytesRead;
    FILE* file;

    // Open an internet connection
    hInternet = InternetOpen("MyAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        printf("InternetOpen failed with error: %lu\n", GetLastError());
        return;
    }

    // Connect to the server
    hConnect = InternetConnect(hInternet, server, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("InternetConnect failed with error: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return;
    }

    // Create an HTTP request
    hRequest = HttpOpenRequest(hConnect, "GET", resource, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        printf("HttpOpenRequest failed with error: %lu\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    // Base64 encode username:password
    char credentials[512];
    snprintf(credentials, sizeof(credentials), "%s:%s", username, password);
    DWORD credentialsLen = lstrlen(credentials);
    DWORD encodedLen = ((credentialsLen + 2) / 3) * 4 + 1; // Base64 encoding length
    char* encodedCredentials = (char*)malloc(encodedLen);
    ZeroMemory(encodedCredentials, encodedLen);
    BOOL encodeSuccess = InternetCanonicalizeUrl(credentials, encodedCredentials, &encodedLen, ICU_ENCODE_BASE64 | ICU_NO_ENCODE);

    // Prepare authorization header
    char authHeader[1024];
    snprintf(authHeader, sizeof(authHeader), "Authorization: Basic %s", encodedCredentials);

    // Add the authorization header to the request
    HttpAddRequestHeaders(hRequest, authHeader, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD);

    // Send the request
    BOOL sent = HttpSendRequest(hRequest, NULL, 0, NULL, 0);
    if (!sent) {
        printf("HttpSendRequest failed with error: %lu\n", GetLastError());
        free(encodedCredentials);
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    // Open the file to write the response
    file = fopen(filePath, "wb");
    if (!file) {
        printf("Failed to open file for writing\n");
        free(encodedCredentials);
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    // Read the response and write to the file
    char buffer[4096];
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &dwBytesRead) && dwBytesRead > 0) {
        fwrite(buffer, 1, dwBytesRead, file);
    }

    // Cleanup
    fclose(file);
    free(encodedCredentials);
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

int main() {
    DownloadFile("example.com", "/path/to/file", "username", "password", "local_file_path");
    return 0;
}
