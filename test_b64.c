#include "libbase64.h"
#include <stdio.h>
#include <string.h>

int main() {
    const char* input = "SGVsbG8gV29ybGQ="; // "Hello World" in Base64
    char output[50];
    size_t output_len = 0;
    struct base64_state state;

    base64_stream_decode_init(&state, 0);
    if (!base64_stream_decode(&state, input, strlen(input), output, &output_len)) {
        fprintf(stderr, "Failed to decode Base64.\n");
        return 1;
    }

    output[output_len] = '\0'; // Null-terminate the decoded string
    printf("Decoded string: %s\n", output);
    return 0;
}

