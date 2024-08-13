#include <stdio.h>
#include "b64/cdecode.h"

int main() {
    const char* input = "SGVsbG8gV29ybGQ=";
    char output[20];
    base64_decodestate state;
    base64_init_decodestate(&state);
    int count = base64_decode_block(input, 16, output, &state);
    
    output[count] = '\0'; // Null-terminate the decoded string
    printf("Decoded string: %s\n", output);
    return 0;
}

