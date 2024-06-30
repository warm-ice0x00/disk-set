#include <ctype.h>

#include "wrappers.h"
enum { kHashLength = 32, kHashBytes = 1 + ((kHashLength - 1) / 2) };
const unsigned long kChunkSize = 0x7FFFFFFF;
const char *const kFilenameFormat = "hashes_%lu";
unsigned char AllSpaces(const char *line) {
  for (; *line; ++line) {
    if (!isspace(*line)) {
      return 0;
    }
  }
  return 1;
}
void FromHex(const char *hex_str, unsigned char *bytes) {
  size_t final_length = kHashBytes;
  unsigned char *p = bytes;
  unsigned temp;
  if (kHashLength % 2) {
    if (sscanf(hex_str++, "%1X", &temp) != 1) {
      perror("sscanf");
      exit(EXIT_FAILURE);
    }
    *p++ = (unsigned char)temp;
    --final_length;
  }
  for (; final_length--; hex_str += 2, ++p) {
    if (sscanf(hex_str, "%2X", &temp) != 1) {
      perror("sscanf");
      exit(EXIT_FAILURE);
    }
    *p = (unsigned char)temp;
  }
}
int main(void) {
  FILE *const file_in = SafeFOpen("hashes.txt", "rb");

  unsigned long file_index = 0;
  for (;;) {
    unsigned long chunk_size = kChunkSize;
    const int formatted_length = snprintf(NULL, 0, kFilenameFormat, file_index);
    FILE *file_out;
    char *const filename = (char *)SafeMAlloc(formatted_length + 1);
    sprintf(filename, kFilenameFormat, file_index);
    file_out = SafeFOpen(filename, "wb");
    free(filename);
    for (; chunk_size >= kHashBytes; chunk_size -= kHashBytes) {
      char buffer[kHashLength + 1];
      unsigned char h[kHashBytes];
      int c;
      if (!SafeFGetS(buffer, sizeof(buffer), file_in)) {
        fclose(file_in);
        fclose(file_out);
        return 0;
      }
      if (AllSpaces(buffer)) {
        continue;
      }
      FromHex(buffer, h);
      SafeFWrite(h, kHashBytes, 1, file_out);
      while ((c = SafeFGetC(file_in)) != '\n' && c != EOF) {
      }
    }
    fclose(file_out);
    ++file_index;
  }
  return 0;
}
