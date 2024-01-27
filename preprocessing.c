#include <stdio.h>
#include <stdlib.h>
enum {
  kHashLength = 16,
  kHashBytes = kHashLength / 2 + (kHashLength % 2 != 0)
};
const unsigned long kChunkSize = 0x7FFFFFFF;
void FromHex(const char *hex_str, unsigned char *bytes) {
  size_t final_length = kHashBytes;
  unsigned char *p = bytes;
  unsigned temp;
  if (kHashLength % 2 == 1) {
    if (sscanf(hex_str++, "%1x", &temp) != 1) {
      perror("sscanf");
      exit(1);
    }
    *p++ = (unsigned char)temp, final_length--;
  }
  for (; final_length--; hex_str += 2, p++) {
    if (sscanf(hex_str, "%2x", &temp) != 1) {
      perror("sscanf");
      exit(1);
    }
    *p = (unsigned char)temp;
  }
}
int main(void) {
  FILE *const file_in = fopen("pwned_passwords.txt", "rb");
  FILE *file_out = NULL;
  char buffer[kHashLength];
  unsigned long file_index = 0, chunk_size = kChunkSize;
  if (file_in == NULL) {
    perror("fopen");
    fclose(file_out);
    return 1;
  }
  while (!feof(file_in)) {
    char filename[256];
    sprintf(filename, "pwned_passwords_preprocessed_%lu", file_index);
    file_out = fopen(filename, "wb");
    if (file_out == NULL) {
      perror("fopen");
      fclose(file_in);
      return 1;
    }
    while (chunk_size >= kHashBytes) {
      unsigned char h[kHashBytes];
      int c;
      if (fread(buffer, kHashLength, 1, file_in) != 1) {
        if (ferror(file_in)) {
          perror("fread");
          fclose(file_in);
          fclose(file_out);
          return 1;
        }
        break;
      }
      FromHex(buffer, h);
      if (fwrite(h, kHashBytes, 1, file_out) != 1) {
        perror("fwrite");
        fclose(file_in);
        fclose(file_out);
        return 1;
      }
      while ((c = fgetc(file_in)) != '\n' && c != EOF)
        ;
      if (ferror(file_in)) {
        perror("fgetc");
        fclose(file_in);
        fclose(file_out);
        return 1;
      }
      chunk_size -= kHashBytes;
    }
    fclose(file_out);
    file_index++;
    chunk_size = kChunkSize;
  }
  fclose(file_in);
  fclose(file_out);
  return 0;
}
