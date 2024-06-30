#include <limits.h>
#include <string.h>

#include "md4.h"
#include "wrappers.h"
enum { kHashLength = 16, kPasswordLength = 6 };
const char *const kFilenameFormat = "hashes_%lu";
unsigned long BinarySearch1(const unsigned char *const val,
                            const size_t num_files) {
  char buffer[kHashLength];
  unsigned long left, right, file_index = ULONG_MAX;
  int cmp;
  for (left = 0, right = num_files; left < right;) {
    const unsigned long mid = left + (right - left) / 2;
    const int formatted_length = snprintf(NULL, 0, kFilenameFormat, mid);
    FILE *file;
    char *const filename = (char *)SafeMAlloc(formatted_length + 1);
    sprintf(filename, kFilenameFormat, mid);
    file = SafeFOpen(filename, "rb");
    free(filename);
    SafeFRead(buffer, kHashLength, 1, file);
    fclose(file);
    cmp = memcmp(val, buffer, kHashLength);
    if (cmp < 0) {
      right = mid;
    } else if (cmp > 0) {
      file_index = mid;
      left = mid + 1;
    } else {
      file_index = mid;
      break;
    }
  }
  return file_index;
}
int BinarySearch2(FILE *const file, const unsigned char *const val,
                  const size_t num_strings) {
  char buffer[kHashLength];
  unsigned long left, right;
  for (left = 0, right = num_strings; left < right;) {
    const unsigned long mid = left + (right - left) / 2;
    int cmp;
    SafeFSeek(file, mid * kHashLength, SEEK_SET);
    SafeFRead(buffer, kHashLength, 1, file);
    cmp = memcmp(val, buffer, kHashLength);
    if (cmp < 0) {
      right = mid;
    } else if (cmp > 0) {
      left = mid + 1;
    } else {
      return 1;
    }
  }
  return 0;
}
unsigned long FindChunkCount(void) {
  unsigned long file_index;
  for (file_index = 0;; ++file_index) {
    const int formatted_length = snprintf(NULL, 0, kFilenameFormat, file_index);
    FILE *file;
    char *const filename = (char *)SafeMAlloc(formatted_length + 1);
    sprintf(filename, kFilenameFormat, file_index);
    file = fopen(filename, "rb");
    free(filename);
    if (!file) {
      break;
    }
    fclose(file);
  }
  return file_index;
}
int Search(const unsigned char *const val, const unsigned long chunk_count) {
  const unsigned long file_index = BinarySearch1(val, chunk_count);
  int formatted_length;
  char *filename;
  FILE *file;
  long size;
  int result;
  if (file_index == ULONG_MAX) {
    return 0;
  }
  formatted_length = snprintf(NULL, 0, kFilenameFormat, file_index);
  filename = (char *)SafeMAlloc(formatted_length + 1);
  sprintf(filename, kFilenameFormat, file_index);
  file = SafeFOpen(filename, "rb");
  free(filename);
  SafeFSeek(file, 0, SEEK_END);
  size = SafeFTell(file);
  result = BinarySearch2(file, val, size / kHashLength);
  fclose(file);
  return result;
}
void AsciiToUtf16Le(char *const ascii, const size_t ascii_length,
                    unsigned char *const utf_16_le) {
  char *ascii_ptr;
  unsigned char *utf_16_ptr = utf_16_le;
  for (ascii_ptr = ascii; ascii_ptr < ascii + ascii_length; ++ascii_ptr) {
    *utf_16_ptr++ = *ascii_ptr;
    *utf_16_ptr++ = 0;
  }
}
void Hash(unsigned char *const hash, const unsigned char *const string,
          const unsigned long length) {
  MD4_CTX context;
  MD4_Init(&context);
  MD4_Update(&context, string, length);
  MD4_Final(hash, &context);
}
int Increment(unsigned char *digits, int length, unsigned char base) {
  unsigned char *p;
  for (p = digits + length - 1; p >= digits; --p) {
    if (*p == base - 1) {
      *p = 0;
    } else {
      (*p)++;
      return 0;
    }
  }
  return 1;
}
int main(void) {
  unsigned char password[kPasswordLength] = {0};
  const unsigned long chunk_count = FindChunkCount();
  for (;;) {
    char ascii[kPasswordLength];
    unsigned char utf_16_le[kPasswordLength * 2];
    unsigned char hash[16];
    unsigned char *password_ptr = password;
    char *ascii_ptr = ascii;
    while (password_ptr < password + kPasswordLength) {
      *ascii_ptr++ = '0' + *password_ptr++;
    }
    AsciiToUtf16Le(ascii, kPasswordLength, utf_16_le);
    Hash(hash, utf_16_le, kPasswordLength * 2);
    if (!Search(hash, chunk_count)) {
      SafePrintF("%.*s\n", kPasswordLength, ascii);
    }
    if (Increment(password, kPasswordLength, 10)) {
      break;
    }
  }
  return 0;
}
