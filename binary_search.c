#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"
enum { kHashLength = 8, kPasswordLength = 6, kFilenamelength = 256 };
const char *const kFilenameFormat = "pwned_passwords_preprocessed_%lu";
unsigned long BinarySearch1(const char *const val, const size_t num_files) {
  char buffer[kHashLength];
  unsigned long left, right, file_index = ULONG_MAX;
  int cmp;
  for (left = 0, right = num_files; left < right;) {
    const unsigned long mid = left + (right - left) / 2;
    char filename[kFilenamelength];
    FILE *file;
    snprintf(filename, kFilenamelength, kFilenameFormat, mid);
    file = fopen(filename, "rb");
    if (file == NULL) {
      perror("fopen");
      exit(1);
    }
    if (fread(buffer, kHashLength, 1, file) != 1) {
      perror("fread");
      exit(1);
    }
    fclose(file);
    cmp = memcmp(buffer, val, kHashLength);
    if (cmp == 0) {
      file_index = mid;
      break;
    } else if (cmp > 0) {
      right = mid;
    } else {
      file_index = mid;
      left = mid + 1;
    }
  }
  return file_index;
}
int BinarySearch2(FILE *const file, const char *const val,
                  const size_t num_strings) {
  char buffer[kHashLength];
  unsigned long left, right;
  for (left = 0, right = num_strings; left < right;) {
    const unsigned long mid = left + (right - left) / 2;
    int cmp;
    if (fseek(file, mid * kHashLength, SEEK_SET) != 0) {
      perror("fseek");
      exit(1);
    }
    if (fread(buffer, kHashLength, 1, file) != 1) {
      perror("fread");
      exit(1);
    }
    cmp = memcmp(buffer, val, kHashLength);
    if (cmp == 0) {
      return 1;
    } else if (cmp > 0) {
      right = mid;
    } else {
      left = mid + 1;
    }
  }
  return 0;
}
unsigned long FindChunkCount(void) {
  char filename[kFilenamelength];
  unsigned long file_index;
  for (file_index = 0;; file_index++) {
    FILE *file;
    snprintf(filename, kFilenamelength, kFilenameFormat, file_index);
    file = fopen(filename, "rb");
    if (file == NULL) break;
    fclose(file);
  }
  return file_index;
}
int Search(const char *const val, const unsigned long chunk_count) {
  const unsigned long file_index = BinarySearch1(val, chunk_count);
  char filename[kFilenamelength];
  long size;
  FILE *file;
  int result;
  if (file_index == ULONG_MAX) return 0;
  snprintf(filename, kFilenamelength, kFilenameFormat, file_index);
  file = fopen(filename, "rb");
  if (file == NULL) {
    perror("fopen");
    exit(1);
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(file);
    exit(1);
  }
  if ((size = ftell(file)) == -1) {
    perror("ftell");
    fclose(file);
    exit(1);
  }
  result = BinarySearch2(file, val, size / kHashLength);
  fclose(file);
  return result;
}
int Increment(unsigned char *digits, int length, unsigned char base) {
  unsigned char *p;
  for (p = digits + length - 1; p >= digits; p--) {
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
  char sha1[20];
  const unsigned long chunk_count = FindChunkCount();
  do {
    char temp[kPasswordLength];
    unsigned char *p = password;
    char *q = temp;
    while (p < password + kPasswordLength) *q++ = '0' + *p++;
    SHA1(sha1, temp, kPasswordLength);
    if (!Search(sha1, chunk_count)) puts(temp);
  } while (!Increment(password, kPasswordLength, 10));
  return 0;
}
