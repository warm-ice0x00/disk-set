#ifndef BLOOM_FILTER_H_
#define BLOOM_FILTER_H_
#include <stdio.h>
#include <stdlib.h>

#include "md4.h"
#include "wrappers.h"
typedef struct {
  FILE *file;
  unsigned long hash_count;
  unsigned long bit_count;
} Bloom;
enum { kHashLength = 16 };
static const char *const kFileName = "bloom_filter";
FILE *BloomCreate(const unsigned long bit_count) {
  FILE *const bloom = SafeFOpen(kFileName, "w+b");
  SafeFSeek(bloom, (1 << (bit_count - 3)) - 1, SEEK_SET);
  SafeFPutC('\0', bloom);
  return bloom;
}
FILE *BloomOpen() { return SafeFOpen(kFileName, "rb"); }
static void Hash(unsigned char *const hash, const char *const string,
                 const unsigned long length) {
  MD4_CTX context;
  MD4_Init(&context);
  MD4_Update(&context, string, length);
  MD4_Final(hash, &context);
}
static unsigned long BytesToUInt32(const unsigned char *const array) {
  return array[0] << 24 | array[1] << 16 | array[2] << 8 | array[3];
}
static char GetBit(FILE *const file, const unsigned long bit_index) {
  const unsigned long byte_index = bit_index >> 3;
  const unsigned long bit_position = 7 - (bit_index & 7);
  unsigned char byte;
  SafeFSeek(file, byte_index, SEEK_SET);
  byte = SafeFGetC(file);
  return (byte >> bit_position) & 1;
}
static void SetBit(FILE *const file, const unsigned long bit_index) {
  const unsigned long byte_index = bit_index >> 3;
  const unsigned long bit_position = 7 - (bit_index & 7);
  unsigned char byte;
  SafeFSeek(file, byte_index, SEEK_SET);
  byte = SafeFGetC(file) | 1 << bit_position;
  SafeFSeek(file, -1, SEEK_CUR);
  SafeFPutC(byte, file);
}
void BloomAdd(const char *const string, const unsigned long length,
              const Bloom bloom) {
  unsigned char hash[kHashLength];
  unsigned char i;
  unsigned long hash_1;
  unsigned long hash_2;
  unsigned long combined_hash;
  Hash(hash, string, length);
  hash_1 = BytesToUInt32(hash);
  hash_2 = BytesToUInt32(hash + 4);
  combined_hash = hash_1;
  for (i = 0; i < bloom.hash_count; ++i) {
    SetBit(bloom.file, combined_hash & ((1 << bloom.bit_count) - 1));
    combined_hash += hash_2;
  }
}
unsigned char BloomCheck(const char *const string, const unsigned long length,
                         const Bloom bloom) {
  unsigned char hash[kHashLength];
  unsigned char i;
  unsigned long hash_1;
  unsigned long hash_2;
  unsigned long combined_hash;
  Hash(hash, string, length);
  hash_1 = BytesToUInt32(hash);
  hash_2 = BytesToUInt32(hash + 4);
  combined_hash = hash_1;
  for (i = 0; i < bloom.hash_count; ++i) {
    if (!GetBit(bloom.file, combined_hash & ((1 << bloom.bit_count) - 1))) {
      return 0;
    }
    combined_hash += hash_2;
  }
  return 1;
}
#endif
