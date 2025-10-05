#pragma once
#include <stdint.h>
#define MAX_CT_LEN 256
struct Packet {
  uint8_t nonce[16];
  uint8_t aad[23];
  uint16_t aadlen;
  uint8_t ct[MAX_CT_LEN];
  uint16_t ctlen;
  uint8_t tag[16];
  bool used;
};
