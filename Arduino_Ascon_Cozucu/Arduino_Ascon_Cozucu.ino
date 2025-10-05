// ascon_pkt_decode.ino
// Decode PKT from FPGA: derive K_i via Ascon-XOF128, then Ascon-128a decrypt+verify.
// Serial monitor: 115200 baud. Paste a full line like:
// PKT;ver=1;nonce_hex=...;aad_hex=...;ct_hex=...;tag_hex=...

#include <Arduino.h>
#include <stdint.h>

// ======== Config (must match FPGA) ========
static const uint8_t S_ROOT[32] = {
  0xDE,0xAD,0xBE,0xEF, 0xFE,0xED,0xFA,0xCE,
  0xBA,0xAD,0xF0,0x0D, 0x12,0x34,0x56,0x78,
  0x90,0xAB,0xCD,0xEF, 0x11,0x22,0x33,0x44,
  0x55,0x66,0x77,0x88, 0x99,0xAA,0xBB,0xCC
};
static const uint8_t POOL[4][16] = {
  {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C, 0x0D,0x0E,0x0F,0x10},
  {0x1A,0x1B,0x1C,0x1D, 0x1E,0x1F,0x20,0x21, 0x22,0x23,0x24,0x25, 0x26,0x27,0x28,0x29},
  {0xFE,0xFD,0xFC,0xFB, 0xFA,0xF9,0xF8,0xF7, 0xF6,0xF5,0xF4,0xF3, 0xF2,0xF1,0xF0,0xEF},
  {0x77,0x88,0x99,0xAA, 0xBB,0xCC,0xDD,0xEE, 0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80}
};

// ======== Small utils ========
static inline uint32_t load32_be(const uint8_t* p){
  return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]);
}
static inline uint64_t load64_be(const uint8_t* p){
  return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|
         ((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8)|((uint64_t)p[7]);
}
static inline void store64_be(uint8_t* p, uint64_t x){
  p[0]=x>>56; p[1]=x>>48; p[2]=x>>40; p[3]=x>>32; p[4]=x>>24; p[5]=x>>16; p[6]=x>>8; p[7]=x;
}
static uint8_t hexNib(char c){
  if (c>='0'&&c<='9') return (uint8_t)(c-'0');
  if (c>='a'&&c<='f') return (uint8_t)(c-'a'+10);
  if (c>='A'&&c<='F') return (uint8_t)(c-'A'+10);
  return 0;
}
static size_t hexToBytes(const char* s, uint8_t* out, size_t maxOut){
  size_t n = 0;
  while (s[0] && s[1]){
    if (s[0]==';' || s[0]=='\r' || s[0]=='\n') break;
    if (n>=maxOut) break;
    uint8_t hi=hexNib(s[0]), lo=hexNib(s[1]);
    out[n++] = (uint8_t)((hi<<4)|lo);
    s+=2;
    if (*s==' '){ ++s; } // tolerate spaces
  }
  return n;
}
static void printHex(const char* label, const uint8_t* p, size_t n){
  Serial.print(label);
  for (size_t i=0;i<n;i++){
    if (p[i]<16) Serial.print('0');
    Serial.print(p[i], HEX);
    if ((i&0x0F)==0x0F) Serial.print("\r\n");
    else Serial.print(' ');
  }
  if ((n&0x0F)!=0) Serial.print("\r\n");
}

// ======== ASCON core (same as FPGA) ========
#define ASCON_AEAD128_IV 0x80800c0800000000ULL
#define ASCON_XOF128_IV  0x00800c0000000000ULL

static const uint8_t RC12[12] = {0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,0x78,0x69,0x5A,0x4B};
static const uint8_t RC8[8]   = {0xB4,0xA5,0x96,0x87,0x78,0x69,0x5A,0x4B};

static inline uint64_t ROR64(uint64_t x, unsigned n){ return (x>>n) | (x<<(64u-n)); }

static inline void ascon_round(uint64_t &x0,uint64_t &x1,uint64_t &x2,uint64_t &x3,uint64_t &x4, uint8_t rc){
  x2 ^= (uint64_t)rc;
  x0 ^= x4;  x4 ^= x3;  x2 ^= x1;
  uint64_t t0=~x0, t1=~x1, t2=~x2, t3=~x3, t4=~x4;
  t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
  x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
  x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;
  x0 ^= ROR64(x0,19) ^ ROR64(x0,28);
  x1 ^= ROR64(x1,61) ^ ROR64(x1,39);
  x2 ^= ROR64(x2, 1) ^ ROR64(x2, 6);
  x3 ^= ROR64(x3,10) ^ ROR64(x3,17);
  x4 ^= ROR64(x4, 7) ^ ROR64(x4,41);
}
static inline void P12(uint64_t &x0,uint64_t &x1,uint64_t &x2,uint64_t &x3,uint64_t &x4){
  for (int i=0;i<12;i++) ascon_round(x0,x1,x2,x3,x4,RC12[i]);
}
static inline void P8(uint64_t &x0,uint64_t &x1,uint64_t &x2,uint64_t &x3,uint64_t &x4){
  for (int i=0;i<8;i++) ascon_round(x0,x1,x2,x3,x4,RC8[i]);
}
static inline void absorb_xor_16(uint64_t &x0,uint64_t &x1,const uint8_t *in,size_t len){
  size_t i=0;
  for (; i<len && i<8; i++) x0 ^= (uint64_t)in[i] << (56 - 8*i);
  for (; i<len; i++)       x1 ^= (uint64_t)in[i] << (56 - 8*(i-8));
}
static inline void squeeze_16(uint8_t *out, size_t len, uint64_t x0,uint64_t x1){
  uint8_t tmp[16];
  store64_be(tmp, x0); store64_be(tmp+8, x1);
  for (size_t i=0;i<len;i++) out[i]=tmp[i];
}

// XOF: exactly as FPGA
static void ascon_xof128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen){
  uint64_t x0=ASCON_XOF128_IV, x1=0, x2=0, x3=0, x4=0;
  while (inlen >= 16){
    x0 ^= load64_be(in); x1 ^= load64_be(in+8);
    P12(x0,x1,x2,x3,x4);
    in += 16; inlen -= 16;
  }
  if (inlen){
    absorb_xor_16(x0,x1,in,inlen);
    if (inlen < 8) x0 ^= (uint64_t)0x80 << (56 - 8*inlen);
    else           x1 ^= (uint64_t)0x80 << (56 - 8*(inlen-8));
  } else {
    x0 ^= (uint64_t)0x80 << 56;
  }
  P12(x0,x1,x2,x3,x4);
  while (outlen){
    size_t n = (outlen < 16) ? outlen : 16;
    squeeze_16(out, n, x0, x1);
    out += n; outlen -= n;
    if (outlen) P12(x0,x1,x2,x3,x4);
  }
}

// AEAD128a decrypt+verify (mirrors your encrypt code)
static bool ascon_aead128_decrypt(
  const uint8_t key[16], const uint8_t nonce[16],
  const uint8_t *aad, size_t aad_len,
  const uint8_t *ct, size_t ct_len,
  const uint8_t tag[16],
  uint8_t *pt_out // may be null
){
  uint64_t x0 = ASCON_AEAD128_IV;
  uint64_t k0 = load64_be(key), k1 = load64_be(key+8);
  uint64_t n0 = load64_be(nonce), n1 = load64_be(nonce+8);
  uint64_t x1 = k0, x2 = k1, x3 = n0, x4 = n1;

  // Init
  P12(x0,x1,x2,x3,x4);
  x3 ^= k0; x4 ^= k1;

  // AAD
  if (aad_len){
    while (aad_len >= 16){
      x0 ^= load64_be(aad);
      x1 ^= load64_be(aad+8);
      P8(x0,x1,x2,x3,x4);
      aad += 16; aad_len -= 16;
    }
    if (aad_len){
      absorb_xor_16(x0,x1,aad,aad_len);
      if (aad_len < 8) x0 ^= (uint64_t)0x80 << (56 - 8*aad_len);
      else             x1 ^= (uint64_t)0x80 << (56 - 8*(aad_len-8));
      P8(x0,x1,x2,x3,x4);
    }
  }
  x4 ^= 1; // domain sep

  // Full 16B blocks
  while (ct_len >= 16){
    uint64_t c0 = load64_be(ct);
    uint64_t c1 = load64_be(ct+8);
    uint64_t m0 = x0 ^ c0;
    uint64_t m1 = x1 ^ c1;
    if (pt_out){
      store64_be(pt_out,   m0);
      store64_be(pt_out+8, m1);
      pt_out += 16;
    }
    x0 = c0; x1 = c1;
    P8(x0,x1,x2,x3,x4);
    ct += 16; ct_len -= 16;
  }

  // Last partial
  if (ct_len){
    uint8_t tmp[16];
    squeeze_16(tmp, 16, x0, x1);
    uint8_t last[16]; // pt for absorb
    for (size_t i=0;i<ct_len;i++){
      uint8_t m = ct[i] ^ tmp[i];
      if (pt_out) pt_out[i] = m;
      last[i] = m;
    }
    absorb_xor_16(x0,x1,last, ct_len);
    if (ct_len < 8) x0 ^= (uint64_t)0x80 << (56 - 8*ct_len);
    else            x1 ^= (uint64_t)0x80 << (56 - 8*(ct_len-8));
  }

  // Final + Tag
  x1 ^= k0; x2 ^= k1;
  P12(x0,x1,x2,x3,x4);
  x3 ^= k0; x4 ^= k1;

  uint8_t tag2[16];
  store64_be(tag2,   x3);
  store64_be(tag2+8, x4);

  // constant-time compare
  uint8_t diff=0;
  for (int i=0;i<16;i++) diff |= (uint8_t)(tag2[i]^tag[i]);
  return diff==0;
}

// ======== KDF (same as FPGA) ========
static void kdf_from_xof(const uint8_t S_root[32], uint32_t device_id,
                         const uint8_t slice_i[16],
                         uint8_t K_out16[16]){
  uint8_t buf[3+32+4+16];
  size_t p=0;
  buf[p++]='K'; buf[p++]='D'; buf[p++]='F';
  memcpy(buf+p, S_root, 32); p+=32;
  buf[p++] = (uint8_t)(device_id>>24);
  buf[p++] = (uint8_t)(device_id>>16);
  buf[p++] = (uint8_t)(device_id>> 8);
  buf[p++] = (uint8_t)(device_id     );
  memcpy(buf+p, slice_i, 16); p+=16;
  ascon_xof128(buf, p, K_out16, 16);
}

// ======== PKT parsing ========
static bool getField(const String& line, const char* key, String& out){
  int k = line.indexOf(key);
  if (k<0) return false;
  k += strlen(key);
  int e = line.indexOf(';', k);
  if (e<0) e = line.length();
  out = line.substring(k, e);
  out.trim();
  return true;
}

void setup(){
  Serial.begin(115200);
  while(!Serial){;}
  Serial.println(F("[ardu] ready. paste PKT line:"));
}

void loop(){
  static String line;
  if (Serial.available()){
    char c = (char)Serial.read();
    if (c=='\r') return;
    if (c!='\n'){ line += c; return; }

    // Got a line
    line.trim();
    if (line.length()==0){ line=""; return; }

    // Basic sanity
    if (!line.startsWith("PKT;ver=1")){
      Serial.println(F("[err ] not a PKT;ver=1 line"));
      line=""; return;
    }

    String sNonce, sAAD, sCT, sTAG;
    if (!getField(line, "nonce_hex=", sNonce) ||
        !getField(line, "aad_hex=",   sAAD)   ||
        !getField(line, "ct_hex=",    sCT)    ||
        !getField(line, "tag_hex=",   sTAG)){
      Serial.println(F("[err ] missing fields"));
      line=""; return;
    }

    // Buffers
    uint8_t nonce[16], aad[64], ct[1024], tag[16], pt[1024];
    size_t nNonce = hexToBytes(sNonce.c_str(), nonce, sizeof(nonce));
    size_t nAAD   = hexToBytes(sAAD.c_str(),   aad,   sizeof(aad));
    size_t nCT    = hexToBytes(sCT.c_str(),    ct,    sizeof(ct));
    size_t nTAG   = hexToBytes(sTAG.c_str(),   tag,   sizeof(tag));
    if (nNonce!=16 || nTAG!=16){
      Serial.println(F("[err ] bad nonce/tag length"));
      line=""; return;
    }

    // Pull device_id and index from AAD layout:
    // AAD = ver(1), dev(4,BE), idx(1), msg_ctr(8,BE), feat(1) [, ts(8)]
    if (nAAD!=15 && nAAD!=23){
      Serial.print(F("[err ] AAD len != 15/23, got ")); Serial.println(nAAD);
      line=""; return;
    }
    uint8_t  ver  = aad[0];
    uint32_t dev  = load32_be(aad+1);
    uint8_t  idx  = aad[5] & 0x03; // we only have 4 slices
    // uint64_t msg = load64_be(aad+6); // not needed for KDF
    // uint8_t  feat= aad[14];

    // Derive K_i
    uint8_t K_i[16];
    kdf_from_xof(S_ROOT, dev, POOL[idx], K_i);

    // Decrypt+verify
    bool ok = ascon_aead128_decrypt(K_i, nonce, aad, nAAD, ct, nCT, tag, pt);

    // Report
    Serial.print(F("[aad ] ver=")); Serial.println(ver);
    Serial.print(F("[aad ] dev=")); Serial.println(dev);
    Serial.print(F("[aad ] idx=")); Serial.println(idx);
    Serial.print(F("[res ] tag=")); Serial.println(ok ? F("OK") : F("FAIL"));
    if (ok){
      Serial.print(F("[pt  ] len=")); Serial.println(nCT);
      Serial.print(F("[pt  ] ascii: "));
      // Print ASCII safely
      for (size_t i=0;i<nCT;i++){
        char ch = (char)pt[i];
        if (ch>=32 && ch<=126) Serial.print(ch); else Serial.print('.');
      }
      Serial.print("\r\n");
      printHex("[pt  ] hex: ", pt, nCT);
    } else {
      // still show PT-guess (not authenticated) if you want:
      // printHex("[pt? ] hex: ", pt, nCT);
    }

    // Debug (optional)
    // printHex("[kdf ] K_i: ", K_i, 16);
    // printHex("[nonce] ", nonce, 16);
    // printHex("[aad  ] ", aad, nAAD);
    // printHex("[ct   ] ", ct, nCT);
    // printHex("[tag  ] ", tag, 16);

    line = "";
    Serial.println(F("----"));
  }
}
