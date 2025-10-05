// ascon_pkt_decode_dual_experiment.ino
// Orijinal çözücüyü KORUR + iki deney ekler:
//  (1) Brute-force hız ölçümü (tek PKT'ye karşı)
//  (2) Sızıntı etkisi (Sade K sızıntısı vs HSF tek K_i sızıntısı)
//
// Seri @115200
// Komutlar:
//   PKT;ver=1;nonce_hex=...;aad_hex=...;ct_hex=...;tag_hex=...   (decode + depoya ekler)
//   B <ms>         : brute-force süresi (vars. 3000 ms)
//   LEAKK <hex32>  : sade-ASCON anahtarı (16B)
//   LEAKKI <hex32> : HSF tek-paket anahtarı K_i (16B)
//   RUN            : Deney-1 + Deney-2 sırayla
// ascon_pkt_decode_dual_experiment.ino
// Orijinal çözücüyü KORUR + iki deney ekler:
//  (1) Brute-force hız ölçümü (tek PKT'ye karşı)
//  (2) Sızıntı etkisi (Sade K sızıntısı vs HSF tek K_i sızıntısı)
//
// Seri @115200
// Komutlar:
//   PKT;ver=1;nonce_hex=...;aad_hex=...;ct_hex=...;tag_hex=...   (decode + depoya ekler)
//   B <ms>         : brute-force süresi (vars. 3000 ms)
//   LEAKK <hex32>  : sade-ASCON anahtarı (16B)
//   LEAKKI <hex32> : HSF tek-paket anahtarı K_i (16B)
//   RUN            : Deney-1 + Deney-2 sırayla

// ascon_pkt_decode_dual_experiment.ino
// Orijinal çözücüne sadık + İki deney (BF hız & sızıntı etkisi)
// Serial@115200
//
// Komutlar:
//   - PKT;ver=1;nonce_hex=...;aad_hex=...;ct_hex=...;tag_hex=...   (paketi ekler + anında decode eder)
//   - B <ms>         : brute-force ölçüm süresi (default 3000 ms)
//   - LEAKK <hex32>  : sade-ASCON anahtarı sızıntısı (16B)
//   - LEAKKI <hex32> : HSF tek-paket anahtarı K_i sızıntısı (16B)
//   - RUN            : Deney-1 (BF hız) + Deney-2 (LEAKK / LEAKKI)
//
// Notlar:
// - Mevcut decode akışı, zaman raporları korunmuştur.
// - Deney-1: Seçilen bir PKT'ye karşı rastgele 128-bit anahtar dener; deneme/s ve ETA(50%) basar.
// - Deney-2: LEAKK varsa bütün PKT'leri tek K ile; LEAKKI varsa bütün PKT'leri tek K_i ile dener.
//             Sade modda çoklu OK; HSF modunda ~1 OK beklenir (hasar izolasyonu).

// PKT;ver=1;nonce_hex=AABBCCDD0000000100000000000001B5;aad_hex=01AABBCCDD0000000000000001B501;ct_hex=6A871B28863DC2E231E680C8BDD8A0AF;tag_hex=553CDB5C2557EBAA992E53CE0AB5AE19

#include "packet.h"
#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <math.h> // log10, pow

// ===== ETA yardımcı sabitleri =====
static constexpr double LOG10_2 = 0.3010299956639812;
static constexpr double SEC_PER_YEAR = 31557600.0;  // 365.25 gün
static constexpr double LOG10_2_POW_127 = 127.0 * LOG10_2;

// --- timing helpers: micros() -> cycles ---
static inline uint32_t us_to_cycles(uint32_t us){
  return (uint32_t)(((uint64_t)us * (F_CPU / 1000000UL)));
}

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
    if (*s==' '){ ++s; }
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

// ======== ASCON core ========
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

// XOF (FPGA ile birebir)
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

// AEAD128a decrypt+verify (orijinal tarz)
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

  P12(x0,x1,x2,x3,x4);
  x3 ^= k0; x4 ^= k1;

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

  if (ct_len){
    uint8_t tmp[16];
    squeeze_16(tmp, 16, x0, x1);
    uint8_t last[16];
    for (size_t i=0;i<ct_len;i++){
      uint8_t m = ct[i] ^ tmp[i];
      if (pt_out) pt_out[i] = m;
      last[i] = m;
    }
    absorb_xor_16(x0,x1,last, ct_len);
    if (ct_len < 8) x0 ^= (uint64_t)0x80 << (56 - 8*ct_len);
    else            x1 ^= (uint64_t)0x80 << (56 - 8*(ct_len-8));
  }

  x1 ^= k0; x2 ^= k1;
  P12(x0,x1,x2,x3,x4);
  x3 ^= k0; x4 ^= k1;

  uint8_t tag2[16];
  store64_be(tag2,   x3);
  store64_be(tag2+8, x4);

  uint8_t diff=0;
  for (int i=0;i<16;i++) diff |= (uint8_t)(tag2[i]^tag[i]);
  return diff==0;
}

// ======== KDF ========
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

// ======== PKT store (deney için) – TANIMI ÖNE ALINDI ========
#define MAX_PKTS    64
#define MAX_CT_LEN  256

static Packet PKTS[MAX_PKTS];
static uint16_t PKT_COUNT = 0;

// Sızıntı anahtarları + BF süresi
static bool have_leakK=false, have_leakKi=false;
static uint8_t leakK[16], leakKi[16];
static uint32_t bf_ms = 3000;

// ======== Parser helpers ========
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

// ======== PRNG (BF için) ========
static uint64_t xs = 0x1234567890ABCDEFull;
static inline uint64_t xorshift64s() {
  xs ^= xs >> 12; xs ^= xs << 25; xs ^= xs >> 27;
  return xs * 0x2545F4914F6CDD1DULL;
}
static inline void next_key(uint8_t k[16]) {
  uint64_t a = xorshift64s();
  uint64_t b = xorshift64s();
  memcpy(k, &a, 8);
  memcpy(k+8, &b, 8);
}

static bool decrypt_with_key(const Packet& p, const uint8_t key[16]){
  return ascon_aead128_decrypt(key, p.nonce, p.aad, p.aadlen, p.ct, p.ctlen, p.tag, nullptr);
}

static void print_sci_years(double log10_years){
  int exp10 = (int)floor(log10_years);
  double mant = pow(10.0, log10_years - exp10);
  Serial.print(mant, 3);
  Serial.print("e+");
  Serial.print(exp10);
  Serial.print(" years");
}

// ======== Deney-1: Brute-force hız ========
static void run_bruteforce_ms(const Packet& p, uint32_t ms){
  Serial.println(F("[BF ] brute-force hiz olcumu basladi"));
  uint32_t t0 = millis();
  uint32_t last_us = micros();
  uint64_t tries = 0, tries_last = 0;
  uint8_t k[16];
  uint32_t bogus=0;

  while ((millis()-t0) < ms){
    next_key(k);
    bool ok = decrypt_with_key(p, k);
    if (ok) bogus++;
    tries++;

    if ((tries % 10000ULL)==0){
      uint32_t now = micros();
      uint32_t dt = now - last_us;
      uint64_t dtries = tries - tries_last;
      double rate = (dt>0) ? ((double)dtries / ((double)dt/1e6)) : 0.0;
      Serial.print(F("[BF ] tries=")); Serial.print((unsigned long)tries);
      Serial.print(F("  rate=")); Serial.print(rate,1); Serial.println(F(" /s"));
      last_us = now; tries_last = tries;
    }
  }
  double rate = (double)tries / ((double)(millis()-t0)/1000.0);
  Serial.print(F("[BF ] done  tries=")); Serial.print((unsigned long)tries);
  Serial.print(F("  avg_rate=")); Serial.print(rate,1); Serial.println(F(" /s"));
  double log10_years = LOG10_2_POW_127 - log10(rate) - log10(SEC_PER_YEAR);
  Serial.print(F("[BF ] ETA(50%) ≈ ")); print_sci_years(log10_years); Serial.println();
  Serial.print(F("[BF ] bogus_successes=")); Serial.println(bogus);
}

// ======== Deney-2: Sızıntı etkisi ========
static void run_leakage_tests(){
  if (PKT_COUNT==0){ Serial.println(F("[LEAK] PKT yok.")); return; }
  if (!have_leakK && !have_leakKi){ Serial.println(F("[LEAK] LEAKK/LEAKKI yok.")); return; }
  auto now_us = [](){ return micros(); };

  if (have_leakK){
    uint32_t t0=now_us(); uint32_t ok=0;
    for (uint16_t i=0;i<PKT_COUNT;i++){
      if (!PKTS[i].used) continue;
      if (decrypt_with_key(PKTS[i], leakK)) ok++;
    }
    uint32_t dt=now_us()-t0;
    Serial.print(F("[LEAK] SADE  K sizintisi: ok=")); Serial.print(ok);
    Serial.print(F("/")); Serial.print(PKT_COUNT);
    Serial.print(F("  time=")); Serial.print(dt); Serial.println(F(" us"));
    // ... LEAKK bloğunun sonunda:
    double per_pkt_us = PKT_COUNT ? (double)dt / (double)PKT_COUNT : 0.0;
    uint32_t est10k_us = (uint32_t)(per_pkt_us * 10000.0 + 0.5);
    Serial.print(F("[LEAK] SADE  est@10000pkts time≈ "));
    Serial.print(est10k_us);
    Serial.println(F(" us (ok≈10000/10000)"));
  }

  if (have_leakKi){
    uint32_t t0=now_us(); uint32_t ok=0;
    for (uint16_t i=0;i<PKT_COUNT;i++){
      if (!PKTS[i].used) continue;
      if (decrypt_with_key(PKTS[i], leakKi)) ok++;
    }
    uint32_t dt=now_us()-t0;
    Serial.print(F("[LEAK] HSF tek K_i:    ok=")); Serial.print(ok);
    Serial.print(F("/")); Serial.print(PKT_COUNT);
    Serial.print(F("  time=")); Serial.print(dt); Serial.println(F(" us"));
    Serial.println(F("[LEAK] Beklenti: ok≈1 (yalniz sizan pakette)."));
    // ... LEAKKI bloğunun sonunda:
    double per_pkt_us = PKT_COUNT ? (double)dt / (double)PKT_COUNT : 0.0;
    uint32_t est10k_us = (uint32_t)(per_pkt_us * 10000.0 + 0.5);
    Serial.print(F("[LEAK] HSF   est@10000pkts time≈ "));
    Serial.print(est10k_us);
    Serial.println(F(" us (ok≈1/10000)"));
  }
}

// ======== Ana akış: orijinal decode + komutlar ========
void setup(){
  Serial.begin(115200);
  while(!Serial){;}
  Serial.println(F("[ardu] ready. paste PKT or commands (B/LEAKK/LEAKKI/RUN)"));
}

static String line;

void loop(){
  if (!Serial.available()) return;
  char c = (char)Serial.read();
  if (c=='\r') return;
  if (c!='\n'){ line += c; return; }

  line.trim();
  if (line.length()==0){ line=""; return; }

  // Komutlar
  if (line.startsWith("B ")){
    long v = atol(line.c_str()+2);
    if (v>0 && v<600000){ bf_ms=(uint32_t)v; Serial.print(F("[cfg ] BF ms=")); Serial.println(bf_ms); }
    else Serial.println(F("[cfg ] BF ms out of range"));
    line=""; return;
  }
  if (line.startsWith("LEAKK ")){
    int n = hexToBytes(line.c_str()+6, leakK, 16);
    if (n==16){ have_leakK=true; Serial.println(F("[LEAKK] set OK")); }
    else Serial.println(F("[LEAKK] hex err"));
    line=""; return;
  }
  if (line.startsWith("LEAKKI ")){
    int n = hexToBytes(line.c_str()+7, leakKi, 16);
    if (n==16){ have_leakKi=true; Serial.println(F("[LEAKKI] set OK")); }
    else Serial.println(F("[LEAKKI] hex err"));
    line=""; return;
  }
  if (line.equals("RUN")){
    if (PKT_COUNT==0){ Serial.println(F("[RUN ] once PKT lazim")); line=""; return; }
    run_bruteforce_ms(PKTS[0], bf_ms);
    run_leakage_tests();
    Serial.println(F("[RUN ] tamam"));
    line=""; return;
  }

  // ---- PKT decode (orijinal akış) ----
  if (!line.startsWith("PKT;ver=1")){
    Serial.println(F("[err ] not a PKT;ver=1 line"));
    line=""; return;
  }

  uint32_t t_total0 = micros();
  uint32_t t_parse0 = micros();

  String sNonce, sAAD, sCT, sTAG;
  if (!getField(line, "nonce_hex=", sNonce) ||
      !getField(line, "aad_hex=",   sAAD)   ||
      !getField(line, "ct_hex=",    sCT)    ||
      !getField(line, "tag_hex=",   sTAG)){
    Serial.println(F("[err ] missing fields"));
    line=""; return;
  }

  uint8_t nonce[16], aad[64], ct[1024], tag[16], pt[1024];
  size_t nNonce = hexToBytes(sNonce.c_str(), nonce, sizeof(nonce));
  size_t nAAD   = hexToBytes(sAAD.c_str(),   aad,   sizeof(aad));
  size_t nCT    = hexToBytes(sCT.c_str(),    ct,    sizeof(ct));
  size_t nTAG   = hexToBytes(sTAG.c_str(),   tag,   sizeof(tag));
  if (nNonce!=16 || nTAG!=16){
    Serial.println(F("[err ] bad nonce/tag length"));
    line=""; return;
  }
  uint32_t t_parse1 = micros();
  uint32_t us_parse = t_parse1 - t_parse0;

  if (nAAD!=15 && nAAD!=23){
    Serial.print(F("[err ] AAD len != 15/23, got ")); Serial.println(nAAD);
    line=""; return;
  }
  uint8_t  ver  = aad[0];
  uint32_t dev  = load32_be(aad+1);
  uint8_t  idx  = aad[5] & 0x03; // 4 slice

  uint8_t K_i[16];
  uint32_t t_kdf0 = micros();
  kdf_from_xof(S_ROOT, dev, POOL[idx], K_i);
  uint32_t t_kdf1 = micros();
  uint32_t us_kdf = t_kdf1 - t_kdf0;

  uint32_t t_aead0 = micros();
  bool ok = ascon_aead128_decrypt(K_i, nonce, aad, nAAD, ct, nCT, tag, pt);
  uint32_t t_aead1 = micros();
  uint32_t us_aead = t_aead1 - t_aead0;

  uint32_t t_total1 = micros();
  uint32_t us_total = t_total1 - t_total0;

  uint32_t c_parse = us_to_cycles(us_parse);
  uint32_t c_kdf   = us_to_cycles(us_kdf);
  uint32_t c_aead  = us_to_cycles(us_aead);
  uint32_t c_total = us_to_cycles(us_total);

  Serial.print(F("[aad ] ver=")); Serial.println(ver);
  Serial.print(F("[aad ] dev=")); Serial.println(dev);
  Serial.print(F("[aad ] idx=")); Serial.println(idx);
  Serial.print(F("[res ] tag=")); Serial.println(ok ? F("OK") : F("FAIL"));
  if (ok){
    Serial.print(F("[pt  ] len=")); Serial.println(nCT);
    Serial.print(F("[pt  ] ascii: "));
    for (size_t i=0;i<nCT;i++){
      char ch = (char)pt[i];
      if (ch>=32 && ch<=126) Serial.print(ch); else Serial.print('.');
    }
    Serial.print("\r\n");
    printHex("[pt  ] hex: ", pt, nCT);
  }
  printHex("[kdf ] K_i: ", K_i, 16);
  printHex("[nonce] ", nonce, 16);
  printHex("[aad  ] ", aad, nAAD);
  printHex("[ct   ] ", ct, nCT);
  printHex("[tag  ] ", tag, 16);

  Serial.print(F("[tim ] parse_us="));   Serial.print(us_parse);
  Serial.print(F(" ; parse_cycles="));   Serial.println(c_parse);

  Serial.print(F("[tim ] kdf_us="));     Serial.print(us_kdf);
  Serial.print(F(" ; kdf_cycles="));     Serial.println(c_kdf);

  Serial.print(F("[tim ] aead_us="));    Serial.print(us_aead);
  Serial.print(F(" ; aead_cycles="));    Serial.println(c_aead);

  Serial.print(F("[tim ] total_us="));   Serial.print(us_total);
  Serial.print(F(" ; total_cycles="));   Serial.println(c_total);

  Serial.print(F("[info] F_CPU=")); Serial.println(F_CPU);
  Serial.println(F("----"));

  // Depoya ekle
  if (PKT_COUNT < MAX_PKTS){
    Packet &P = PKTS[PKT_COUNT++];
    memcpy(P.nonce, nonce, 16);
    memcpy(P.tag,   tag,   16);
    P.aadlen = (uint16_t)nAAD;
    memcpy(P.aad, aad, P.aadlen);
    P.ctlen = (uint16_t)nCT;
    if (P.ctlen > MAX_CT_LEN) P.ctlen = MAX_CT_LEN;
    memcpy(P.ct, ct, P.ctlen);
    P.used = true;
  } else {
    Serial.println(F("[warn] PKT depo dolu (MAX_PKTS)"));
  }

  line="";
}
