// multi_aead_decode_sade.ino  (fixed)
// SADE modlarında PKT satırını çöz: ASCON-128a, ACORN-128, TinyJAMBU-128
// (JAMBU-PRESENT-128 gönderici varyantı terslenebilir değil -> loglarız)
// 115200 baud; PKT;ver=1;nonce_hex=...;aad_hex=...;ct_hex=...;tag_hex=...

#include <Arduino.h>
#include <stdint.h>
#include <string.h>

// ---- ACORN tip tanımı: Sget/Sxor'dan ÖNCE olmalı ----
#ifndef ACORN_STATE_T_DEFINED
#define ACORN_STATE_T_DEFINED 1

#include <stdint.h>   // zaten varsa sorun değil
#define ACORN_STATE_BITS 293

// ACORN kaydırgaç durumu 293 bit; 5*64 = 320 bitlik alanda tutuluyor
typedef struct acorn_state_t {
  uint64_t w[5];
} acorn_state_t;

#endif // ACORN_STATE_T_DEFINED


/* ====================== Small utils ====================== */
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
  size_t n=0;
  while (s[0] && s[1]){
    if (s[0]==';' || s[0]=='\r' || s[0]=='\n') break;
    if (n>=maxOut) break;
    uint8_t hi=hexNib(s[0]), lo=hexNib(s[1]);
    out[n++] = (uint8_t)((hi<<4)|lo);
    s+=2;
    if (*s==' ') ++s;
  }
  return n;
}
static void printHex(const char* label, const uint8_t* p, size_t n){
  Serial.print(label);
  for (size_t i=0;i<n;i++){
    if (p[i]<16) Serial.print('0');
    Serial.print(p[i], HEX);
    Serial.print((i%16==15)?"\r\n":" ");
  }
  if (n%16) Serial.print("\r\n");
}
static inline uint32_t approx_cycles_from_us(uint32_t us){
#if F_CPU >= 1000000UL
  uint64_t num = (uint64_t)us * (uint64_t)F_CPU + 500000ULL;
  return (uint32_t)(num / 1000000ULL);
#else
  return 0;
#endif
}

/* =========================================================
 *                     ASCON-128a (decrypt+verify)
 * ========================================================= */
#define ASCON_AEAD128_IV 0x80800c0800000000ULL
#define ASCON_XOF128_IV  0x00800c0000000000ULL
static const uint8_t RC12[12]={0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,0x78,0x69,0x5A,0x4B};
static const uint8_t RC8[8]  ={0xB4,0xA5,0x96,0x87,0x78,0x69,0x5A,0x4B};
static inline uint64_t ROR64(uint64_t x, unsigned n){ return (x>>n)|(x<<(64u-n)); }
static inline void ascon_round(uint64_t &x0,uint64_t &x1,uint64_t &x2,uint64_t &x3,uint64_t &x4, uint8_t rc){
  x2^=(uint64_t)rc; x0^=x4; x4^=x3; x2^=x1;
  uint64_t t0=~x0, t1=~x1, t2=~x2, t3=~x3, t4=~x4;
  t0&=x1; t1&=x2; t2&=x3; t3&=x4; t4&=x0;
  x0^=t1; x1^=t2; x2^=t3; x3^=t4; x4^=t0;
  x1^=x0; x0^=x4; x3^=x2; x2=~x2;
  x0^=ROR64(x0,19)^ROR64(x0,28);
  x1^=ROR64(x1,61)^ROR64(x1,39);
  x2^=ROR64(x2, 1)^ROR64(x2, 6);
  x3^=ROR64(x3,10)^ROR64(x3,17);
  x4^=ROR64(x4, 7)^ROR64(x4,41);
}
static inline void P12(uint64_t &x0,uint64_t &x1,uint64_t &x2,uint64_t &x3,uint64_t &x4){ for(int i=0;i<12;i++) ascon_round(x0,x1,x2,x3,x4,RC12[i]); }
static inline void P8 (uint64_t &x0,uint64_t &x1,uint64_t &x2,uint64_t &x3,uint64_t &x4){ for(int i=0;i<8 ;i++) ascon_round(x0,x1,x2,x3,x4,RC8[i]); }
static inline void absorb_xor_16(uint64_t &x0,uint64_t &x1,const uint8_t*in,size_t len){
  size_t i=0; for(; i<len && i<8; i++) x0^=(uint64_t)in[i]<<(56-8*i);
  for(; i<len; i++)                    x1^=(uint64_t)in[i]<<(56-8*(i-8));
}
static inline void squeeze_16(uint8_t*out,size_t len,uint64_t x0,uint64_t x1){
  uint8_t t[16]; store64_be(t,x0); store64_be(t+8,x1);
  for(size_t i=0;i<len;i++) out[i]=t[i];
}
static bool ascon128a_decrypt_verify(const uint8_t key[16], const uint8_t nonce[16],
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* ct,  size_t ct_len,
                                     const uint8_t tag[16],
                                     uint8_t* pt_out /* may be null */)
{
  uint64_t x0=ASCON_AEAD128_IV;
  uint64_t k0=load64_be(key), k1=load64_be(key+8);
  uint64_t n0=load64_be(nonce), n1=load64_be(nonce+8);
  uint64_t x1=k0,x2=k1,x3=n0,x4=n1;
  P12(x0,x1,x2,x3,x4); x3^=k0; x4^=k1;

  if(aad_len){
    while(aad_len>=16){ x0^=load64_be(aad); x1^=load64_be(aad+8); P8(x0,x1,x2,x3,x4); aad+=16; aad_len-=16; }
    if(aad_len){ absorb_xor_16(x0,x1,aad,aad_len);
      if(aad_len<8) x0^=(uint64_t)0x80<<(56-8*aad_len); else x1^=(uint64_t)0x80<<(56-8*(aad_len-8)); P8(x0,x1,x2,x3,x4);
    }
  }
  x4 ^= 1;

  while(ct_len>=16){
    uint64_t c0=load64_be(ct), c1=load64_be(ct+8);
    uint64_t m0=x0^c0, m1=x1^c1;
    if (pt_out){ store64_be(pt_out, m0); store64_be(pt_out+8, m1); pt_out+=16; }
    x0=c0; x1=c1; P8(x0,x1,x2,x3,x4);
    ct+=16; ct_len-=16;
  }
  if(ct_len){
    uint8_t t[16]; squeeze_16(t,16,x0,x1);
    uint8_t last[16]; for(size_t i=0;i<ct_len;i++){ uint8_t m=ct[i]^t[i]; if(pt_out) pt_out[i]=m; last[i]=m; }
    absorb_xor_16(x0,x1,last,ct_len);
    if(ct_len<8) x0^=(uint64_t)0x80<<(56-8*ct_len); else x1^=(uint64_t)0x80<<(56-8*(ct_len-8));
  }
  x1^=k0; x2^=k1; P12(x0,x1,x2,x3,x4); x3^=k0; x4^=k1;
  uint8_t tag2[16]; store64_be(tag2,x3); store64_be(tag2+8,x4);
  uint8_t diff=0; for(int i=0;i<16;i++) diff|=(uint8_t)(tag2[i]^tag[i]);
  return diff==0;
}

/* =========================================================
 *                 ACORN-128 (decrypt+verify)
 *   (bit-serial; SADE key = 0xB0..BF)  — FIXED TYPE NAMES
 * ========================================================= */
#define ACORN_STATE_BITS 293

static inline uint32_t Sget(const acorn_state_t* S,int j){ return (uint32_t)((S->w[j>>6]>>(j&63))&1ULL); }
static inline void     Sxor(acorn_state_t* S,int j,uint32_t b){ if(b) S->w[j>>6]^=(1ULL<<(j&63)); }
static inline void     Sclr_hi(acorn_state_t* S){
  const int last=ACORN_STATE_BITS-1; const int lw=last>>6; const int keep=(last&63)+1;
  uint64_t mask=(keep==64)?~0ULL:((1ULL<<keep)-1ULL); for(int i=lw+1;i<5;i++) S->w[i]=0; S->w[lw]&=mask;
}
static inline uint32_t MAJ(uint32_t x,uint32_t y,uint32_t z){ return (x&y)^(x&z)^(y&z); }
static inline uint32_t CH (uint32_t x,uint32_t y,uint32_t z){ return (x&y)^((~x)&z); }
static inline uint32_t KSG128(const acorn_state_t* S){ return (uint32_t)( Sget(S,12)^Sget(S,154)^MAJ(Sget(S,235),Sget(S,61),Sget(S,193)) ); }
static inline uint32_t FBK128(const acorn_state_t* S,uint32_t ca,uint32_t cb){
  uint32_t ks=KSG128(S);
  uint32_t f=(uint32_t)( Sget(S,0) ^ (~Sget(S,107)&1u) ^ MAJ(Sget(S,244),Sget(S,23),Sget(S,160)) ^
                          CH(Sget(S,230),Sget(S,111),Sget(S,66)) ^ (ca&Sget(S,196)) ^ (cb&ks) );
  return f&1u;
}
static inline void StateUpdate128(acorn_state_t* S,uint32_t m,uint32_t ca,uint32_t cb){
  Sxor(S,289, Sget(S,235)^Sget(S,230));
  Sxor(S,230, Sget(S,196)^Sget(S,193));
  Sxor(S,193, Sget(S,160)^Sget(S,154));
  Sxor(S,154, Sget(S,111)^Sget(S,107));
  Sxor(S,107, Sget(S,66) ^Sget(S,61));
  Sxor(S,61 , Sget(S,23) ^Sget(S,0));
  uint32_t f=FBK128(S,ca,cb)^(m&1u);
  acorn_state_t old=*S; for(int i=0;i<5;i++) S->w[i]=0;
  S->w[0]=(old.w[0]>>1)|(old.w[1]<<63);
  S->w[1]=(old.w[1]>>1)|(old.w[2]<<63);
  S->w[2]=(old.w[2]>>1)|(old.w[3]<<63);
  S->w[3]=(old.w[3]>>1)|(old.w[4]<<63);
  S->w[4]=(old.w[4]>>1);
  Sclr_hi(S); if(f) S->w[(ACORN_STATE_BITS-1)>>6] |= (1ULL<<((ACORN_STATE_BITS-1)&63));
}
static inline uint32_t get_bit(const uint8_t*b, uint64_t pos){ return (b[pos>>3]>>(pos&7))&1u; }
static inline void     set_bit(uint8_t*b, uint64_t pos, uint32_t v){ if(v) b[pos>>3]|=(uint8_t)(1u<<(pos&7)); else b[pos>>3]&=(uint8_t)~(1u<<(pos&7)); }

static bool acorn128_decrypt_verify(const uint8_t K[16], const uint8_t N[16],
                                    const uint8_t *AAD, uint64_t aad_len,
                                    const uint8_t *CT,  uint64_t ct_len,
                                    const uint8_t TAG[16],
                                    uint8_t *PT /* may be null */)
{
  uint64_t aad_bits=aad_len*8ULL, msg_bits=ct_len*8ULL;
  acorn_state_t S; for(int i=0;i<5;i++) S.w[i]=0;

  // Init
  for(int i=0;i<128;i++) StateUpdate128(&S, get_bit(K,i), 1,1);
  for(int i=0;i<128;i++) StateUpdate128(&S, get_bit(N,i), 1,1);
  for(int i=0;i<1536;i++){ uint32_t mi=get_bit(K,i&127); if(i==0) mi^=1u; StateUpdate128(&S,mi,1,1); }

  // AAD
  for(uint64_t i=0;i<aad_bits+256;i++){
    uint32_t mi = (i<aad_bits)? get_bit(AAD,i) : (i==aad_bits);
    StateUpdate128(&S, mi, (i<aad_bits+128)?1u:0u, 1u);
  }

  // MSG (recover PT, update with PT)
  if (PT) memset(PT,0,(size_t)ct_len);
  for(uint64_t i=0;i<msg_bits+256;i++){
    uint32_t ca=(i<msg_bits+128)?1u:0u;
    uint32_t ks=KSG128(&S);
    if(i<msg_bits){
      uint32_t ci=get_bit(CT,i);
      uint32_t pi=ci ^ ks;
      if(PT) set_bit(PT,i,pi);
      StateUpdate128(&S,pi,ca,0);
    } else {
      StateUpdate128(&S,(i==msg_bits)?1u:0u,ca,0);
    }
  }

  // Final tag
  uint8_t tagbits[16]; memset(tagbits,0,16);
  for(int i=0;i<768;i++){ uint32_t ks=KSG128(&S); StateUpdate128(&S,0,1,1); if(i>=640){ set_bit(tagbits, i-640, ks); } }
  uint8_t diff=0; for(int i=0;i<16;i++) diff|=(uint8_t)(tagbits[i]^TAG[i]);
  return diff==0;
}

/* =========================================================
 *               TinyJAMBU-128 (decrypt+verify)
 * ========================================================= */
static void tinyjambu_permutation(uint32_t s[4], const uint32_t key[4], int rounds){
  for(int i=0;i<rounds;i++){
    uint32_t t = ( (s[1]>>15) | (s[2]<<17) )
               ^ ( (s[2]>>6)  | (s[3]<<26) )
               ^ ( (s[2]>>21) | (s[3]<<11) )
               ^ ( (s[2]>>27) | (s[3]<<5)  )
               ^ ( (s[2]>>29) | (s[3]<<3)  )
               ^ key[i&3];
    uint32_t ns0 = s[1], ns1 = s[2], ns2 = s[3], ns3 = s[0]^t;
    s[0]=ns0; s[1]=ns1; s[2]=ns2; s[3]=ns3;
  }
}
static bool tinyjambu128_decrypt_verify(
    const uint8_t K[16], const uint8_t N[16], const uint8_t *AAD, size_t aad_len,
    const uint8_t *CT, size_t ct_len, const uint8_t TAG[16], uint8_t *PT /* may be null */)
{
  uint32_t s[4]={0}, key[4]; for(int i=0;i<4;i++) key[i]=load32_be(K+4*i);
  // Init
  s[0]=load32_be(N+0); s[1]=load32_be(N+4); s[2]=load32_be(N+8); s[3]=load32_be(N+12);
  tinyjambu_permutation(s,key,1024);

  // AAD
  const uint8_t *p=AAD; size_t l=aad_len;
  while(l>=4){ s[0]^=load32_be(p); tinyjambu_permutation(s,key,384); p+=4; l-=4; }
  if(l){ uint8_t buf[4]={0}; for(size_t i=0;i<l;i++) buf[i]=p[i]; buf[l]^=0x80; s[0]^=load32_be(buf); tinyjambu_permutation(s,key,384); }

  // MSG
  if (PT) memset(PT,0,ct_len);
  p=CT; l=ct_len;
  while(l>=4){
    uint32_t ks=s[1];
    uint32_t c=load32_be(p);
    uint32_t m=c ^ ks;
    if (PT){ PT[0]=m>>24; PT[1]=m>>16; PT[2]=m>>8; PT[3]=m; PT+=4; }
    s[0]^=m; tinyjambu_permutation(s,key,1152);
    p+=4; l-=4;
  }
  if(l){
    uint8_t out[4]={0};
    for(size_t i=0;i<l;i++) out[i]=p[i];
    uint32_t c = ((uint32_t)out[0]<<24)|((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|((uint32_t)out[3]);
    uint32_t ks=s[1];
    uint32_t m = c ^ ks;
    if (PT){ if(l>0) PT[0]=m>>24; if(l>1) PT[1]=m>>16; if(l>2) PT[2]=m>>8; /* if(l>3) PT[3]=m; */ PT+=l; }
    s[0]^=m; tinyjambu_permutation(s,key,1152);
  }

  // Final tag
  uint8_t tag2[16];
  tinyjambu_permutation(s,key,640);
  for(int i=0;i<4;i++){ uint32_t v = s[i]^key[i]; tag2[4*i+0]=v>>24; tag2[4*i+1]=v>>16; tag2[4*i+2]=v>>8; tag2[4*i+3]=v; }
  uint8_t diff=0; for(int i=0;i<16;i++) diff|=(uint8_t)(tag2[i]^TAG[i]);
  return diff==0;
}

/* =========================================================
 *          JAMBU-PRESENT-128 (AEAD) — sender variant
 * ========================================================= */
static bool jambu_present128_decrypt_verify_UNSUPPORTED(
  const uint8_t K[16], const uint8_t N[16],
  const uint8_t *AAD, size_t aad_len,
  const uint8_t *CT,  size_t ct_len,
  const uint8_t TAG16[16], uint8_t* /*PT*/)
{
  (void)K; (void)N; (void)AAD; (void)aad_len; (void)CT; (void)ct_len; (void)TAG16;
  return false;
}

/* ====================== SADE Keys ======================== */
static void fill_sade_key(uint8_t key[16], uint8_t base){
  for(int i=0;i<16;i++) key[i] = (uint8_t)(base + i);
}

/* ====================== PKT parsing ====================== */
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

/* ======================== Arduino ======================== */
void setup(){
  Serial.begin(115200);
  while(!Serial){;}
  Serial.println(F("[ardu] ready. paste PKT line (ver=1):"));
}

void loop(){
  static String line;
  if (Serial.available()){
    char c = (char)Serial.read();
    if (c=='\r') return;
    if (c!='\n'){ line += c; return; }

    line.trim();
    if (line.length()==0){ line=""; return; }
    if (!line.startsWith("PKT;ver=1")){
      Serial.println(F("[err ] not a PKT;ver=1 line"));
      line=""; return;
    }

    String sNonce, sAAD, sCT, sTAG;
    if (!getField(line,"nonce_hex=",sNonce) ||
        !getField(line,"aad_hex=",  sAAD)   ||
        !getField(line,"ct_hex=",   sCT)    ||
        !getField(line,"tag_hex=",  sTAG)){
      Serial.println(F("[err ] missing fields"));
      line=""; return;
    }

    // Buffers
    uint8_t nonce[16], aad[128], ct[2048], tag[16], pt[2048];
    size_t nNonce = hexToBytes(sNonce.c_str(), nonce, sizeof(nonce));
    size_t nAAD   = hexToBytes(sAAD.c_str(),   aad,   sizeof(aad));
    size_t nCT    = hexToBytes(sCT.c_str(),    ct,    sizeof(ct));
    size_t nTAG   = hexToBytes(sTAG.c_str(),   tag,   sizeof(tag));
    if (nNonce!=16 || nTAG!=16){
      Serial.println(F("[err ] bad nonce/tag length"));
      line=""; return;
    }

    Serial.println(F("----- decode attempts (SADE modes) -----"));

    bool any_ok=false, multi_ok=false;
    int ok_count=0;

    // 1) ASCON-128a (SADE key A0..AF)
    {
      uint8_t K[16]; fill_sade_key(K, 0xA0);
      uint32_t t0=micros();
      bool ok = ascon128a_decrypt_verify(K, nonce, aad, nAAD, ct, nCT, tag, pt);
      uint32_t us=micros()-t0, cyc=approx_cycles_from_us(us);
      Serial.print(F("[ascon] tag=")); Serial.print(ok?F("OK"):F("FAIL"));
      Serial.print(F("  us=")); Serial.print(us);
      Serial.print(F("  cyc~")); Serial.println(cyc);
      if(ok){
        any_ok=true; ok_count++; if (ok_count>1) multi_ok=true;
        Serial.print(F("[pt   ] ascii: "));
        for(size_t i=0;i<nCT;i++){ char ch=(char)pt[i]; Serial.print((ch>=32&&ch<=126)?ch:'.'); }
        Serial.print("\r\n");
        printHex("[pt   ] hex: ", pt, nCT);
      }
    }

    // 2) ACORN-128 (SADE key B0..BF)
    {
      uint8_t K[16]; fill_sade_key(K, 0xB0);
      uint32_t t0=micros();
      bool ok = acorn128_decrypt_verify(K, nonce, aad, nAAD, ct, nCT, tag, pt);
      uint32_t us=micros()-t0, cyc=approx_cycles_from_us(us);
      Serial.print(F("[acorn] tag=")); Serial.print(ok?F("OK"):F("FAIL"));
      Serial.print(F("  us=")); Serial.print(us);
      Serial.print(F("  cyc~")); Serial.println(cyc);
      if(ok){
        any_ok=true; ok_count++; if (ok_count>1) multi_ok=true;
        Serial.print(F("[pt   ] ascii: "));
        for(size_t i=0;i<nCT;i++){ char ch=(char)pt[i]; Serial.print((ch>=32&&ch<=126)?ch:'.'); }
        Serial.print("\r\n");
        printHex("[pt   ] hex: ", pt, nCT);
      }
    }

    // 3) TinyJAMBU-128 (SADE key C0..CF)
    {
      uint8_t K[16]; fill_sade_key(K, 0xC0);
      uint32_t t0=micros();
      bool ok = tinyjambu128_decrypt_verify(K, nonce, aad, nAAD, ct, nCT, tag, pt);
      uint32_t us=micros()-t0, cyc=approx_cycles_from_us(us);
      Serial.print(F("[tjmb ] tag=")); Serial.print(ok?F("OK"):F("FAIL"));
      Serial.print(F("  us=")); Serial.print(us);
      Serial.print(F("  cyc~")); Serial.println(cyc);
      if(ok){
        any_ok=true; ok_count++; if (ok_count>1) multi_ok=true;
        Serial.print(F("[pt   ] ascii: "));
        for(size_t i=0;i<nCT;i++){ char ch=(char)pt[i]; Serial.print((ch>=32&&ch<=126)?ch:'.'); }
        Serial.print("\r\n");
        printHex("[pt   ] hex: ", pt, nCT);
      }
    }

    // 4) JAMBU-PRESENT-128 (sender variant not directly invertible)
    {
      uint8_t K[16]; fill_sade_key(K, 0xE0);
      uint32_t t0=micros();
      bool ok = jambu_present128_decrypt_verify_UNSUPPORTED(K, nonce, aad, nAAD, ct, nCT, tag, NULL);
      uint32_t us=micros()-t0, cyc=approx_cycles_from_us(us);
      Serial.print(F("[jmpr ] tag=")); Serial.print(ok?F("OK"):F("FAIL"));
      Serial.print(F("  us=")); Serial.print(us);
      Serial.print(F("  cyc~")); Serial.println(cyc);
      if(!ok){
        Serial.println(F("[jmpr ] NOTE: Sender's JAMBU-PRESENT variant mixes Mi inside E_K input;"));
        Serial.println(F("         decryption not directly feasible. To support decode, change MSG step to"));
        Serial.println(F("         keystream independent of Mi (e.g., Y=E_K(S^DOM_MSG); Ci=Mi^Y; S^=Ci)."));
      }
    }

    if (!any_ok){
      Serial.println(F("[res ] no algorithm verified the tag."));
    } else if (multi_ok){
      Serial.println(F("[res ] WARNING: multiple algorithms verified; check mode selection/AAD signals."));
    }
    Serial.println(F("----"));
    line="";
  }
}
