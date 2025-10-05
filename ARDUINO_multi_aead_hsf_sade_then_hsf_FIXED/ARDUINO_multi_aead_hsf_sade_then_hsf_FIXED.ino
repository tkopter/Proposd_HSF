// multi_aead_decode_sade.ino  (fixed + JM-PRESENT-128 decrypt eklendi)
// SADE modlarında PKT satırını çöz: ASCON-128a, ACORN-128, TinyJAMBU-128, JAMBU-PRESENT-128
// 115200 baud; PKT;ver=1;nonce_hex=...;aad_hex=...;ct_hex=...;tag_hex=...

#include <Arduino.h>
#include <stdint.h>
#include <string.h>

uint8_t nonce[16], aad[128], ct[2048], tag[16], pt[2048]; // BU KISIM DİREKT İNCLUDE ALTINA TAŞINIRSA RAMİ RAHATLATIP DAHA DA HIZLI SONUÇ VERİYOR YAPISAL OLARAK.
// ---- ACORN tip tanımı: Sget/Sxor'dan ÖNCE olmalı ----
#ifndef ACORN_STATE_T_DEFINED
#define ACORN_STATE_T_DEFINED 1

#include <stdint.h>
#define ACORN_STATE_BITS 293

// ACORN kaydırgaç durumu 293 bit; 5*64 = 320 bitlik alanda tutuluyor
typedef struct acorn_state_t {
  uint64_t w[5];
} acorn_state_t;

#endif // ACORN_STATE_T_DEFINED



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



/* =========================================================
 *                 ACORN-128 (decrypt+verify)
 * ========================================================= */
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
 *          JAMBU-PRESENT-128 (AEAD) — decrypt+verify
 *          (Vitis keystream: Y = E_K(S ^ DOM_MSG), Mi bağımsız)
 * ========================================================= */
static const uint8_t P8_S[16]={0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2};
static uint64_t p8_sbox_layer(uint64_t s){
  uint64_t o=0; for(int i=0;i<16;i++){ uint8_t nib=(s>>(i*4))&0xF; o |= (uint64_t)P8_S[nib]<<(i*4); } return o;
}
static uint64_t p8_pLayer(uint64_t s){
  uint64_t o=0; for(int i=0;i<64;i++){ int pos = (i==63)?63 : ((16*i)%63); o |= ((s>>i)&1ULL) << pos; } return o;
}
static uint64_t present128_rk[32];
static void present128_key_schedule(const uint8_t K[16]){
  // Basit 128-bit PRESENT anahtar çizelgesi (khi|klo), LROT 61, Sbox MS nibble, rc XOR
  uint64_t khi = load64_be(K), klo = load64_be(K+8);
  for (int r = 1; r <= 32; r++) {
    present128_rk[r - 1] = khi;
    uint64_t new_hi = (khi << 61) | (klo >> 3);
    uint64_t new_lo = (klo << 61) | (khi >> 3);
    khi = new_hi; klo = new_lo;
    uint8_t ms   = (uint8_t)((khi >> 60) & 0xF);
    uint8_t repl = P8_S[ms];
    khi = (khi & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)repl << 60);
    klo ^= (uint64_t)r; // (Vitis çekirdeğiyle farklıysa burayı ayarla)
  }
}
static void present128_encrypt_block(uint8_t out[8], const uint8_t in[8]){
  uint64_t s=load64_be(in);
  for(int r=0;r<31;r++){ s ^= present128_rk[r]; s = p8_sbox_layer(s); s = p8_pLayer(s); }
  s ^= present128_rk[31];
  store64_be(out,s);
}

// JM domain sabitleri
static const uint64_t JAMBU_DOM_AAD = 0xA0A0A0A0A0A0A0A0ULL;
static const uint64_t JAMBU_DOM_MSG = 0xB1B1B1B1B1B1B1B1ULL;
static const uint64_t JAMBU_DOM_FIN = 0xC2C2C2C2C2C2C2C2ULL;

static bool jambu_present128_decrypt_verify(
  const uint8_t K[16], const uint8_t N[16],
  const uint8_t* AAD, size_t aad_len,
  const uint8_t* CT,  size_t ct_len,
  const uint8_t* TAG, size_t tag_len,
  uint8_t* PT /* may be null */)
{
  present128_key_schedule(K);

  // Init: S = E_K(N0 ^ N1), R = 0
  uint64_t n0 = load64_be(N), n1 = load64_be(N+8);
  uint8_t  b8[8];
  uint64_t S_in = n0 ^ n1;
  store64_be(b8, S_in); present128_encrypt_block(b8, b8);
  uint64_t S = load64_be(b8);
  uint64_t R = 0;

  // AAD blokları (8B), son blok 0x80 ile pad
  if (aad_len){
    for(size_t i=0;; i+=8){
      bool last = ((i+8) >= aad_len);
      uint8_t blk[8]={0};
      size_t r = aad_len - i; if (r>8) r=8; if (r>0) memcpy(blk, AAD+i, r);
      if (last && (r<8)) blk[r]=0x80;

      uint64_t Ai = load64_be(blk);
      uint64_t X  = S ^ Ai ^ JAMBU_DOM_AAD;
      store64_be(b8, X); present128_encrypt_block(b8, b8);
      S = load64_be(b8);
      R ^= S;
      if (last) break;
    }
  }

  // MSG (keystream Y = E_K(S ^ DOM_MSG))
  if (PT) memset(PT,0,ct_len);
  for(size_t i=0; i<ct_len; ){
    bool last = ((i+8) >= ct_len);
    uint64_t X = S ^ JAMBU_DOM_MSG;
    store64_be(b8, X); present128_encrypt_block(b8, b8);
    uint8_t ks[8]; memcpy(ks,b8,8);

    if (!last){
      uint64_t Ci = load64_be(CT+i);
      uint64_t Mi = Ci ^ load64_be(ks);
      if (PT) store64_be(PT+i, Mi);
      S ^= Ci; R ^= Ci;
      i += 8;
    } else {
      size_t r = ct_len - i; // 1..7 veya 0
      if (r){
        uint8_t ptb[8]={0};
        for(size_t j=0;j<r;j++) ptb[j] = (uint8_t)(CT[i+j] ^ ks[j]);
        if (PT) memcpy(PT+i, ptb, r);

        // Mi_pad = PT || 0x80 || 00..
        uint8_t mipad[8]={0}; memcpy(mipad, ptb, r); mipad[r]=0x80;
        uint8_t cifull[8]; for(size_t j=0;j<8;j++) cifull[j]=(uint8_t)(mipad[j]^ks[j]);
        uint64_t Ci_full = load64_be(cifull);
        S ^= Ci_full; R ^= Ci_full;
      } else {
        // r==0: tam blok hizası; encrypt tarafı full Y karmışsa:
        uint64_t Ci_full = load64_be(ks);
        S ^= Ci_full; R ^= Ci_full;
      }
      break;
    }
  }

  // Final + Tag(8B)
  uint64_t F = S ^ R ^ JAMBU_DOM_FIN;
  store64_be(b8, F); present128_encrypt_block(b8, b8);
  uint8_t calc8[8]; memcpy(calc8,b8,8);

  if (tag_len < 8) return false; // senin üstteki kontrol zaten 16 bekliyor
  uint8_t diff=0; for(int k=0;k<8;k++) diff |= (uint8_t)(calc8[k] ^ TAG[k]); // 16 geldiyse ilk 8 karşılaştırılır
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

    // <<<<<< BU İKİ SATIRI BURAYA EKLEYİN >>>>>>
    uint32_t us_parse = 0; // Değişkeni burada tanımla
    uint32_t t_parse0 = micros();
    // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    String sNonce, sAAD, sCT, sTAG;
    if (!getField(line,"nonce_hex=",sNonce) ||
        !getField(line,"aad_hex=",  sAAD)   ||
        !getField(line,"ct_hex=",   sCT)    ||
        !getField(line,"tag_hex=",  sTAG)){
      Serial.println(F("[err ] missing fields"));
      line=""; return;
    }

    // Buffers
    // uint8_t nonce[16], aad[128], ct[2048], tag[16], pt[2048]; // BU KISIM DİREKT İNCLUDE ALTINA TAŞINIRSA RAMİ RAHATLATIP DAHA DA HIZLI SONUÇ VERİYOR YAPISAL OLARAK.
    size_t nNonce = hexToBytes(sNonce.c_str(), nonce, sizeof(nonce));
    size_t nAAD   = hexToBytes(sAAD.c_str(),   aad,   sizeof(aad));
    size_t nCT    = hexToBytes(sCT.c_str(),    ct,    sizeof(ct));
    size_t nTAG   = hexToBytes(sTAG.c_str(),   tag,   sizeof(tag));

    // <<<<<< BU SATIRI BURAYA EKLEYİN >>>>>>
    us_parse = micros() - t_parse0;
    // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    
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
      Serial.print(F("[ascon] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F("  us=")); Serial.print(us); Serial.print(F(" (total_us~")); Serial.print(us + us_parse); Serial.print(F(")")); Serial.print(F("  cyc~")); Serial.println(cyc);
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
      Serial.print(F("[acorn] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F("  us=")); Serial.print(us); Serial.print(F(" (total_us~")); Serial.print(us + us_parse); Serial.print(F(")")); Serial.print(F("  cyc~")); Serial.println(cyc);
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
      Serial.print(F("[tjmb ] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F("  us=")); Serial.print(us); Serial.print(F(" (total_us~")); Serial.print(us + us_parse); Serial.print(F(")")); Serial.print(F("  cyc~")); Serial.println(cyc);
      if(ok){
        any_ok=true; ok_count++; if (ok_count>1) multi_ok=true;
        Serial.print(F("[pt   ] ascii: "));
        for(size_t i=0;i<nCT;i++){ char ch=(char)pt[i]; Serial.print((ch>=32&&ch<=126)?ch:'.'); }
        Serial.print("\r\n");
        printHex("[pt   ] hex: ", pt, nCT);
      }
    }

    // 4) JAMBU-PRESENT-128 (SADE key E0..EF) — tag 16 ise ilk 8 bayt kıyaslanır
    {
      uint8_t K[16]; fill_sade_key(K, 0xE0);
      uint32_t t0=micros();
      bool ok = jambu_present128_decrypt_verify(K, nonce, aad, nAAD, ct, nCT, tag, nTAG, pt);
      uint32_t us=micros()-t0, cyc=approx_cycles_from_us(us);
      Serial.print(F("[jmpr ] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F("  us=")); Serial.print(us); Serial.print(F(" (total_us~")); Serial.print(us + us_parse); Serial.print(F(")")); Serial.print(F("  cyc~")); Serial.println(cyc);
      if(ok){
        any_ok=true; ok_count++; if (ok_count>1) multi_ok=true;
        Serial.print(F("[pt   ] ascii: "));
        for(size_t i=0;i<nCT;i++){ char ch=(char)pt[i]; Serial.print((ch>=32&&ch<=126)?ch:'.'); }
        Serial.print("\r\n");
        printHex("[pt   ] hex: ", pt, nCT);
      }
    }

    // =======================================================================
    //    BÖLÜM 2: HSF MODU TESTLERİ
    // =======================================================================
    Serial.println(F("----- HSF Mode Benchmarks -----"));
    // HSF testleri sadece AAD uzunluğu uygunsa çalıştırılır.
    if (nAAD == 15 || nAAD == 23) {
      //uint32_t us_parse;
      uint32_t us_kdf;
      uint8_t K_i[16];
    
      // Parse ve KDF işlemleri tüm HSF testleri için bir kez yapılır.
      {
        //uint32_t t_parse0 = micros();
        uint32_t dev = load32_be(aad+1);
        uint8_t  idx = aad[5] & 0x03;
        //us_parse = micros() - t_parse0;
    
        uint32_t t_kdf0 = micros();
        kdf_from_xof(S_ROOT, dev, POOL[idx], K_i);
        us_kdf = micros() - t_kdf0;
      }
    
      // Her algoritma için AEAD süresi ayrı ayrı ölçülür.
      {
        uint32_t t_aead0 = micros(); 
        bool ok = ascon128a_decrypt_verify(K_i, nonce, aad, nAAD, ct, nCT, tag, pt); 
        uint32_t us_aead = micros() - t_aead0;
        Serial.print(F("[hsf-ascon ] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F(" | parse_us=")); Serial.print(us_parse); Serial.print(F(" kdf_us=")); Serial.print(us_kdf); Serial.print(F(" aead_us=")); Serial.println(us_aead); if(ok) printHex("[pt] ", pt, nCT);
      }
      {
        uint32_t t_aead0 = micros(); 
        bool ok = acorn128_decrypt_verify(K_i, nonce, aad, nAAD, ct, nCT, tag, pt); 
        uint32_t us_aead = micros() - t_aead0;
        Serial.print(F("[hsf-acorn ] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F(" | parse_us=")); Serial.print(us_parse); Serial.print(F(" kdf_us=")); Serial.print(us_kdf); Serial.print(F(" aead_us=")); Serial.println(us_aead); if(ok) printHex("[pt] ", pt, nCT);
      }
      {
        uint32_t t_aead0 = micros(); 
        bool ok = tinyjambu128_decrypt_verify(K_i, nonce, aad, nAAD, ct, nCT, tag, pt); 
        uint32_t us_aead = micros() - t_aead0;
        Serial.print(F("[hsf-tjmb  ] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F(" | parse_us=")); Serial.print(us_parse); Serial.print(F(" kdf_us=")); Serial.print(us_kdf); Serial.print(F(" aead_us=")); Serial.println(us_aead); if(ok) printHex("[pt] ", pt, nCT);
      }
      {
        uint32_t t_aead0 = micros(); 
        bool ok = jambu_present128_decrypt_verify(K_i, nonce, aad, nAAD, ct, nCT, tag, nTAG, pt); 
        uint32_t us_aead = micros() - t_aead0;
        Serial.print(F("[hsf-jmpr  ] tag=")); Serial.print(ok?F("OK"):F("FAIL")); Serial.print(F(" | parse_us=")); Serial.print(us_parse); Serial.print(F(" kdf_us=")); Serial.print(us_kdf); Serial.print(F(" aead_us=")); Serial.println(us_aead); if(ok) printHex("[pt] ", pt, nCT);
      }
      printHex("[kdf-key] ", K_i, 16);
    } else {
      Serial.println(F("[hsf-info  ] AAD length is not 15 or 23. Skipping HSF tests."));
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
