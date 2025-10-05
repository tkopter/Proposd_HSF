/* =========================================================================
 *  gizli.c — Menü’lü tek dosya (benchmark entry):
 *      1 HSF'li ASCON        2 Sade ASCON
 *      3 HSF'li ACORN        4 Sade ACORN
 *      5 HSF'li TinyJAMBU    6 Sade TinyJAMBU
 *      7 HSF'li PRESENT      8 Sade PRESENT (ECB, 2x64 -> 16B)
 *      9 HSF'li JAMBU        0 Sade JAMBU   [placeholder]
 *
 *  - Kütüphane yok. Vitis/Zynq bare-metal. PMU/GT ile cycle & µs ölçümü.
 *  - Ana program değişmez; bu dosya doğrudan gizli_fonksiyon() çağrılır.
 *  - HSF = tüm algoritmalarda **ASCON-XOF128** ile KDF (KEY türetimi) + aynı rapor.
 * ========================================================================= */

#include <stdint.h>
#include <stddef.h>
#include "xparameters.h"
#include "xuartps_hw.h"

/* ---------- Donanım saatleri ---------- */
#define CPU_HZ           XPAR_CPU_CORTEXA9_0_CPU_CLK_FREQ_HZ
#define GT_FREQ_HZ      ((uint64_t)CPU_HZ / 2ULL)         /* Zynq Global Timer = CPU/2 */
#define USE_PMU  1
#define USE_GT_HW 1

/* --- Mailbox imzası (TAG[0..3]’ten) --- */
static uint32_t g_mail_sig = 0;
static inline uint32_t tag32(const uint8_t *T){
    return (uint32_t)T[0] | ((uint32_t)T[1]<<8) | ((uint32_t)T[2]<<16) | ((uint32_t)T[3]<<24);
}

/* ---- Kalıcı seçim ve ortalama sayaçları (X ile sıfırlanır) ---- */
static volatile char g_choice = 0;      /* 0 => menü, '1'..'9','0' => seçim */
static uint64_t g_acc_ticks = 0;
static uint64_t g_count     = 0;

static inline void reset_averages(void){
    g_acc_ticks = 0;
    g_count     = 0;
}

/* ---------- UART yardımcıları ---------- */
static inline void uart_init(void){
    uint32_t base = XPAR_XUARTPS_0_BASEADDR;
    uint32_t cr   = XUartPs_ReadReg(base, XUARTPS_CR_OFFSET);
    XUartPs_WriteReg(base, XUARTPS_CR_OFFSET,
        (cr & ~XUARTPS_CR_EN_DIS_MASK) | XUARTPS_CR_TX_EN | XUARTPS_CR_RX_EN);
}
static inline void uart_putc(char c){
    uint32_t base = XPAR_XUARTPS_0_BASEADDR;
    while (XUartPs_IsTransmitFull(base)) {}
    XUartPs_WriteReg(base, XUARTPS_FIFO_OFFSET, (uint32_t)c);
}
static inline void uart_puts(const char* s){ uart_init(); while(*s) uart_putc(*s++); }

/* Bloklamayan tek karakter okuma (veri yoksa 0) */
static inline char uart_getc_nowait(void){
    uint32_t base = XPAR_XUARTPS_0_BASEADDR;
    if (!XUartPs_IsReceiveData(base)) return 0;
    return (char)XUartPs_ReadReg(base, XUARTPS_FIFO_OFFSET);
}
/* CR/LF’yi atlayarak tek karakterli seçim okur (bloklar) */
static inline char read_choice_blocking(void){
    while (1){
        uint32_t base = XPAR_XUARTPS_0_BASEADDR;
        while (!XUartPs_IsReceiveData(base)) {}
        char c = (char)XUartPs_ReadReg(base, XUARTPS_FIFO_OFFSET);
        if (c=='\r' || c=='\n') continue;
        return c;
    }
}

/* ---------- Global Timer ---------- */
#if USE_GT_HW
static inline void gt_enable_if_needed(void){
    volatile uint32_t *GT = (uint32_t*)0xF8F00200u; /* [0]:LO, [1]:HI, [2]:CTRL */
    uint32_t ctrl = GT[2];
    if ((ctrl & 1u) == 0u){
        GT[2] = ctrl | 1u;
        uint32_t low = GT[0]; GT[0] = low; (void)GT[0];
        asm volatile("DSB; ISB");
    }
}
static inline uint64_t gt_read(void){
    volatile uint32_t *GT=(uint32_t*)0xF8F00200u;
    uint32_t h1,l,h2; do{ h1=GT[1]; l=GT[0]; h2=GT[1]; }while(h1!=h2);
    return ((uint64_t)h1<<32)|l;
}
#else
static inline void gt_enable_if_needed(void){}
static inline uint64_t gt_read(void){ static uint64_t soft=0; soft+=50000; return soft; }
#endif

/* ---------- PMU (Cycle counter) ---------- */
#if USE_PMU
static inline void pmu_enable_cyccnt(void){
    uint32_t v;
    asm volatile("MRC p15,0,%0,c9,c12,0":"=r"(v));
    v |= (1u<<0)|(1u<<1)|(1u<<2); v &= ~(1u<<3);
    asm volatile("MCR p15,0,%0,c9,c12,0"::"r"(v));
    v = (1u<<31);
    asm volatile("MCR p15,0,%0,c9,c12,1"::"r"(v));
    asm volatile("ISB");
}
static inline void pmu_reset_cyccnt(void){
    uint32_t v; asm volatile("MRC p15,0,%0,c9,c12,0":"=r"(v));
    v |= (1u<<2); asm volatile("MCR p15,0,%0,c9,c12,0"::"r"(v)); asm volatile("ISB");
}
static inline uint32_t pmu_get_cyccnt(void){
    uint32_t cc; asm volatile("MRC p15,0,%0,c9,c13,0":"=r"(cc)); return cc;
}
#else
static inline void pmu_enable_cyccnt(void){}
static inline void pmu_reset_cyccnt(void){}
static inline uint32_t pmu_get_cyccnt(void){ return 0; }
#endif

/* ---------- ufak yardımcılar ---------- */
static inline void s_push(char **w, char c){ *(*w)++ = c; }
static inline void s_puts(char **w, const char *s){ while(*s) *(*w)++ = *s++; }

static inline uint64_t u64_div_u32(uint64_t num, uint32_t den){
    uint64_t q=0,r=0; for(int i=63;i>=0;--i){ r=(r<<1)|((num>>i)&1ULL); if(r>=den){ r-=den; q|=(1ULL<<i);} } return q;
}
static inline void u32_to_dec(uint32_t v, char **w){ char t[10]; int n=0; do{ t[n++]=(char)('0'+(v%10)); v/=10; }while(v); while(n--) s_push(w,t[n]); }
static inline void u64_to_dec(uint64_t v, char **w){
    char t[20]; int n=0; do{ uint64_t q=u64_div_u32(v,10u); uint64_t q10=(q<<3)+(q<<1); uint32_t r=(uint32_t)(v-q10); t[n++]=(char)('0'+r); v=q; }while(v); while(n--) s_push(w,t[n]);
}
static inline void print_u32_line(const char* label, uint32_t v){ char b[32]; char* w=b; u32_to_dec(v,&w); *w=0; uart_puts(label); uart_puts(b); uart_puts("\r\n"); }
static inline void print_u64_line(const char* label, uint64_t v){ char b[40]; char* w=b; u64_to_dec(v,&w); *w=0; uart_puts(label); uart_puts(b); uart_puts("\r\n"); }

static inline void put_hex8(uint8_t b){ static const char H[]="0123456789ABCDEF"; char s[3]; s[0]=H[b>>4]; s[1]=H[b&0xF]; s[2]=0; uart_puts(s); }
static inline void dump_hex(const uint8_t* p, size_t n){ for(size_t i=0;i<n;i++){ put_hex8(p[i]); uart_puts(((i&0xF)==0xF)?"\r\n":" "); } if((n&0xF)!=0) uart_puts("\r\n"); }
static inline void bytes_to_hex(const uint8_t* p, size_t n, char **w){ static const char H[]="0123456789ABCDEF"; for(size_t i=0;i<n;i++){ s_push(w,H[p[i]>>4]); s_push(w,H[p[i]&0xF]); } }

static inline void* b_memset(void* d, int v, size_t n){ uint8_t* D=(uint8_t*)d; for(size_t i=0;i<n;i++) D[i]=(uint8_t)v; return d; }
static inline void  b_memcpy(void* d, const void* s, size_t n){ uint8_t* D=(uint8_t*)d; const uint8_t* S=(const uint8_t*)s; for(size_t i=0;i<n;i++) D[i]=S[i]; }

static inline void store32_be(uint8_t* p, uint32_t x){ p[0]=x>>24; p[1]=x>>16; p[2]=x>>8; p[3]=x; }
static inline void store64_be(uint8_t* p, uint64_t x){ p[0]=x>>56; p[1]=x>>48; p[2]=x>>40; p[3]=x>>32; p[4]=x>>24; p[5]=x>>16; p[6]=x>>8; p[7]=x; }
static inline uint32_t load32_be(const uint8_t* p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]); }
static inline uint64_t load64_be(const uint8_t* p){
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|
           ((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8)|((uint64_t)p[7]);
}

/* ===================================================================== */
/* =============================  ASCON  ================================ */
/* ===================================================================== */
static inline uint64_t ROR64(uint64_t x, unsigned n){ return (x>>n)|(x<<(64u-n)); }
static const uint8_t RC12[12]={0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,0x78,0x69,0x5A,0x4B};
static const uint8_t RC8[8]  ={0xB4,0xA5,0x96,0x87,0x78,0x69,0x5A,0x4B};
static inline void ascon_round(uint64_t *x0,uint64_t *x1,uint64_t *x2,uint64_t *x3,uint64_t *x4, uint8_t rc){
    *x2^=(uint64_t)rc; *x0^=*x4; *x4^=*x3; *x2^=*x1;
    uint64_t t0=*x0, t1=*x1, t2=*x2, t3=*x3, t4=*x4;
    t0=~t0; t1=~t1; t2=~t2; t3=~t3; t4=~t4;
    t0&=*x1; t1&=*x2; t2&=*x3; t3&=*x4; t4&=*x0;
    *x0^=t1; *x1^=t2; *x2^=t3; *x3^=t4; *x4^=t0;
    *x1^=*x0; *x0^=*x4; *x3^=*x2; *x2=~(*x2);
    *x0^=ROR64(*x0,19)^ROR64(*x0,28);
    *x1^=ROR64(*x1,61)^ROR64(*x1,39);
    *x2^=ROR64(*x2, 1)^ROR64(*x2, 6);
    *x3^=ROR64(*x3,10)^ROR64(*x3,17);
    *x4^=ROR64(*x4, 7)^ROR64(*x4,41);
}
static inline void P12(uint64_t *x0,uint64_t *x1,uint64_t *x2,uint64_t *x3,uint64_t *x4){ for(int i=0;i<12;i++) ascon_round(x0,x1,x2,x3,x4,RC12[i]); }
static inline void P8 (uint64_t *x0,uint64_t *x1,uint64_t *x2,uint64_t *x3,uint64_t *x4){ for(int i=0;i<8 ;i++) ascon_round(x0,x1,x2,x3,x4,RC8[i]);  }

static inline void absorb_xor_16(uint64_t *x0,uint64_t *x1,const uint8_t*in,size_t len){
    size_t i=0; for(; i<len && i<8; i++) *x0^=(uint64_t)in[i]<<(56-8*i);
    for(; i<len; i++)                    *x1^=(uint64_t)in[i]<<(56-8*(i-8));
}
static inline void squeeze_16(uint8_t*out,size_t len,uint64_t x0,uint64_t x1){
    uint8_t t[16]; store64_be(t,x0); store64_be(t+8,x1);
    for(size_t i=0;i<len;i++) out[i]=t[i];
}

#define ASCON_AEAD128_IV 0x80800c0800000000ULL
#define ASCON_XOF128_IV  0x00800c0000000000ULL

/* ASCON-128 AEAD — alt-kırılım sayaçlı sürüm */
static void ascon_aead128_encrypt(
    const uint8_t key[16], const uint8_t nonce[16],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt,  size_t pt_len,
    uint8_t* ct, uint8_t tag[16],
    /* alt-kırılım sayaçları: */
    uint32_t *cyc_init, uint32_t *cyc_aad, uint32_t *cyc_msg, uint32_t *cyc_fin)
{
    /* state ve sabitler */
    uint64_t x0=ASCON_AEAD128_IV;
    uint64_t k0=load64_be(key),    k1=load64_be(key+8);
    uint64_t n0=load64_be(nonce),  n1=load64_be(nonce+8);
    uint64_t x1=k0, x2=k1, x3=n0,  x4=n1;

    /* ---------- INIT ---------- */
#if USE_PMU
    uint32_t c0 = pmu_get_cyccnt();
#endif
    P12(&x0,&x1,&x2,&x3,&x4);
    x3 ^= k0; x4 ^= k1;
#if USE_PMU
    if (cyc_init) *cyc_init = pmu_get_cyccnt() - c0;
#else
    if (cyc_init) *cyc_init = 0;
#endif

    /* ---------- AAD ---------- */
#if USE_PMU
    uint32_t c2 = pmu_get_cyccnt();
#endif
    if (aad_len){
        while (aad_len >= 16){
            x0 ^= load64_be(aad);
            x1 ^= load64_be(aad+8);
            P8(&x0,&x1,&x2,&x3,&x4);
            aad += 16; aad_len -= 16;
        }
        if (aad_len){
            absorb_xor_16(&x0,&x1,aad,aad_len);
            if (aad_len < 8)  x0 ^= (uint64_t)0x80 << (56 - 8*aad_len);
            else              x1 ^= (uint64_t)0x80 << (56 - 8*(aad_len-8));
            P8(&x0,&x1,&x2,&x3,&x4);
        }
    }
    /* domain sep (AAD -> MSG) */
    x4 ^= 1ULL;
#if USE_PMU
    if (cyc_aad) *cyc_aad = pmu_get_cyccnt() - c2;
#else
    if (cyc_aad) *cyc_aad = 0;
#endif

    /* ---------- MSG (PT -> CT) ---------- */
#if USE_PMU
    uint32_t c4 = pmu_get_cyccnt();
#endif
    while (pt_len >= 16){
        x0 ^= load64_be(pt);
        x1 ^= load64_be(pt+8);
        store64_be(ct,   x0);
        store64_be(ct+8, x1);
        P8(&x0,&x1,&x2,&x3,&x4);
        pt += 16; ct += 16; pt_len -= 16;
    }
    if (pt_len){
        absorb_xor_16(&x0,&x1,pt,pt_len);
        uint8_t t[16]; squeeze_16(t,16,x0,x1);
        for (size_t i=0;i<pt_len;i++) ct[i] = t[i];
        if (pt_len < 8)  x0 ^= (uint64_t)0x80 << (56 - 8*pt_len);
        else             x1 ^= (uint64_t)0x80 << (56 - 8*(pt_len-8));
    }
#if USE_PMU
    if (cyc_msg) *cyc_msg = pmu_get_cyccnt() - c4;
#else
    if (cyc_msg) *cyc_msg = 0;
#endif

    /* ---------- FIN (tag) ---------- */
#if USE_PMU
    uint32_t c6 = pmu_get_cyccnt();
#endif
    x1 ^= k0; x2 ^= k1;
    P12(&x0,&x1,&x2,&x3,&x4);
    x3 ^= k0; x4 ^= k1;
    store64_be(tag,   x3);
    store64_be(tag+8, x4);
#if USE_PMU
    if (cyc_fin) *cyc_fin = pmu_get_cyccnt() - c6;
#else
    if (cyc_fin) *cyc_fin = 0;
#endif
}


/* XOF128 (KDF için) */
static void ascon_xof128(const uint8_t*in,size_t inlen,uint8_t*out,size_t outlen){
    uint64_t x0=ASCON_XOF128_IV,x1=0,x2=0,x3=0,x4=0;
    while(inlen>=16){ x0^=load64_be(in); x1^=load64_be(in+8); P12(&x0,&x1,&x2,&x3,&x4); in+=16; inlen-=16; }
    if(inlen){ absorb_xor_16(&x0,&x1,in,inlen); if(inlen<8) x0^=(uint64_t)0x80<<(56-8*inlen); else x1^=(uint64_t)0x80<<(56-8*(inlen-8)); }
    else { x0^=(uint64_t)0x80<<56; }
    P12(&x0,&x1,&x2,&x3,&x4);
    while(outlen){ size_t n=(outlen<16)?outlen:16; squeeze_16(out,n,x0,x1); out+=n; outlen-=n; if(outlen) P12(&x0,&x1,&x2,&x3,&x4); }
}

/* ===================================================================== */
/* =============================  ACORN  ================================ */
/* ===================================================================== */
#define ACORN_STATE_BITS 293
typedef struct { uint64_t w[5]; } acorn_state;
static inline uint32_t Sget(const acorn_state*S,int j){ return (uint32_t)((S->w[j>>6]>>(j&63))&1ULL); }
static inline void     Sxor(acorn_state*S,int j,uint32_t b){ if(b) S->w[j>>6]^=(1ULL<<(j&63)); }
static inline void Sclr_hi(acorn_state*S){ const int last=ACORN_STATE_BITS-1; const int lw=last>>6; const int keep=(last&63)+1;
    uint64_t mask=(keep==64)?~0ULL:((1ULL<<keep)-1ULL); for(int i=lw+1;i<5;i++) S->w[i]=0; S->w[lw]&=mask; }
static inline uint32_t MAJ(uint32_t x,uint32_t y,uint32_t z){ return (x&y)^(x&z)^(y&z); }
static inline uint32_t CH (uint32_t x,uint32_t y,uint32_t z){ return (x&y)^((~x)&z); }
static inline uint32_t KSG128(const acorn_state*S){ return (uint32_t)( Sget(S,12)^Sget(S,154)^MAJ(Sget(S,235),Sget(S,61),Sget(S,193)) ); }
static inline uint32_t FBK128(const acorn_state*S,uint32_t ca,uint32_t cb){
    uint32_t ks=KSG128(S);
    uint32_t f=(uint32_t)( Sget(S,0) ^ (~Sget(S,107)&1u) ^ MAJ(Sget(S,244),Sget(S,23),Sget(S,160)) ^
                            CH(Sget(S,230),Sget(S,111),Sget(S,66)) ^ (ca&Sget(S,196)) ^ (cb&ks) );
    return f&1u;
}
static void StateUpdate128(acorn_state*S,uint32_t m,uint32_t ca,uint32_t cb){
    Sxor(S,289, Sget(S,235)^Sget(S,230));
    Sxor(S,230, Sget(S,196)^Sget(S,193));
    Sxor(S,193, Sget(S,160)^Sget(S,154));
    Sxor(S,154, Sget(S,111)^Sget(S,107));
    Sxor(S,107, Sget(S,66) ^Sget(S,61));
    Sxor(S,61 , Sget(S,23) ^Sget(S,0));
    uint32_t f=FBK128(S,ca,cb)^(m&1u);
    acorn_state old=*S; for(int i=0;i<5;i++) S->w[i]=0;
    S->w[0]=(old.w[0]>>1)|(old.w[1]<<63);
    S->w[1]=(old.w[1]>>1)|(old.w[2]<<63);
    S->w[2]=(old.w[2]>>1)|(old.w[3]<<63);
    S->w[3]=(old.w[3]>>1)|(old.w[4]<<63);
    S->w[4]=(old.w[4]>>1);
    Sclr_hi(S); if(f) S->w[(ACORN_STATE_BITS-1)>>6] |= (1ULL<<((ACORN_STATE_BITS-1)&63));
}
static inline uint32_t get_bit(const uint8_t*b, uint64_t pos){ return (b[pos>>3]>>(pos&7))&1u; }
static inline void     set_bit(uint8_t*b, uint64_t pos, uint32_t v){ if(v) b[pos>>3]|=(uint8_t)(1u<<(pos&7)); else b[pos>>3]&=(uint8_t)~(1u<<(pos&7)); }

static void acorn128_aead_encrypt(const uint8_t K[16], const uint8_t N[16],
    const uint8_t *AAD, uint64_t aad_len, const uint8_t *PT, uint64_t pt_len,
    uint8_t *CT, uint8_t TAG[16], uint32_t *cyc_init,uint32_t *cyc_aad,uint32_t *cyc_msg,uint32_t *cyc_fin)
{
    uint64_t aad_bits=aad_len*8ULL, msg_bits=pt_len*8ULL;
    acorn_state S; S.w[0]=S.w[1]=S.w[2]=S.w[3]=S.w[4]=0;
#if USE_PMU
    uint32_t c0=pmu_get_cyccnt();
#endif
    for(int i=0;i<128;i++) StateUpdate128(&S, get_bit(K,i), 1,1);
    for(int i=0;i<128;i++) StateUpdate128(&S, get_bit(N,i), 1,1);
    for(int i=0;i<1536;i++){ uint32_t mi=get_bit(K,i&127); if(i==0) mi^=1u; StateUpdate128(&S,mi,1,1); }
#if USE_PMU
    uint32_t c1=pmu_get_cyccnt(); *cyc_init=c1-c0;
#else
    *cyc_init=0;
#endif
#if USE_PMU
    uint32_t c2=pmu_get_cyccnt();
#endif
    for(uint64_t i=0;i<aad_bits+256;i++){
        uint32_t mi = (i<aad_bits)? get_bit(AAD,i) : (i==aad_bits);
        StateUpdate128(&S, mi, (i<aad_bits+128)?1u:0u, 1u);
    }
#if USE_PMU
    uint32_t c3=pmu_get_cyccnt(); *cyc_aad=c3-c2;
#else
    *cyc_aad=0;
#endif
#if USE_PMU
    uint32_t c4=pmu_get_cyccnt();
#endif
    b_memset(CT,0,pt_len);
    for(uint64_t i=0;i<msg_bits+256;i++){
        uint32_t ca=(i<msg_bits+128)?1u:0u; uint32_t ks=KSG128(&S);
        if(i<msg_bits){ uint32_t pi=get_bit(PT,i); set_bit(CT,i,pi^ks); StateUpdate128(&S,pi,ca,0); }
        else           { StateUpdate128(&S, (i==msg_bits)?1u:0u, ca, 0); }
    }
#if USE_PMU
    uint32_t c5=pmu_get_cyccnt(); *cyc_msg=c5-c4;
#else
    *cyc_msg=0;
#endif
#if USE_PMU
    uint32_t c6=pmu_get_cyccnt();
#endif
    uint8_t tagbits[16]; b_memset(tagbits,0,16);
    for(int i=0;i<768;i++){ uint32_t ks=KSG128(&S); StateUpdate128(&S,0,1,1); if(i>=640){ set_bit(tagbits, i-640, ks); } }
    for(int i=0;i<16;i++) TAG[i]=tagbits[i];
#if USE_PMU
    uint32_t c7=pmu_get_cyccnt(); *cyc_fin=c7-c6;
#else
    *cyc_fin=0;
#endif
}

/* ===================================================================== */
/* ===========================  TinyJAMBU  ============================== */
/* ===================================================================== */
/* Basit 32-bit registerli permütasyon – referans varyantına sadık, yeterli benchmark için */
static void tinyjambu_permutation(uint32_t s[4], const uint32_t key[4], int rounds){
    for(int i=0;i<rounds;i++){
        uint32_t t = ( (s[1]>>15) | (s[2]<<17) )
                   ^ ( (s[2]>>6)  | (s[3]<<26) )
                   ^ ( (s[2]>>21) | (s[3]<<11) )
                   ^ ( (s[2]>>27) | (s[3]<<5)  )
                   ^ ( (s[2]>>29) | (s[3]<<3)  )
                   ^ key[i&3];
        /* opsiyonel: t ^= (s[2] & s[3]); */
        uint32_t ns0 = s[1], ns1 = s[2], ns2 = s[3], ns3 = s[0]^t;
        s[0]=ns0; s[1]=ns1; s[2]=ns2; s[3]=ns3;
    }
}
static void tinyjambu_aead_encrypt(
    const uint8_t K[16], const uint8_t N[16], const uint8_t *AAD, size_t aad_len,
    const uint8_t *PT, size_t pt_len, uint8_t *CT, uint8_t TAG[16],
    uint32_t *cyc_init,uint32_t *cyc_aad,uint32_t *cyc_msg,uint32_t *cyc_fin)
{
    uint32_t s[4]={0}, key[4]; for(int i=0;i<4;i++) key[i]=load32_be(K+4*i);
#if USE_PMU
    uint32_t c0=pmu_get_cyccnt();
#endif
    s[0]=load32_be(N+0); s[1]=load32_be(N+4); s[2]=load32_be(N+8); s[3]=load32_be(N+12);
    tinyjambu_permutation(s,key,1024);
#if USE_PMU
    uint32_t c1=pmu_get_cyccnt();
    *cyc_init=c1-c0;
#else
    *cyc_init=0;
#endif
#if USE_PMU
    uint32_t c2=pmu_get_cyccnt();
#endif
    /* AAD */
    const uint8_t *p=AAD; size_t l=aad_len; while(l>=4){ s[0]^=load32_be(p); tinyjambu_permutation(s,key,384); p+=4; l-=4; }
    if(l){ uint8_t buf[4]={0}; for(size_t i=0;i<l;i++) buf[i]=p[i]; buf[l]^=0x80; s[0]^=load32_be(buf); tinyjambu_permutation(s,key,384); }
#if USE_PMU
    uint32_t c3=pmu_get_cyccnt();
    *cyc_aad=c3-c2;
#else
    *cyc_aad=0;
#endif
#if USE_PMU
    uint32_t c4=pmu_get_cyccnt();
#endif
    /* PT -> CT */
    p=PT; l=pt_len; while(l>=4){ uint32_t ks=s[1]; uint32_t m=load32_be(p); store32_be(CT, ks^m); s[0]^=m; tinyjambu_permutation(s,key,1152); p+=4; CT+=4; l-=4; }
    if(l){
        uint8_t buf[4]={0};
        for(size_t i=0;i<l; i++){ buf[i]=p[i]; }
        buf[l]^=0x80;

        uint32_t m  = load32_be(buf);
        uint32_t ks = s[1];
        uint32_t c  = m ^ ks;
        uint8_t out[4];
        store32_be(out, c);

        for(size_t i=0;i<l; i++){ ((uint8_t*)CT)[i]=out[i]; }

        /* döngü DIŞINDA tek kez yapılması gereken state güncellemeleri: */
        s[0] ^= m;
        tinyjambu_permutation(s, key, 1152);
    }

#if USE_PMU
    uint32_t c5=pmu_get_cyccnt();
    *cyc_msg=c5-c4;
#else
    *cyc_msg=0;
#endif
#if USE_PMU
    uint32_t c6=pmu_get_cyccnt();
#endif
    /* final: 640 rounds + tag */
    tinyjambu_permutation(s,key,640);
    for(int i=0;i<4;i++) store32_be(TAG+4*i, s[i]^key[i]);
#if USE_PMU
    uint32_t c7=pmu_get_cyccnt();
    *cyc_fin=c7-c6;
#else
    *cyc_fin=0;
#endif
}

/* ===================================================================== */
/* ===========================  PRESENT-128  ============================ */
/* ===================================================================== */
static const uint8_t P8_S[16]={0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2};
static uint64_t present128_roundkeys[32]; /* 32 round (k128) */

static uint64_t p8_sbox_layer(uint64_t s){ uint64_t o=0; for(int i=0;i<16;i++){ uint8_t nib=(s>>(i*4))&0xF; o |= (uint64_t)P8_S[nib]<<(i*4); } return o; }
static uint64_t p8_pLayer(uint64_t s){
    uint64_t o=0; for(int i=0;i<64;i++){ int pos = (i==63)?63 : ( (16*i) % 63 ); o |= ((s>>i)&1ULL) << pos; } return o;
}
/* 128-bit key schedule (sadece 64-bit ile rotl_128(k,61)) */
static void present128_key_schedule(const uint8_t K[16]){
    uint64_t khi = load64_be(K);
    uint64_t klo = load64_be(K+8);
    for (int r = 1; r <= 32; r++) {
        present128_roundkeys[r - 1] = khi;
        uint64_t new_hi = (khi << 61) | (klo >> 3);
        uint64_t new_lo = (klo << 61) | (khi >> 3);
        khi = new_hi; klo = new_lo;
        uint8_t ms   = (uint8_t)((khi >> 60) & 0xF);
        uint8_t repl = P8_S[ms];
        khi = (khi & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)repl << 60);
        klo ^= (uint64_t)r;
    }
}
static void present128_encrypt_block(uint8_t out[8], const uint8_t in[8]){
    uint64_t s=load64_be(in);
    for(int r=0;r<31;r++){ s ^= present128_roundkeys[r]; s = p8_sbox_layer(s); s = p8_pLayer(s); }
    s ^= present128_roundkeys[31];
    store64_be(out,s);
}
/* 128-bit PT (2x64) -> 128-bit CT (ECB iki blok) */
static void present128_encrypt_2x64(const uint8_t key16[16], const uint8_t pt16[16], uint8_t ct16[16]){
    present128_key_schedule(key16);
    present128_encrypt_block(ct16,   pt16);
    present128_encrypt_block(ct16+8, pt16+8);
}



/* ===== JAMBU (JM-PRESENT-128) yardımcıları ===== */
static inline uint64_t get64(const uint8_t* p, size_t n, size_t i){
    uint8_t b[8]={0}; size_t r = (n - i>=8)?8:(n-i);
    if (r) b_memcpy(b, p+i, r);
    return load64_be(b);
}
static inline void put64(uint8_t* p, size_t n, size_t i, uint64_t v){
    uint8_t b[8]; store64_be(b,v); size_t r=(n - i>=8)?8:(n-i); if(r) b_memcpy(p+i,b,r);
}
static const uint64_t JAMBU_DOM_AAD  = 0xA0A0A0A0A0A0A0A0ULL;
static const uint64_t JAMBU_DOM_MSG  = 0xB1B1B1B1B1B1B1B1ULL;
static const uint64_t JAMBU_DOM_FIN  = 0xC2C2C2C2C2C2C2C2ULL;

/* JM-PRESENT-128 AEAD (tag 8B) — bizim PRESENT implementasyonunu kullanır */
static void jambu_present128_encrypt(
    const uint8_t K[16], const uint8_t N[16],
    const uint8_t *AAD, size_t aad_len,
    const uint8_t *PT,  size_t pt_len,
    uint8_t *CT, uint8_t TAG8[8],
    uint32_t *cyc_init, uint32_t *cyc_aad, uint32_t *cyc_msg, uint32_t *cyc_fin)
{
    uint64_t S=0, R=0; uint8_t b8[8];

#if USE_PMU
    uint32_t c0=pmu_get_cyccnt();
#endif

    /* Init: S = E_K(N0 ^ N1), R = 0 */
    uint64_t n0=load64_be(N), n1=load64_be(N+8);
    store64_be(b8, n0 ^ n1);
    present128_key_schedule(K);
    present128_encrypt_block(b8, b8);
    S = load64_be(b8); R = 0;

#if USE_PMU
    uint32_t c1=pmu_get_cyccnt();
    *cyc_init=c1-c0;
#else
    *cyc_init=0;
#endif

#if USE_PMU
    uint32_t c2=pmu_get_cyccnt();
#endif
    /* AAD */
    for(size_t i=0;i<=aad_len;i+=8){
        int last = (i+8>=aad_len);
        uint64_t Ai = get64(AAD, aad_len, i);
        if (last && (aad_len%8)!=0){ uint8_t pad[8]={0}; size_t r=aad_len-i; if(r) b_memcpy(pad,AAD+i,r); pad[r]=0x80; Ai=load64_be(pad); }
        uint64_t X = S ^ Ai ^ JAMBU_DOM_AAD;
        store64_be(b8, X); present128_encrypt_block(b8, b8);
        S = load64_be(b8); R ^= S;
        if (last) break;
    }
#if USE_PMU
    uint32_t c3=pmu_get_cyccnt();
    *cyc_aad=c3-c2;
#else
    *cyc_aad=0;
#endif

#if USE_PMU
    uint32_t c4=pmu_get_cyccnt();
#endif
    /* MSG */
    b_memset(CT,0,pt_len);
    for(size_t i=0;i<=pt_len;i+=8){
        int last = (i+8>=pt_len);
        uint64_t Mi = get64(PT, pt_len, i);
        if (last && (pt_len%8)!=0){ uint8_t pad[8]={0}; size_t r=pt_len-i; if(r) b_memcpy(pad,PT+i,r); pad[r]=0x80; Mi=load64_be(pad); }
        uint64_t X = S ^ JAMBU_DOM_MSG; //burada mi vardı. hataydı. Mi ^ifadesi silindi.
        store64_be(b8, X); present128_encrypt_block(b8, b8);
        uint64_t Y = load64_be(b8);
        uint64_t Ci = Mi ^ Y;
        put64(CT, pt_len, i, Ci);
        S = Ci ^ S; R ^= Ci;
        if (last) break;
    }
#if USE_PMU
    uint32_t c5=pmu_get_cyccnt();
    *cyc_msg=c5-c4;
#else
    *cyc_msg=0;
#endif

#if USE_PMU
    uint32_t c6=pmu_get_cyccnt();
#endif
    /* Final: tag 8B */
    uint64_t F = S ^ R ^ JAMBU_DOM_FIN;
    store64_be(b8, F); present128_encrypt_block(b8, b8);
    uint64_t T = load64_be(b8); store64_be(TAG8, T);
#if USE_PMU
    uint32_t c7=pmu_get_cyccnt();
    *cyc_fin=c7-c6;
#else
    *cyc_fin=0;
#endif
}






/* ===================================================================== */
/* ====================== KDF / Nonce / AAD ============================= */
/* ===================================================================== */
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

static void ascon_xof128(const uint8_t*in,size_t inlen,uint8_t*out,size_t outlen); /* fwd */

static void make_nonce(uint8_t N[16], uint32_t dev, uint32_t epoch, uint64_t msg){
    store32_be(N+0,dev); store32_be(N+4,epoch); store64_be(N+8,msg);
}
static void make_aad(uint8_t*A,size_t*alen,uint32_t dev,uint8_t idx,uint64_t msg,uint8_t feat,int with_ts){
    size_t p=0; A[p++]=0x01; store32_be(A+p,dev); p+=4; A[p++]=idx; store64_be(A+p,msg); p+=8; A[p++]=feat;
    if(with_ts){ uint64_t t=gt_read(); store64_be(A+p,t); p+=8; }
    *alen=p;
}

static void kdf_from_xof(const uint8_t Sroot[32], uint32_t device_id, const uint8_t slice_i[16], uint8_t K_out16[16]){
    uint8_t buf[3+32+4+16]; size_t p=0;
    buf[p++]='K'; buf[p++]='D'; buf[p++]='F';
    b_memcpy(buf+p,Sroot,32); p+=32;
    store32_be(buf+p,device_id); p+=4;
    b_memcpy(buf+p,slice_i,16); p+=16;
    ascon_xof128(buf,p,K_out16,16);
}

/* ===================================================================== */
/* =============================  Rapor  ================================= */
/* ===================================================================== */
static void report_common(uint32_t cycles_total, uint64_t ticks, uint32_t cycles_kdf, uint32_t cycles_aead,
                          uint32_t pt_len, const uint8_t* N, const uint8_t* AAD, size_t aad_len,
                          const uint8_t* PT, const uint8_t* CT, const uint8_t* TAG)
{
    char line[512]; char* w=line;
    s_puts(&w,"PKT;ver=1;nonce_hex="); bytes_to_hex(N,16,&w);
    s_puts(&w,";aad_hex="); bytes_to_hex(AAD,aad_len,&w);
    s_puts(&w,";ct_hex=");  bytes_to_hex(CT,pt_len,&w);
    s_puts(&w,";tag_hex="); bytes_to_hex(TAG,16,&w);
    s_puts(&w,"\r\n"); *w=0; uart_puts(line);

    uint32_t us_total = (uint32_t)u64_div_u32(ticks*1000000ULL + (uint32_t)(GT_FREQ_HZ/2ULL), (uint32_t)GT_FREQ_HZ);

    uint32_t cycles_glue = (cycles_total > (cycles_kdf + cycles_aead)) ? (cycles_total - cycles_kdf - cycles_aead) : 0u;
    uint32_t kdf_us  = (uint32_t)u64_div_u32((uint64_t)cycles_kdf  * 1000000ULL + (uint32_t)(CPU_HZ/2U), (uint32_t)CPU_HZ);
    uint32_t aead_us = (uint32_t)u64_div_u32((uint64_t)cycles_aead * 1000000ULL + (uint32_t)(CPU_HZ/2U), (uint32_t)CPU_HZ);
    uint32_t glue_us = (uint32_t)u64_div_u32((uint64_t)cycles_glue * 1000000ULL + (uint32_t)(CPU_HZ/2U), (uint32_t)CPU_HZ);

    g_acc_ticks += ticks; g_count++;
    uint64_t avg_ticks_per = u64_div_u32(g_acc_ticks, (uint32_t)g_count);
    uint32_t avg_us = (uint32_t)u64_div_u32(avg_ticks_per*1000000ULL + (uint32_t)(GT_FREQ_HZ/2ULL), (uint32_t)GT_FREQ_HZ);

    print_u32_line("[time] us_total=", us_total);
    print_u32_line("[time] avg_us=",   avg_us);
    print_u32_line("[time] kdf_us=",   kdf_us);
    print_u32_line("[time] aead_us=",  aead_us);
    print_u32_line("[time] glue_us=",  glue_us);
    print_u32_line("[pmu ] cycles_total=", cycles_total);
    print_u32_line("[pmu ] kdf_cycles=",   cycles_kdf);
    print_u32_line("[pmu ] aead_cycles=",  cycles_aead);

    /* Nonce alanları */
    uint32_t dev=load32_be(N+0), epoch=load32_be(N+4); uint64_t msg=load64_be(N+8);
    print_u32_line("[nonce] dev=",dev); print_u32_line("[nonce] epoch=",epoch); print_u64_line("[nonce] msg=",msg);
    uart_puts("[nonce] raw(hex): "); dump_hex(N,16);

    /* AAD alanları */
    print_u32_line("[aad ] len=", (uint32_t)aad_len);
    if(aad_len==15 || aad_len==23){
        uint8_t  ver=AAD[0]; uint32_t d=load32_be(AAD+1); uint8_t idx=AAD[5]; uint64_t m=load64_be(AAD+6); uint8_t feat=AAD[14];
        print_u32_line("[aad ] ver=",ver); print_u32_line("[aad ] dev=",d);
        print_u32_line("[aad ] idx=",idx); print_u64_line("[aad ] msg=",m); print_u32_line("[aad ] feat=",feat);
        if(aad_len==23){ uint64_t ts=load64_be(AAD+15); print_u64_line("[aad ] ts=",ts); }
    }
    uart_puts("[aad ] raw(hex): "); dump_hex(AAD,aad_len);

    /* PT/CT/TAG */
    print_u32_line("[pt  ] len=", pt_len);
    uart_puts("[pt  ] ascii: "); for(uint32_t i=0;i<pt_len;i++){ char ch=(PT[i]>=32 && PT[i]<=126)?(char)PT[i]:'.'; uart_putc(ch); } uart_puts("\r\n");
    uart_puts("[ct  ] hex: "); dump_hex(CT,pt_len);
    uart_puts("[tag ] hex: "); dump_hex(TAG,16);
}

/* ===================================================================== */
/* ============================  RUNNERS  =============================== */
/* ===================================================================== */

static void run_ascon(int hsf){
    const uint32_t DEVICE_ID=0xAABBCCDDu; static uint32_t epoch_ctr=1; static uint64_t msg_ctr=0; msg_ctr++;
    uint8_t N[16], AAD[32]; size_t aad_len=0; uint8_t PT[]="ThisIsTheMessage"; const uint32_t pt_len=(uint32_t)(sizeof(PT)-1);
    make_nonce(N,DEVICE_ID,epoch_ctr,msg_ctr);
    uint8_t index_i=(uint8_t)((gt_read()^msg_ctr)&0x3u);
    make_aad(AAD,&aad_len,DEVICE_ID,index_i,msg_ctr,0x01,0);

    uint8_t KEY[16]; uint32_t cycles_kdf=0;
    gt_enable_if_needed(); pmu_enable_cyccnt(); pmu_reset_cyccnt();

    uint32_t cyc0=pmu_get_cyccnt(); uint64_t gt0=gt_read(); /* total start: KDF dahil */
    if(hsf){ uint32_t c0=pmu_get_cyccnt(); kdf_from_xof(S_ROOT,DEVICE_ID,POOL[index_i],KEY); uint32_t c1=pmu_get_cyccnt(); cycles_kdf=c1-c0; }
    else { for(int i=0;i<16;i++) KEY[i]=(uint8_t)(0xA0+i); }

    uint8_t CT[pt_len], TAG[16];
    uint32_t cyc_init=0, cyc_aad=0, cyc_msg=0, cyc_fin=0;
    uint32_t c_a0=pmu_get_cyccnt();
    ascon_aead128_encrypt(KEY, N, AAD, aad_len, PT, pt_len, CT, TAG,
                          &cyc_init, &cyc_aad, &cyc_msg, &cyc_fin);
        g_mail_sig = tag32(TAG);
    uint32_t c_a1=pmu_get_cyccnt(); uint32_t cycles_aead=c_a1-c_a0;

    uint64_t gt1=gt_read(); uint32_t cyc1=pmu_get_cyccnt(); uint32_t cycles_total=cyc1-cyc0;
    uart_puts("[key ] hex: "); dump_hex(KEY,16);

    uart_puts(hsf? "[gizli] ASCON-128 (HSF) basladi\r\n" : "[gizli] ASCON-128 (sade) basladi\r\n");
    report_common(cycles_total, gt1-gt0, cycles_kdf, cycles_aead, pt_len, N, AAD, aad_len, PT, CT, TAG);
    /* tekdüze alt-ölçümler */
    print_u32_line("[aead] init_cycles=",cyc_init);
    print_u32_line("[aead] aad_cycles=", cyc_aad);
    print_u32_line("[aead] msg_cycles=", cyc_msg);
    print_u32_line("[aead] fin_cycles=", cyc_fin);
    uart_puts("[gizli] bitti\r\n");
}

static void run_acorn(int hsf){
    const uint32_t DEVICE_ID=0xAABBCCDDu; static uint32_t epoch_ctr=1; static uint64_t msg_ctr=0; msg_ctr++;
    uint8_t N[16], AAD[32]; size_t aad_len=0; uint8_t PT[]="ThisIsTheMessage"; const uint32_t pt_len=(uint32_t)(sizeof(PT)-1);
    make_nonce(N,DEVICE_ID,epoch_ctr,msg_ctr);
    uint8_t index_i=(uint8_t)((gt_read()^msg_ctr)&0x3u);
    make_aad(AAD,&aad_len,DEVICE_ID,index_i,msg_ctr,0x01,0);

    uint8_t KEY[16]; uint32_t cycles_kdf=0;
    gt_enable_if_needed(); pmu_enable_cyccnt(); pmu_reset_cyccnt();

    uint32_t cyc0=pmu_get_cyccnt(); uint64_t gt0=gt_read();
    if(hsf){ uint32_t c0=pmu_get_cyccnt(); kdf_from_xof(S_ROOT,DEVICE_ID,POOL[index_i],KEY); uint32_t c1=pmu_get_cyccnt(); cycles_kdf=c1-c0; }
    else   { for(int i=0;i<16;i++) KEY[i]=(uint8_t)(0xB0+i); }


    uint8_t CT[pt_len], TAG[16];
    uint32_t cyc_init=0,cyc_aad=0,cyc_msg=0,cyc_fin=0;

    uint32_t c_a0=pmu_get_cyccnt();
    acorn128_aead_encrypt(KEY,N,AAD,aad_len,PT,pt_len,CT,TAG,&cyc_init,&cyc_aad,&cyc_msg,&cyc_fin);
    g_mail_sig = tag32(TAG);
    uint32_t c_a1=pmu_get_cyccnt(); uint32_t cycles_aead=c_a1-c_a0;

    uint64_t gt1=gt_read(); uint32_t cyc1=pmu_get_cyccnt(); uint32_t cycles_total=cyc1-cyc0;
    uart_puts("[key ] hex: "); dump_hex(KEY,16);

    uart_puts(hsf? "[gizli] ACORN-128 (HSF) basladi\r\n" : "[gizli] ACORN-128 (sade) basladi\r\n");
    report_common(cycles_total, gt1-gt0, cycles_kdf, cycles_aead, pt_len, N, AAD, aad_len, PT, CT, TAG);
    print_u32_line("[aead] init_cycles=",cyc_init);
    print_u32_line("[aead] aad_cycles=", cyc_aad);
    print_u32_line("[aead] msg_cycles=", cyc_msg);
    print_u32_line("[aead] fin_cycles=", cyc_fin);
    uart_puts("[gizli] bitti\r\n");
}

static void run_tinyjambu(int hsf){
    const uint32_t DEVICE_ID=0xAABBCCDDu; static uint32_t epoch_ctr=1; static uint64_t msg_ctr=0; msg_ctr++;
    uint8_t N[16], AAD[32]; size_t aad_len=0; uint8_t PT[]="ThisIsTheMessage"; const uint32_t pt_len=(uint32_t)(sizeof(PT)-1);
    make_nonce(N,DEVICE_ID,epoch_ctr,msg_ctr);
    uint8_t index_i=(uint8_t)((gt_read()^msg_ctr)&0x3u);
    make_aad(AAD,&aad_len,DEVICE_ID,index_i,msg_ctr,0x01,0);

    uint8_t KEY[16]; uint32_t cycles_kdf=0;
    gt_enable_if_needed(); pmu_enable_cyccnt(); pmu_reset_cyccnt();

    uint32_t cyc0=pmu_get_cyccnt(); uint64_t gt0=gt_read();
    if(hsf){ uint32_t c0=pmu_get_cyccnt(); kdf_from_xof(S_ROOT,DEVICE_ID,POOL[index_i],KEY); uint32_t c1=pmu_get_cyccnt(); cycles_kdf=c1-c0; }
    else   { for(int i=0;i<16;i++) KEY[i]=(uint8_t)(0xC0+i); }

    uint8_t CT[pt_len], TAG[16];
    uint32_t cyc_init=0,cyc_aad=0,cyc_msg=0,cyc_fin=0;

    uint32_t c_a0=pmu_get_cyccnt();
    tinyjambu_aead_encrypt(KEY,N,AAD,aad_len,PT,pt_len,CT,TAG,&cyc_init,&cyc_aad,&cyc_msg,&cyc_fin);
    g_mail_sig = tag32(TAG);
    uint32_t c_a1=pmu_get_cyccnt(); uint32_t cycles_aead=c_a1-c_a0;

    uint64_t gt1=gt_read(); uint32_t cyc1=pmu_get_cyccnt(); uint32_t cycles_total=cyc1-cyc0;
    uart_puts("[key ] hex: "); dump_hex(KEY,16);

    uart_puts(hsf? "[gizli] TinyJAMBU-128 (HSF) basladi\r\n" : "[gizli] TinyJAMBU-128 (sade) basladi\r\n");
    report_common(cycles_total, gt1-gt0, cycles_kdf, cycles_aead, pt_len, N, AAD, aad_len, PT, CT, TAG);
    print_u32_line("[aead] init_cycles=",cyc_init);
    print_u32_line("[aead] aad_cycles=", cyc_aad);
    print_u32_line("[aead] msg_cycles=", cyc_msg);
    print_u32_line("[aead] fin_cycles=", cyc_fin);
    uart_puts("[gizli] bitti\r\n");
}

static void run_present(int hsf){
    const uint32_t DEVICE_ID=0xAABBCCDDu; static uint32_t epoch_ctr=1; static uint64_t msg_ctr=0; msg_ctr++;
    uint8_t N[16], AAD[32]; size_t aad_len=0; uint8_t PT[]="ThisIsTheMessage"; const uint32_t pt_len=(uint32_t)(sizeof(PT)-1);
    make_nonce(N,DEVICE_ID,epoch_ctr,msg_ctr);
    uint8_t index_i=(uint8_t)((gt_read()^msg_ctr)&0x3u);
    make_aad(AAD,&aad_len,DEVICE_ID,index_i,msg_ctr,0x01,0);

    uint8_t KEY[16]; uint32_t cycles_kdf=0;
    gt_enable_if_needed(); pmu_enable_cyccnt(); pmu_reset_cyccnt();

    uint32_t cyc0=pmu_get_cyccnt(); uint64_t gt0=gt_read();
    if(hsf){ uint32_t c0=pmu_get_cyccnt(); kdf_from_xof(S_ROOT,DEVICE_ID,POOL[index_i],KEY); uint32_t c1=pmu_get_cyccnt(); cycles_kdf=c1-c0; }
    else   { for(int i=0;i<16;i++) KEY[i]=(uint8_t)(0xD0+i); }

    uint8_t CT[pt_len], TAG[16]; for(int i=0;i<16;i++) TAG[i]=0; /* AEAD değil -> tag=0 */

    uint32_t c_a0=pmu_get_cyccnt();
    present128_encrypt_2x64(KEY, PT, CT);
    g_mail_sig = tag32(TAG);
    uint32_t c_a1=pmu_get_cyccnt(); uint32_t cycles_aead=c_a1-c_a0;

    uint64_t gt1=gt_read(); uint32_t cyc1=pmu_get_cyccnt(); uint32_t cycles_total=cyc1-cyc0;
    uart_puts("[key ] hex: "); dump_hex(KEY,16);

    uart_puts(hsf? "[gizli] PRESENT-128 (HSF baslik, ECB) basladi\r\n" : "[gizli] PRESENT-128 (sade, ECB) basladi\r\n");
    report_common(cycles_total, gt1-gt0, cycles_kdf, cycles_aead, pt_len, N, AAD, aad_len, PT, CT, TAG);
    print_u32_line("[aead] init_cycles=", 0);
    print_u32_line("[aead] aad_cycles=",  0);
    print_u32_line("[aead] msg_cycles=",  cycles_aead);
    print_u32_line("[aead] fin_cycles=",  0);
    uart_puts("[gizli] bitti\r\n");
}

/* JAMBU (placeholder) */
static void run_jambu(int hsf){
    const uint32_t DEVICE_ID=0xAABBCCDDu; static uint32_t epoch_ctr=1; static uint64_t msg_ctr=0; msg_ctr++;
    uint8_t N[16], AAD[32]; size_t aad_len=0; uint8_t PT[]="ThisIsTheMessage"; const uint32_t pt_len=(uint32_t)(sizeof(PT)-1);
    make_nonce(N,DEVICE_ID,epoch_ctr,msg_ctr);
    uint8_t index_i=(uint8_t)((gt_read()^msg_ctr)&0x3u);
    make_aad(AAD,&aad_len,DEVICE_ID,index_i,msg_ctr,0x01,0);

    uint8_t KEY[16]; uint32_t cycles_kdf=0;
    gt_enable_if_needed(); pmu_enable_cyccnt(); pmu_reset_cyccnt();
    uint32_t cyc0=pmu_get_cyccnt(); uint64_t gt0=gt_read();

    if(hsf){ uint32_t c0=pmu_get_cyccnt(); kdf_from_xof(S_ROOT,DEVICE_ID,POOL[index_i],KEY); uint32_t c1=pmu_get_cyccnt(); cycles_kdf=c1-c0; }
    else   { for(int i=0;i<16;i++) KEY[i]=(uint8_t)(0xE0+i); }

    uint8_t CT[pt_len]; uint8_t TAG8[8];
    uint32_t cyc_init=0,cyc_aad=0,cyc_msg=0,cyc_fin=0;

    /* AEAD (Jambu) */
    uint32_t c_a0=pmu_get_cyccnt();
    jambu_present128_encrypt(KEY,N,AAD,aad_len,PT,pt_len,CT,TAG8,&cyc_init,&cyc_aad,&cyc_msg,&cyc_fin);
    uint32_t c_a1=pmu_get_cyccnt(); uint32_t cycles_aead=c_a1-c_a0;

    /* Tek format için TAG’i 16B buffer’a taşı (8B tag + 8B sıfır) */
    uint8_t TAG16[16]; b_memset(TAG16,0,16); b_memcpy(TAG16,TAG8,8);

    uint64_t gt1=gt_read(); uint32_t cyc1=pmu_get_cyccnt(); uint32_t cycles_total=cyc1-cyc0;
    /* KEY’i bas */
    uart_puts("[key ] hex: "); dump_hex(KEY,16);

    uart_puts(hsf? "[gizli] JAMBU-PRESENT-128 (HSF) basladi\r\n" : "[gizli] JAMBU-PRESENT-128 (sade) basladi\r\n");
    report_common(cycles_total, gt1-gt0, cycles_kdf, cycles_aead, pt_len, N, AAD, aad_len, PT, CT, TAG16);
    print_u32_line("[aead] init_cycles=",cyc_init);
    print_u32_line("[aead] aad_cycles=", cyc_aad);
    print_u32_line("[aead] msg_cycles=", cyc_msg);
    print_u32_line("[aead] fin_cycles=", cyc_fin);
    uart_puts("[gizli] bitti\r\n");

    /* Mailbox imzası (TAG8’den) */
    g_mail_sig = ((uint32_t)TAG8[0]) | ((uint32_t)TAG8[1]<<8) | ((uint32_t)TAG8[2]<<16) | ((uint32_t)TAG8[3]<<24);
}


/* ----------------- Menü ----------------- */
static void print_menu(void){
    uart_puts("\r\n=== HSF TEST MENUSU ===\r\n");
    uart_puts("1 -> HSF'li ASCON\r\n");
    uart_puts("2 -> Sade ASCON\r\n");
    uart_puts("3 -> HSF'li ACORN\r\n");
    uart_puts("4 -> Sade ACORN\r\n");
    uart_puts("5 -> HSF'li TinyJAMBU\r\n");
    uart_puts("6 -> Sade TinyJAMBU\r\n");
    uart_puts("7 -> HSF'li PRESENT\r\n");
    uart_puts("8 -> Sade PRESENT\r\n");
    uart_puts("9 -> HSF'li JAMBU\r\n");
    uart_puts("0 -> Sade JAMBU\r\n");
    uart_puts("X -> Ana menüye dön / reset\r\n");
    uart_puts("=======================\r\n");
    uart_puts("> ");
}

/* BRAM entry — tek atış: seçim yoksa içeride menüde blokla; seçim varsa bir tur koşup RETURN */
__attribute__((used, noinline, section(".bench.entry")))
void gizli_fonksiyon(uint32_t mailbox_addr)
{
    volatile uint32_t* mb = (volatile uint32_t*)mailbox_addr;
    *mb = 0x11111111;

    gt_enable_if_needed();
#if USE_PMU
    pmu_enable_cyccnt();
#endif

    /* Her çağrının başında X yakala (kullanıcı arada yollamış olabilir) */
    char k = uart_getc_nowait();
    if (k=='X' || k=='x'){
        reset_averages();
        g_choice = 0;
        uart_puts("[menu] reset: ortalamalar sifirlandi, ana menude.\r\n");
    }

    /* Seçim yoksa: menüde blokla ve geçerli seçim al */
    if (g_choice == 0){
        print_menu();
        char ch;
        do { ch = read_choice_blocking(); } while (ch=='\r' || ch=='\n');
        if (ch=='X' || ch=='x'){
            reset_averages();
            g_choice = 0;
            *mb = 0x22222222; /* menude bekliyor imzasi */
            return;
        }
        if (ch>='0' && ch<='9'){
            reset_averages();   /* yeni moda girerken ortalamalar sıfır */
            g_choice = ch;
        } else {
            uart_puts("[menu] Gecersiz secim\r\n");
            *mb = 0x22222222;
            return;
        }
    }

    /* Tek tur çalıştır ve RETURN: dışarıda [RET] görünür */
    switch (g_choice){
        case '1': run_ascon(1);       break;
        case '2': run_ascon(0);       break;
        case '3': run_acorn(1);       break;
        case '4': run_acorn(0);       break;
        case '5': run_tinyjambu(1);   break;
        case '6': run_tinyjambu(0);   break;
        case '7': run_present(1);     break;
        case '8': run_present(0);     break;
        case '9': run_jambu(1); break;
        case '0': run_jambu(0); break;
        default:  uart_puts("[menu] Gecersiz secim\r\n"); *mb=0x22222222; return;
    }

    /* Çalıştırma bitti */
    *mb = g_mail_sig;  /* dinamik imza: TAG[0..3] */

    /* Post-key: kullanıcı X gönderdiyse bir sonraki çağrıda menüye düş */
    char post = uart_getc_nowait();
    if (post=='X' || post=='x'){
        reset_averages();
        g_choice = 0;
		uart_puts("[menu] reset: bir sonraki calismada ana menude.\r\n");
    }
}
