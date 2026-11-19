#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <nmmintrin.h>
#include "../runtime/emu.c"

static uint64_t rnd64(void){ return ((uint64_t)rand()<<62)^((uint64_t)rand()<<31)^rand(); }
static void rnd_str(uint8_t *v){
  int mode = rand()%3;
  for(int i=0;i<16;i++){
    if(mode==0) v[i]=rand();
    else if(mode==1) v[i]="abc\0xyz"[rand()%7];
    else v[i]=(rand()%4==0)?0:(rand()%3)+'a';
  }
}
struct emu_desc dsc;
int fails=0;
#define CHECK(cond, ...) do{ if(!(cond)){ if(fails++<20) printf(__VA_ARGS__); } }while(0)

static uint64_t native_flags(void){ return 0; }

#define DO_EST(IMM) do{ \
   __m128i A=_mm_loadu_si128((void*)a), B=_mm_loadu_si128((void*)b); \
   int ri=_mm_cmpestri(A,la,B,lb,IMM); int cf=_mm_cmpestrc(A,la,B,lb,IMM), zf=_mm_cmpestrz(A,la,B,lb,IMM), sf=_mm_cmpestrs(A,la,B,lb,IMM), of=_mm_cmpestro(A,la,B,lb,IMM); \
   __m128i rm=_mm_cmpestrm(A,la,B,lb,IMM); \
   int ii=_mm_cmpistri(A,B,IMM); int icf=_mm_cmpistrc(A,B,IMM), izf=_mm_cmpistrz(A,B,IMM), isf=_mm_cmpistrs(A,B,IMM), iof=_mm_cmpistro(A,B,IMM); __m128i im=_mm_cmpistrm(A,B,IMM); \
   for(int op=3;op<=6;op++){ struct emu_ctx c; memset(&c,0,sizeof c); memcpy(c.xmm[1],a,16); memcpy(c.xmm[2],b,16); c.rax=(uint32_t)la; c.rdx=(uint32_t)lb; c.rcx=0xdeadbeefcafebabeULL; c.rflags=0x202; \
     memset(&dsc,0,sizeof dsc); dsc.op=op; dsc.dst=1; dsc.src=2; dsc.imm=IMM; dsc.srcsize=16; dsc.base=dsc.index=0xff; c.ret=(uint64_t)&dsc; emu_dispatch(&c); \
     int ecf=!!(c.rflags&FL_CF), ezf=!!(c.rflags&FL_ZF), esf=!!(c.rflags&FL_SF), eof=!!(c.rflags&FL_OF); \
     if(op==3){ CHECK(c.rcx==(uint64_t)ri && ecf==cf&&ezf==zf&&esf==sf&&eof==of, "estri imm=%02x la=%d lb=%d got %lx/%d%d%d%d want %x/%d%d%d%d\n",IMM,la,lb,c.rcx,ecf,ezf,esf,eof,ri,cf,zf,sf,of);} \
     if(op==4){ CHECK(!memcmp(c.xmm[0],&rm,16)&& ecf==cf&&ezf==zf&&esf==sf&&eof==of, "estrm imm=%02x la=%d lb=%d\n",IMM,la,lb);} \
     if(op==5){ CHECK(c.rcx==(uint64_t)ii && ecf==icf&&ezf==izf&&esf==isf&&eof==iof, "istri imm=%02x got %lx/%d%d%d%d want %x/%d%d%d%d\n",IMM,c.rcx,ecf,ezf,esf,eof,ii,icf,izf,isf,iof);} \
     if(op==6){ CHECK(!memcmp(c.xmm[0],&im,16)&& ecf==icf&&ezf==izf&&esf==isf&&eof==iof, "istrm imm=%02x\n",IMM);} \
   } }while(0)

int main(void){
  srand(1234);
  for(int it=0; it<20000; it++){
    uint8_t a[16], b[16]; rnd_str(a); rnd_str(b);
    int la = (rand()%40)-20, lb=(rand()%40)-20;
#define X(i) DO_EST(i);
    X(0x00)X(0x01)X(0x02)X(0x03)X(0x04)X(0x05)X(0x06)X(0x07)X(0x08)X(0x09)X(0x0a)X(0x0b)X(0x0c)X(0x0d)X(0x0e)X(0x0f)
    X(0x10)X(0x14)X(0x18)X(0x1c)X(0x20)X(0x24)X(0x28)X(0x2c)X(0x30)X(0x34)X(0x38)X(0x3c)X(0x31)X(0x35)X(0x39)X(0x3d)
    X(0x40)X(0x44)X(0x48)X(0x4c)X(0x41)X(0x45)X(0x49)X(0x4d)X(0x70)X(0x74)X(0x78)X(0x7c)X(0x73)X(0x77)X(0x7b)X(0x7f)
    X(0x12)X(0x16)X(0x1a)X(0x1e)X(0x33)X(0x37)X(0x3b)X(0x3f)X(0x42)X(0x46)X(0x4a)X(0x4e)X(0x62)X(0x66)X(0x6a)X(0x6e)

    uint64_t v=rnd64(), crc=rnd64();
    for(int sz=2; sz<=8; sz*=2){ struct emu_ctx c; memset(&c,0,sizeof c); c.rbx=v; c.rsi=0x1111222233334444ULL; memset(&dsc,0,sizeof dsc); dsc.op=1; dsc.dst=6; dsc.src=3; dsc.srcsize=sz; dsc.dstsize=sz; dsc.base=dsc.index=0xff; c.ret=(uint64_t)&dsc; emu_dispatch(&c);
      uint64_t want = sz==8? __builtin_popcountll(v): sz==4? (uint64_t)__builtin_popcount((uint32_t)v) : (0x1111222233330000ULL | __builtin_popcount((uint16_t)v));
      CHECK(c.rsi==want && (!!(c.rflags&FL_ZF))==(want==0||(sz==2&&(uint16_t)v==0)), "popcnt sz%d\n",sz); }
    for(int sz=1; sz<=8; sz*=2){ struct emu_ctx c; memset(&c,0,sizeof c); c.r9=v; c.rax=crc; memset(&dsc,0,sizeof dsc); dsc.op=2; dsc.dst=0; dsc.src=9; dsc.srcsize=sz; dsc.base=dsc.index=0xff; c.ret=(uint64_t)&dsc; emu_dispatch(&c);
      uint64_t want = sz==1? _mm_crc32_u8(crc,v): sz==2? _mm_crc32_u16(crc,v): sz==4? _mm_crc32_u32(crc,v): _mm_crc32_u64(crc,v);
      CHECK(c.rax==want, "crc sz%d %lx vs %lx\n",sz,c.rax,want); }
    { struct emu_ctx c; memset(&c,0,sizeof c); uint64_t x[2]={rnd64(),rnd64()}, y[2]={rnd64(),rand()%2?x[1]:rnd64()}; memcpy(c.xmm[3],x,16); memcpy(c.xmm[7],y,16);
      memset(&dsc,0,sizeof dsc); dsc.op=7; dsc.dst=3; dsc.src=7; dsc.srcsize=16; dsc.base=dsc.index=0xff; c.ret=(uint64_t)&dsc; emu_dispatch(&c);
      __m128i w=_mm_cmpgt_epi64(_mm_loadu_si128((void*)x),_mm_loadu_si128((void*)y)); CHECK(!memcmp(&w,c.xmm[3],16),"pcmpgtq\n"); }
  }
  printf("fails=%d\n", fails);
  return fails!=0;
}
