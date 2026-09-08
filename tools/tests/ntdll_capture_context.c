// Execute the actual PE export under macOS x86-64/Rosetta, without running DllMain/imports.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef struct __attribute__((aligned(16))) {
    uint8_t seed[512], expected_fx[512], saved_fx[512];
    uint64_t rsp, rip, flags;
    uint16_t selectors[6];
} Probe;
typedef struct __attribute__((aligned(16))) {
    uint8_t before[32], context[0x4d0], after[32];
} GuardedContext;
_Static_assert(offsetof(Probe, rsp) == 1536, "assembly probe layout");
_Static_assert(offsetof(Probe, selectors) == 1560, "assembly selectors layout");
extern void capture_artifact_probe(void *entry, void *context, Probe *probe);

static void require(int valid, const char *what) {
    if (!valid) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
}
static uint16_t u16(const uint8_t *p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
static void put16(uint8_t *p, uint16_t v) { memcpy(p,&v,2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p,&v,4); }
static void span(size_t offset, size_t length, size_t limit) {
    require(offset <= limit && length <= limit-offset, "PE span outside image/file");
}
static void equal(const uint8_t *a, const uint8_t *b, size_t n, const char *name) {
    for (size_t i=0;i<n;i++) if (a[i]!=b[i]) {
        fprintf(stderr,"FAIL: %s byte %zu: %02x != %02x\n",name,i,a[i],b[i]); exit(1);
    }
}
static void filled(const uint8_t *p, size_t n, uint8_t byte, const char *name) {
    for (size_t i=0;i<n;i++) require(p[i]==byte,name);
}

static void *load_capture(const char *path, void **mapping, size_t *mapped_size) {
    FILE *f=fopen(path,"rb"); require(f!=NULL,"open ntdll.dll");
    require(fseek(f,0,SEEK_END)==0,"seek DLL"); long end=ftell(f);
    require(end>0 && end<=256*1024*1024,"bounded DLL size"); rewind(f);
    size_t size=(size_t)end; uint8_t *file=malloc(size); require(file!=NULL,"file allocation");
    require(fread(file,1,size,f)==size,"read DLL"); fclose(f);
    span(0,64,size); require(u16(file)==0x5a4d,"DOS magic");
    size_t pe=u32(file+0x3c); span(pe,24,size);
    require(u32(file+pe)==0x4550 && u16(file+pe+4)==0x8664,"AMD64 PE signature");
    size_t sections=u16(file+pe+6), optional_size=u16(file+pe+20), opt=pe+24;
    span(opt,optional_size,size); require(optional_size>=120 && u16(file+opt)==0x20b,"PE32+ optional header");
    size_t image_size=u32(file+opt+56), headers=u32(file+opt+60);
    require(image_size>0 && image_size<=256*1024*1024,"bounded image size");
    span(0,headers,size); span(0,headers,image_size);
    uint8_t *image=mmap(NULL,image_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    require(image!=MAP_FAILED,"map DLL staging"); memcpy(image,file,headers);
    size_t table=opt+optional_size; span(table,sections*40,size);
    for(size_t i=0;i<sections;i++) {
        const uint8_t *s=file+table+i*40;
        size_t va=u32(s+12), raw=u32(s+20), bytes=u32(s+16);
        span(va,u32(s+8),image_size); span(va,bytes,image_size); span(raw,bytes,size);
        require(va>=headers || bytes==0,"section must not overwrite headers");
        memcpy(image+va,file+raw,bytes);
    }
    require(u32(file+opt+108)>=1,"export directory present");
    size_t ex=u32(file+opt+112), ex_size=u32(file+opt+116);
    span(ex,ex_size,image_size); require(ex_size>=40,"export header");
    const uint8_t *e=image+ex;
    size_t functions=u32(e+20), names=u32(e+24), funcs=u32(e+28), strings=u32(e+32), ords=u32(e+36);
    span(funcs,functions*4,image_size); span(strings,names*4,image_size); span(ords,names*2,image_size);
    size_t rva=0;
    for(size_t i=0;i<names;i++) {
        size_t name=u32(image+strings+i*4); span(name,1,image_size);
        require(memchr(image+name,0,image_size-name)!=NULL,"terminated export name");
        if(strcmp((const char *)image+name,"RtlCaptureContext")==0) {
            size_t ordinal=u16(image+ords+i*2); require(ordinal<functions,"export ordinal");
            rva=u32(image+funcs+ordinal*4); break;
        }
    }
    require(rva!=0 && rva<image_size,"capture export found");
    require(rva<ex || rva-ex>=ex_size,"capture is not a forwarded export");
    int executable=0;
    for(size_t i=0;i<sections;i++) {
        const uint8_t *s=file+table+i*40; size_t va=u32(s+12), bytes=u32(s+16);
        if(rva>=va && rva-va<bytes && (u32(s+36)&0x20000000)) executable=1;
    }
    require(executable,"capture export has actual executable bytes");
    // The audited capture export/body has no absolute relocations or external dependencies.
    require(mprotect(image,image_size,PROT_READ|PROT_EXEC)==0,"make artifact executable");
    free(file); *mapping=image; *mapped_size=image_size; return image+rva;
}

int main(int argc, char **argv) {
    require(argc==2,"usage: ntdll_capture_context /absolute/path/ntdll.dll");
    void *mapping; size_t mapped_size;
    void *entry=load_capture(argv[1],&mapping,&mapped_size);
    Probe p; memset(&p,0,sizeof(p));
    GuardedContext output; memset(&output,0xcc,sizeof(output));
    memset(output.before,0xa7,sizeof(output.before)); memset(output.after,0x7a,sizeof(output.after));
    put16(p.seed,0x027f); p.seed[4]=0xff; put32(p.seed+24,0x1f80);
    // Eight finite 80-bit x87 values, each in a 16-byte physical register slot.
    for(size_t i=0;i<8;i++) { p.seed[32+i*16]=0x10+i; p.seed[39+i*16]=0x80; put16(p.seed+40+i*16,0x3fff+i); }
    for(size_t i=0;i<256;i++) p.seed[160+i]=(uint8_t)(i*37+11);
    // FXSAVE leaves its software-reserved tail untouched; compare defined fields separately.
    memset(p.expected_fx,0xcc,sizeof(p.expected_fx));
    capture_artifact_probe(entry,output.context,&p);
    const uint8_t *c=output.context;
    require(u32(c+0x30)==0x10000f,"FULL|SEGMENTS flags");
    require(u32(c+0x44)==(uint32_t)p.flags,"actual entry EFLAGS");
    equal(c+0x38,(const uint8_t *)p.selectors,12,"actual segment selectors");
    for(size_t i=0;i<16;i++) {
        uint64_t expected=UINT64_C(0x1111000000000000)+i;
        if(i==1) expected=(uintptr_t)c;
        if(i==4) expected=p.rsp;
        require(u64(c+0x78+i*8)==expected,"captured GPR/RSP sentinel");
    }
    require(u64(c+0xf8)==p.rip,"actual call return RIP");
    require(u32(c+0x34)==u32(p.expected_fx+24),"top-level MXCSR");
    equal(c+0x100,p.expected_fx,32,"x87 control/status/pointers/MXCSR");
    for(size_t i=0;i<8;i++) equal(c+0x120+i*16,p.expected_fx+32+i*16,10,"80-bit x87 register");
    equal(c+0x1a0,p.expected_fx+160,256,"all sixteen XMM registers");
    filled(c,0x30,0xcc,"home slots unchanged");
    filled(c+0x48,0x30,0xcc,"debug registers unchanged");
    filled(c+0x2a0,96,0xcc,"FX software-reserved tail unchanged");
    filled(c+0x300,0x1d0,0xcc,"vector/debug extension unchanged");
    filled(output.before,sizeof(output.before),0xa7,"leading canary");
    filled(output.after,sizeof(output.after),0x7a,"trailing canary");
    require(munmap(mapping,mapped_size)==0,"unmap artifact");
    puts("PASS: actual ntdll RtlCaptureContext GPR/control/selectors/x87/XMM/reserved/canaries");
    return 0;
}
