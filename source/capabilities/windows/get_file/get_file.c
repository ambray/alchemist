#include <alchemy_defs.h>
#ifdef _WIN32
#include <Windows.h>
#else

#define NULL                        (void*)0
#define HANDLE                      void*
#define INVALID_HANDLE_VALUE        ((void*)-1)
#define GENERIC_READ                0x80000000
#define FILE_SHARE_READ             0x00000001
#define OPEN_EXISTING               0x00000003
#define FILE_ATTRIBUTE_NORMAL       0x00000080
#define HEAP_ZERO_MEMORY            0x00000008

extern void __stdcall CloseHandle(void*);
extern void* __stdcall CreateFileW(const wchar_t* fileName, unsigned int access,
                                   unsigned int share, void* sec, unsigned int create,
                                   unsigned int attrs, void* hTemp);

extern bool __stdcall ReadFile(void* hFile, void* buf, unsigned int size, 
                               unsigned int* read, void* overlap);

extern unsigned int __stdcall GetFileSize(void* hFile, unsigned int* upper);

extern void __stdcall HeapAlloc(void* hHeap, unsigned int flags, void* p);
extern void __stdcall HeapFree(void* hHeap, unsigned int flags, void* p);
extern void* GetProcessHeap(void);
#endif

typedef get_file_ctx_ {
    HANDLE hFile;
} get_file_ctx;


static bool init_ctx(get_file_ctx* ctx, const wchar_t* path)
{
    if(NULL == ctx || NULL == path)
        return false;

    if(INVALID_HANDLE_VALUE == (ctx->hFile = CreateFileW(path, GENERIC_READ,
                                                         FILE_SHARE_READ, NULL,
                                                         OPEN_EXISTING, 
                                                         FILE_ATTRIBUTE_NORMAL, NULL))) {
        return false;
    }

    return true;
}


static void free_ctx(get_file_ctx* ctx)
{
    if(NULL != ctx && ctx->hFile != INVALID_HANDLE_VALUE)
        CloseHandle(ctx->hFile);
}


static unsigned long long get_size(get_file_ctx* ctx)
{
    union {
        struct {
            unsigned int dwLow;
            unsigned int dwHigh;
        } s;
        long long total;
    } u;

    if(NULL == ctx || INVALID_HANDLE_VALUE == ctx->hFile)
        return 0;
    
    u.s.dwLow = GetFileSize(ctx->hFile, &u.s.dwHigh);

    return u.total; 
}

void free_buffer(unsigned char* buf)
{
    if(NULL != buf)
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, buf);

}

OUT_PARAM_DEALLOC(buf, free_buffer)
OUT_PARAM(size)
FAIL_IF(return, false)
ENTRY_POINT
bool get_file(const wchar_t* path, unsigned char** buf, unsigned long long* size)
{
    get_file_ctx       f = {0};
    bool               rv = true;
    unsigned long long tmpSize = 0;
    unsigned char*     tmpBuf = NULL;
    unsigned int       dwRead = 0;

    if(NULL == path || NULL == buf || NULL == size)
        return false;
    
    if(!init_ctx(&f, path))
        return false;   

    if(0 == (tmpSize = get_size(&f))) {
        rv = false;
        goto cleanup;
    }

    if(NULL == (tmpBuf = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tmpSize))) {
        rv = false;
        goto cleanup;
    }
   
    if(!ReadFile(f.hFile, tmpBuf, tmpSize, &dwRead) || 0 == dwRead) {
        rv = false;
        goto cleanup;
    }

    *buf = tmpBuf;
    *size = tmpSize;
cleanup:
    free_ctx(&f);    
    return rv;
}
