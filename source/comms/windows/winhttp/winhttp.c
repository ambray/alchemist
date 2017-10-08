#include <alchemy_defs.h>

#ifdef _WIN32
#include <Windows.h>
#else

#endif

typedef comms_ctx_ {
    HINTERNET  Session;
    HINTERNET  Connect;
    HINTERNET  Request;
} comms_ctx;

bool comms_init(comms_ctx* ctx, const wchar_t* url)
{
    return true;
}

bool comms_send(comms_ctx* ctx, const void* buf, unsigned long size)
{

    return true;
}

void comms_dealloc(void* buf)
{

}

bool comms_recv(comms_ctx* ctx, void** buf, unsigned long* size)
{

    return true;
}

void comms_free(comms_ctx* ctx)
{

}
