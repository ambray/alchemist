#include <stdlib.h>
#include <stdio.h>
#include "../common_includes/alchemy_defs.h"

SET_ANNOTATION("marshal", "bytes") 
OUT_PARAM(outbuf)
bool marshal_bytes(unsigned long id, const unsigned char* buf, unsigned long size,
                   unsigned char* outbuf, unsigned long outbuf_size)
{
    unsigned long idx = 0;

    if(NULL == buf || NULL == outbuf)
        return false;

    if((size + (sizeof(unsigned long) * 2)) > outbuf_size)
        return false;

    idx = sizeof(id);
    memcpy(outbuf, &id, idx);
    memcpy(&outbuf[idx], &size, sizeof(size));
    idx += sizeof(unsigned long);
    memcpy(&outbuf[idx], buf, size);

    return true;
}

SET_ANNOTATION("marshal", "word")
OUT_PARAM(outbuf)
bool marshal_word(unsigned long id, unsigned short val, unsigned char* outbuf, 
                  unsigned long outbuf_size)
{
    if(NULL == outbuf || outbuf_size < (sizeof(unsigned long) + sizeof(unsigned short)))
        return false;

    memcpy(outbuf, &id, sizeof(id));   
    memcpy(&outbuf[sizeof(unsigned long)], &val, sizeof(val));

    return true;
}

SET_ANNOTATION("marshal", "dword")
OUT_PARAM(outbuf)
bool marshal_dword(unsigned long id, unsigned int val, unsigned char* outbuf, unsigned long outsize)
{

    return true;
}

SET_ANNOTATION("marshal", "qword")
OUT_PARAM(outbuf)
bool marshal_qword(unsigned long id, unsigned long long val, unsigned char* outbuf, 
                   unsigned long outsize)
{

    return false;
}

SET_ANNOTATION("marshal", "float")
OUT_PARAM(outbuf)
bool marshal_float(unsigned long id, float val, unsigned char* outbuf, unsigned long osize)
{
    return false;
}


SET_ANNOTATION("marshal", "bool")
OUT_PARAM(outbuf)
bool marshal_bool(unsigned long id, bool val, unsigned char* outbuf, unsigned long osize)
{
    return false;
}


SET_ANNOTATION("marshal-size")
unsigned long get_size(unsigned long id, unsigned long input_size)
{
    return sizeof(unsigned long) + input_size;
}
