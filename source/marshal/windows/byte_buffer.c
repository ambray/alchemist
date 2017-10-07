#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <alchemy_defs.h>

MARSHAL_ENTRY(bytes)
OUT_PARAM(outbuf)
FAIL_IF(return, false)
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

UNMARSHAL_ENTRY(bytes)
OUT_PARAM(outbuf)
FAIL_IF(return, false)
bool unmarshal_bytes(const unsigned char* buf, unsigned long size,
                   unsigned char* outbuf, unsigned long outbuf_size)
{
    unsigned long idx = 0;

    if(NULL == buf || NULL == outbuf)
        return false;

    if(size < (sizeof(unsigned long) * 2))
       return false;

    idx = sizeof(unsigned long);
    unsigned long data_size = buf[idx];
    idx += sizeof(unsigned long);

    if(outbuf_size < data_size)
       return false;

    memcpy(outbuf, &buf[idx], data_size);
    return true;
}

MARSHAL_ENTRY(word)
OUT_PARAM(outbuf)
FAIL_IF(return, false)
bool marshal_word(unsigned long id, unsigned short val, unsigned char* outbuf, 
                  unsigned long outbuf_size)
{
    if(NULL == outbuf || outbuf_size < (sizeof(unsigned long) + sizeof(unsigned short)))
        return false;

    memcpy(outbuf, &id, sizeof(id));
    memcpy(&outbuf[sizeof(unsigned long)], &val, sizeof(val));

    return true;
}

MARSHAL_ENTRY(word)
OUT_PARAM(val)
FAIL_IF(return, false)
bool unmarshal_word(unsigned short &val, unsigned char* buf, unsigned long buf_size)
{
    if(NULL == buf || buf_size < (sizeof(unsigned long) + sizeof(unsigned short)))
        return false;

    memcpy(&val, &buf[sizeof(unsigned long)], sizeof(unsigned short));

    return true;
}


MARSHAL_ENTRY(dword)
OUT_PARAM(outbuf)
FAIL_IF(return, false)
bool marshal_dword(unsigned long id, unsigned int val, unsigned char* outbuf, unsigned long outsize)
{

    if(NULL == outbuf || outsize < (sizeof(unsigned long) + sizeof(unsigned int)))
        return false;

    memcpy(outbuf, &id, sizeof(id));
    memcpy(&outbuf[sizeof(unsigned long)], &val, sizeof(val));

    return true;
}

MARSHAL_ENTRY(dword)
OUT_PARAM(val)
FAIL_IF(return, false)
bool unmarshal_dword(unsigned int &val, unsigned char* buf, unsigned long buf_size)
{

    if(NULL == buf || buf_size < (sizeof(unsigned long) + sizeof(unsigned int)))
        return false;

    memcpy(&val, &buf[sizeof(unsigned long)], sizeof(unsigned int));

    return true;
}

MARSHAL_ENTRY(qword)
OUT_PARAM(outbuf)
FAIL_IF(return, false)
bool marshal_qword(unsigned long id, unsigned long long val, unsigned char* outbuf, 
                   unsigned long outsize)
{

    if(NULL == outbuf || outsize < (sizeof(unsigned long) + sizeof(unsigned long long)))
        return false;

    memcpy(outbuf, &id, sizeof(id));
    memcpy(&outbuf[sizeof(unsigned long)], &val, sizeof(val));

    return false;
}

MARSHAL_ENTRY(qword)
OUT_PARAM(val)
FAIL_IF(return, false)
bool unmarshal_qword(unsigned long long &val, unsigned char* buf, unsigned long buf_size)
{

    if(NULL == buf || buf_size < (sizeof(unsigned long) + sizeof(unsigned long long)))
        return false;

    memcpy(&val, &buf[sizeof(unsigned long)], sizeof(unsigned long long));

    return false;
}

MARSHAL_ENTRY(float)
OUT_PARAM(outbuf)
bool marshal_float(unsigned long id, float val, unsigned char* outbuf, unsigned long osize)
{
    if(NULL == outbuf || osize < (sizeof(unsigned long) + sizeof(float)))
        return false;

    memcpy(outbuf, &id, sizeof(id));
    memcpy(&outbuf[sizeof(unsigned long)], &val, sizeof(val));

    return false;
}

MARSHAL_ENTRY(float)
OUT_PARAM(val)
bool unmarshal_float(float &val, unsigned char* buf, unsigned long buf_size)
{
    if(NULL == buf || buf_size < (sizeof(unsigned long) + sizeof(float)))
        return false;

    memcpy(&val, &buf[sizeof(unsigned long)], sizeof(float));

    return false;
}

MARSHAL_ENTRY(bool)
OUT_PARAM(outbuf)
FAIL_IF(return, false)
bool marshal_bool(unsigned long id, bool val, unsigned char* outbuf, unsigned long osize)
{
    if(NULL == outbuf || osize < (sizeof(unsigned long) + sizeof(bool)))
        return false;

    memcpy(outbuf, &id, sizeof(id));
    memcpy(&outbuf[sizeof(unsigned long)], &val, sizeof(val));

    return false;
}

MARSHAL_ENTRY(bool)
OUT_PARAM(val)
FAIL_IF(return, false)
bool unmarshal_bool(bool &val, unsigned char* buf, unsigned long buf_size)
{
    if(NULL == buf || buf_size < (sizeof(unsigned long) + sizeof(bool)))
        return false;

    memcpy(&val, &buf[sizeof(unsigned long)], sizeof(bool));

    return false;
}

//SET_ANNOTATION("marshal-size")
unsigned long get_size(unsigned long id, unsigned long input_size, int type)
{
    return sizeof(unsigned long) + input_size;
}

bool print_buffer(unsigned char* buf, unsigned long buf_size){
    for (int i = 0; i < buf_size; i++){
        printf("%02X", buf[i]);
    }
    printf("\n\n");
    return true;
}

#ifdef TEST
int main(int argc, char *argv[]){

    /* Marshal bytes */
    unsigned long id = 33;
    unsigned char buf[24] = {"THIS IS MARSHALLED DATA"};
    unsigned long size = 24;
    unsigned char outbuf[40];
    unsigned long outbuf_size = 40;
    bool result = marshal_bytes(id, buf, size, outbuf, outbuf_size);
    printf("Data: %s\n", buf);
    printf("\tbuf size: %lu\n", size);
    printf("\tMarshalling Data:\t0x");
    print_buffer(buf, outbuf_size);

    /* Umarshal bytes */
    size = 66;
    unsigned char unmarshalled_buff[24];
    unsigned long data_size;
    result = unmarshal_bytes(outbuf, outbuf_size, unmarshalled_buff, size);
    printf("\tUnmarhsalling Data: %s\n\n", unmarshalled_buff);

    /* Marshal short */
    unsigned short val_word = 20348;
    printf("\tMarshalling word: %hu\n", val_word);
    result =  marshal_word(id, val_word, outbuf, outbuf_size);

    /* Unmarshal short */
    unsigned short word_result = 0;
    result =  unmarshal_word(word_result, outbuf, outbuf_size);
    printf("\tUnmarshalling word: %hu\n\n", word_result);


    /* Marshal dword */
    unsigned int val_dword = 0x12345678;
    printf("\tMarshalling word: %u\n", val_dword);
    result =  marshal_dword(id, val_dword, outbuf, outbuf_size);

    /* Unmarshal dword */
    unsigned int dword_result = 0;
    result =  unmarshal_dword(dword_result, outbuf, outbuf_size);
    printf("\tUnmarshalling word: %u\n\n", dword_result);


    /* Marshal qword */
    unsigned long long val_qword = 0x1234567812345678;
    printf("\tMarshalling qword: %llu\n", val_qword);
    result =  marshal_qword(id, val_qword, outbuf, outbuf_size);

    /* Unmarshal dword */
    unsigned long long qword_result = 0;
    result =  unmarshal_qword(qword_result, outbuf, outbuf_size);
    printf("\tUnmarshalling word: %llu\n\n", qword_result);

    /* Marshal float */
    float val_float = 99.99;
    printf("\tMarshalling float: %f\n", val_float);
    result =  marshal_float(id, val_float, outbuf, outbuf_size);

    /* Unmarshal dword */
    float float_result = 0;
    result =  unmarshal_float(float_result, outbuf, outbuf_size);
    printf("\tUnmarshalling float: %f\n\n", float_result);

    /* Marshal bool */
    bool val_bool = true;
    printf("\tMarshalling bool: %d\n", val_bool);
    result =  marshal_bool(id, val_float, outbuf, outbuf_size);

    /* Unmarshal bool */
    bool bool_result = 0;
    result =  unmarshal_bool(bool_result, outbuf, outbuf_size);
    printf("\tUnmarshalling bool: %d\n\n", bool_result);
}
#endif
