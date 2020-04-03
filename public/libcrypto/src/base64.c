#include <stdlib.h>
#include "base64.h"
//EnCode Table
static const unsigned char g_base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

#define END_CHAR '='

//Decode Table
static unsigned char g_decode_base64_talbe[256]= {
    0x41, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0x40, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#define MAKE_DWORD(b1,b2,b3,b4)  ( ((((unsigned int)(b1))<<24) & 0xff000000) | ((((unsigned int)(b2))<<16) & 0x00ff0000) | ((((unsigned int)(b3))<<8) & 0x0000ff00) | ((((unsigned int)(b4))) & 0x000000ff) )

static unsigned int T24_32BIT(unsigned char B0, unsigned char B1, unsigned char B2)
{
    unsigned char Val[4] = { 0 } ;

    Val[0] = ( B0 >> 2 ) ;

    Val[1] = ((B0 & 0x03) << 4) | (B1 >> 4) ;

    Val[2] = ((B1 & 0x0F) << 2) | (B2 >> 6) ;

    Val[3] = (B2 & 0x3F ) ;

    return MAKE_DWORD(Val[3],Val[2],Val[1],Val[0]);
}

static unsigned int T32_24BIT(unsigned char Val_0, unsigned char Val_1, unsigned char Val_2, unsigned char Val_3)
{
    unsigned char LowVal[3] = { 0 } ;

    LowVal[0] = ((Val_0 & 0x3F) << 2) | ((Val_1 & 0x30) >> 4) ;

    LowVal[1] = ((Val_1 & 0x0F) << 4) | ((Val_2 & 0x3C) >> 2) ;

    LowVal[2] = ((Val_2 & 0x03) << 6) | (Val_3 & 0x3F) ;

    return MAKE_DWORD(0, LowVal[2], LowVal[1], LowVal[0]);
}

int base64_encode (
    char  *in_buf,
    int   in_buf_len,
    char  *out_buf,
    int   out_buf_max_len,
    int   *out_buf_len
)
{
    unsigned char digit[4] = {0};
    int reminder = 0;
    int count = 0;
    int cur_in = 0;
	int cur_out = 0;
    int final_len = 0;

    if (0 == in_buf_len)
    {
        *out_buf_len = 0;
        return BASE64_ENCODE_SUCCEEDED;
    }

    reminder = in_buf_len % 3;        //取余
    count = in_buf_len - reminder;    //取整

    if (reminder > 0)
        final_len = count / 3 * 4 + 4;
    else
        final_len = count / 3 * 4;

    if (NULL == out_buf)
    {
        *out_buf_len = final_len;
        return BASE64_ENCODE_SUCCEEDED;
    }

    if (out_buf_max_len < final_len)
        return BASE64_OUTBUF_SIZE_TOO_SMALL; 

    cur_out = 0;

    for (cur_in = 0; cur_in < count; cur_in += 3)
    {
        *(unsigned int*)(&digit[0]) = T24_32BIT((unsigned char)in_buf[cur_in + 0], (unsigned char)in_buf[cur_in + 1], (unsigned char)in_buf[cur_in + 2]);

        out_buf[cur_out++] = g_base64_alphabet[digit[0]];
        out_buf[cur_out++] = g_base64_alphabet[digit[1]];
        out_buf[cur_out++] = g_base64_alphabet[digit[2]];
        out_buf[cur_out++] = g_base64_alphabet[digit[3]];
    }

    switch(reminder)
    {
        case 0:
            out_buf[cur_out] = 0;
            break;
        case 1:
            *(unsigned int*)(&digit[0]) = T24_32BIT(in_buf[cur_in + 0], 0, 0);
            out_buf[cur_out++] = g_base64_alphabet[digit[0]];
            out_buf[cur_out++] = g_base64_alphabet[digit[1]];
			out_buf[cur_out++] = END_CHAR;
			out_buf[cur_out++] = END_CHAR;
            out_buf[cur_out]   = 0;
            break;
        case 2:
            *(int*)(&digit[0]) = T24_32BIT(in_buf[cur_in + 0], in_buf[cur_in + 1], 0);
            out_buf[cur_out++] = g_base64_alphabet[digit[0]];
            out_buf[cur_out++] = g_base64_alphabet[digit[1]];
            out_buf[cur_out++] = g_base64_alphabet[digit[2]];
            out_buf[cur_out++] = END_CHAR;
            out_buf[cur_out]   = 0;
            break;
        default:
            return BASE64_GENERAL_ERROR;
            break;
    }

    if (NULL != out_buf_len)
        *out_buf_len = cur_out;

    return BASE64_ENCODE_SUCCEEDED;
} // base64_encode

int base64_decode (
    char  *in_buf,
    int   in_buf_len,
    char  *out_buf,
    int   out_buf_max_len,
    int   *out_buf_len
)
{
	unsigned char digit[4] = {0};
    int cur_in = 0;
    int cur_out = 0;
    int count_tail = 0;
    int final_len = 0;
	int i = 0;

    if (0 == in_buf_len)
    {
        *out_buf_len = 0;
        return BASE64_DECODE_SUCCEEDED;
    }

    if (NULL == in_buf)
        return BASE64_DECODE_STRING_NONE;
    if (0 != in_buf_len % 4)
        return BASE64_DECODE_STR_LENERR;
    // 通过最后 4 字节，计算解码后的长度
    count_tail = 0;
    for (i = 0; i < 2; i++)
        if (END_CHAR == in_buf[in_buf_len - 1 - i])
            count_tail++;

    final_len = in_buf_len / 4 * 3 - count_tail;

    if (NULL == out_buf)
    {
        *out_buf_len = final_len; 
        return BASE64_DECODE_SUCCEEDED;
    }

    if (out_buf_max_len < final_len)
        return BASE64_OUTBUF_SIZE_TOO_SMALL;

    // 前 N－4 个字节
	cur_out = 0;
    for (cur_in = 0; cur_in < in_buf_len - 4; cur_in += 4)
    {
        *(unsigned int*)(&digit[0]) = T32_24BIT(
                        g_decode_base64_talbe[in_buf[cur_in + 0]],
                        g_decode_base64_talbe[in_buf[cur_in + 1]],
                        g_decode_base64_talbe[in_buf[cur_in + 2]],
                        g_decode_base64_talbe[in_buf[cur_in + 3]]
                        );
        out_buf[cur_out + 0] = digit[0];        
        out_buf[cur_out + 1] = digit[1];
        out_buf[cur_out + 2] = digit[2]; 
        cur_out += 3;
    }

    *(unsigned int*)(&digit[0]) = T32_24BIT( g_decode_base64_talbe[in_buf[in_buf_len - 4]],
                    g_decode_base64_talbe[in_buf[in_buf_len - 3]],
                    g_decode_base64_talbe[in_buf[in_buf_len - 2]],
                    g_decode_base64_talbe[in_buf[in_buf_len - 1]]
                    );

    for (i = 0; i < 3 - count_tail; i++)
        out_buf[cur_out++] = digit[i];

    if (NULL != out_buf_len)
        *out_buf_len = cur_out;

    return BASE64_DECODE_SUCCEEDED;
}
