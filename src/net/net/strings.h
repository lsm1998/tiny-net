#ifndef TINY_NET_STRINGS_H
#define TINY_NET_STRINGS_H

#include <ctype.h>

static inline size_t x_strlen(const char* s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static inline int x_append_char(char* dst, const size_t size, size_t* pos, char c)
{
    if (*pos + 1 >= size) return 0;
    dst[(*pos)++] = c;
    dst[*pos] = '\0';
    return 1;
}

static inline int x_append_dec_u8(char* dst, const size_t size, size_t* pos, uint8_t v)
{
    // write decimal without leading zeros
    char tmp[3];
    int len = 0;

    if (v >= 100)
    {
        tmp[len++] = (char)('0' + (v / 100));
        v %= 100;
        tmp[len++] = (char)('0' + (v / 10));
        tmp[len++] = (char)('0' + (v % 10));
    }
    else if (v >= 10)
    {
        tmp[len++] = (char)('0' + (v / 10));
        tmp[len++] = (char)('0' + (v % 10));
    }
    else
    {
        tmp[len++] = (char)('0' + v);
    }

    for (int i = 0; i < len; i++)
    {
        if (!x_append_char(dst, size, pos, tmp[i])) return 0;
    }
    return 1;
}

static inline int x_append_hex_u16(char* dst, const size_t size, size_t* pos, uint16_t v)
{
    static const char hexd[] = "0123456789abcdef";
    char buf[4];
    int started = 0;

    if (v == 0)
    {
        return x_append_char(dst, size, pos, '0');
    }

    buf[0] = hexd[(v >> 12) & 0xF];
    buf[1] = hexd[(v >> 8) & 0xF];
    buf[2] = hexd[(v >> 4) & 0xF];
    buf[3] = hexd[v & 0xF];

    for (int i = 0; i < 4; i++)
    {
        if (!started && buf[i] == '0') continue;
        started = 1;
        if (!x_append_char(dst, size, pos, buf[i])) return 0;
    }
    return 1;
}

static inline int x_is_ipv4_mapped(const uint8_t a[16])
{
    for (int i = 0; i < 10; i++) if (a[i] != 0) return 0;
    return (a[10] == 0xff && a[11] == 0xff);
}

#endif //TINY_NET_STRINGS_H
