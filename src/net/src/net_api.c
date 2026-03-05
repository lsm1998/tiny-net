#include "net_api.h"
#include "strings.h"

char* x_inet_ntoa(const struct in_addr in)
{
    static char ip_buf[INET_ADDRSTRLEN];
    if (x_inet_ntop(AF_INET, in.addr_array, ip_buf, sizeof(ip_buf)) == NULL)
    {
        return NULL;
    }
    return ip_buf;
}

uint32_t x_inet_addr(const char* cp)
{
    if (cp == NULL)
    {
        return 0;
    }
    uint32_t addr = 0;
    uint32_t val = 0;
    int dots = 0;
    while (*cp)
    {
        if (isdigit((unsigned char)*cp))
        {
            val = val * 10 + (*cp - '0');
            if (val > 255)
                return INADDR_NONE;
        }
        else if (*cp == '.')
        {
            if (++dots > 3)
                return INADDR_NONE;

            addr = (addr << 8) | val;
            val = 0;
        }
        else
        {
            return INADDR_NONE;
        }
        cp++;
    }
    if (dots != 3)
    {
        return INADDR_NONE;
    }

    addr = (addr << 8) | val;

    return x_htonl(addr);
}

int x_inet_pton(const int family, const char* src, void* dst)
{
    if (family == AF_INET)
    {
        uint32_t addr = x_inet_addr(src);
        if (addr == INADDR_NONE)
        {
            errno = EINVAL;
            return -1;
        }
        *(uint32_t*)dst = addr;
        return 1;
    }
    return 0;
}

const char* x_inet_ntop(const int family, const void* src, char* dst, const size_t size)
{
    if (!src || !dst || size == 0)
    {
        errno = EINVAL;
        return NULL;
    }

    dst[0] = '\0';

    if (family == AF_INET)
    {
        if (size < INET_ADDRSTRLEN)
        {
            errno = ENOSPC;
            return NULL;
        }

        const uint8_t* b = (const uint8_t*)src;
        size_t pos = 0;

        if (!x_append_dec_u8(dst, size, &pos, b[0]))
        {
            errno = ENOSPC;
            return NULL;
        }
        if (!x_append_char(dst, size, &pos, '.'))
        {
            errno = ENOSPC;
            return NULL;
        }
        if (!x_append_dec_u8(dst, size, &pos, b[1]))
        {
            errno = ENOSPC;
            return NULL;
        }
        if (!x_append_char(dst, size, &pos, '.'))
        {
            errno = ENOSPC;
            return NULL;
        }
        if (!x_append_dec_u8(dst, size, &pos, b[2]))
        {
            errno = ENOSPC;
            return NULL;
        }
        if (!x_append_char(dst, size, &pos, '.'))
        {
            errno = ENOSPC;
            return NULL;
        }
        if (!x_append_dec_u8(dst, size, &pos, b[3]))
        {
            errno = ENOSPC;
            return NULL;
        }

        return dst;
    }

    // 目前仅支持IPv4
    return NULL;
}
