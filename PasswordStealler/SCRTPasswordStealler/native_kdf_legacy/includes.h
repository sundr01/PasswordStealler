// includes.h — заглушка для сборки OpenBSD-кода под MSVC/MinGW
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifndef u_int8_t
typedef uint8_t  u_int8_t;
#endif
#ifndef u_int16_t
typedef uint16_t u_int16_t;
#endif
#ifndef u_int32_t
typedef uint32_t u_int32_t;
#endif

// OpenBSD-атрибуты ? no-op
#ifndef __unused
#define __unused
#endif
#ifndef __dead
#define __dead
#endif
#ifndef __packed
#define __packed
#endif
#ifndef __pure
#define __pure
#endif
#ifndef __bounded
#define __bounded(x)
#endif
#ifndef __bounded__
#define __bounded__(x)
#endif
#ifndef __nonnull
#define __nonnull(x)
#endif
#ifndef __attribute__
#define __attribute__(x)
#endif

// BSD-шные алиасы
#ifndef bzero
#define bzero(b, len) memset((b), 0, (len))
#endif
#ifndef bcopy
#define bcopy(src, dst, len) memmove((dst), (src), (len))
#endif

// безопасное зануление (на всякий)
static void explicit_bzero(void* p, size_t n) {
    volatile unsigned char* vp = (volatile unsigned char*)p;
    while (n--) *vp++ = 0;
}
