/**********************************************************\
|                                                          |
| php_xxtea.c                                              |
|                                                          |
| XXTEA for pecl source file.                              |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Author:  Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Feb 7, 2016                                |
|                                                          |
\**********************************************************/

#include "php_xxtea.h"
#include "ext/standard/info.h" /* for phpinfo() functions */

#if defined(_MSC_VER)
#include "win32/php_stdint.h"
#elif defined(__FreeBSD__) && __FreeBSD__ < 5
/* FreeBSD 4 doesn't have stdint.h file */
#include <inttypes.h>
#else
#include <stdint.h>
#endif

#include <sys/types.h> /* This will likely define BYTE_ORDER */

#ifndef BYTE_ORDER
#if (BSD >= 199103)
# include <machine/endian.h>
#else
#if defined(linux) || defined(__linux__)
# include <endian.h>
#else
#define LITTLE_ENDIAN   1234    /* least-significant byte first (vax, pc) */
#define BIG_ENDIAN  4321    /* most-significant byte first (IBM, net) */
#define PDP_ENDIAN  3412    /* LSB first in word, MSW first in long (pdp)*/

#if defined(__i386__) || defined(__x86_64__) || defined(__amd64__) || \
   defined(vax) || defined(ns32000) || defined(sun386) || \
   defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
   defined(__alpha__) || defined(__alpha)
#define BYTE_ORDER    LITTLE_ENDIAN
#endif

#if defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || \
    defined (BIT_ZERO_ON_LEFT) || defined(m68k) || defined(__sparc)
#define BYTE_ORDER  BIG_ENDIAN
#endif
#endif /* linux */
#endif /* BSD */
#endif /* BYTE_ORDER */

#ifndef BYTE_ORDER
#ifdef __BYTE_ORDER
#if defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#endif
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif
#endif
#endif

#if PHP_MAJOR_VERSION < 7
typedef int length_t;
#define __RETURN_STRINGL(s, l) RETURN_STRINGL(s, l, 0)
#define __add_assoc_string(arg, key, str) add_assoc_string(arg, key, str, 1)
#else
typedef size_t length_t;
#define __RETURN_STRINGL(s, l) RETVAL_STRINGL(s, l); efree(s); return;
#define __add_assoc_string(arg, key, str) add_assoc_string(arg, key, str)
#endif

#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
#define DELTA 0x9e3779b9

static uint32_t * xxtea_to_uint_array(const uint8_t * data, size_t len, int inc_len, size_t * out_len) {
    uint32_t *out;
#if !(defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
    size_t i;
#endif
    size_t n;

    n = (((len & 3) == 0) ? (len >> 2) : ((len >> 2) + 1));

    if (inc_len) {
        out = ecalloc(n + 1, sizeof(uint32_t));
        out[n] = (uint32_t)len;
        *out_len = n + 1;
    }
    else {
        out = ecalloc(n, sizeof(uint32_t));
        *out_len = n;
    }
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(out, data, len);
#else
    for (i = 0; i < len; ++i) {
        out[i >> 2] |= (uint32_t)data[i] << ((i & 3) << 3);
    }
#endif

    return out;
}

static uint8_t * xxtea_to_ubyte_array(const uint32_t * data, size_t len, int inc_len, size_t * out_len) {
    uint8_t *out;
#if !(defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
    size_t i;
#endif
    size_t m, n;

    n = len << 2;

    if (inc_len) {
        m = data[len - 1];
        n -= 4;
        if ((m < n - 3) || (m > n)) return NULL;
        n = m;
    }

    out = (uint8_t *)emalloc(n + 1);

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(out, data, n);
#else
    for (i = 0; i < n; ++i) {
        out[i] = (uint8_t)(data[i >> 2] >> ((i & 3) << 3));
    }
#endif

    out[n] = '\0';
    *out_len = n;

    return out;
}

static uint32_t * xxtea_uint_encrypt(uint32_t * data, size_t len, uint32_t * key) {
    uint32_t n = (uint32_t)len - 1;
    uint32_t z = data[n], y, p, q = 6 + 52 / (n + 1), sum = 0, e;

    if (n < 1) return data;

    while (0 < q--) {
        sum += DELTA;
        e = sum >> 2 & 3;

        for (p = 0; p < n; p++) {
            y = data[p + 1];
            z = data[p] += MX;
        }

        y = data[0];
        z = data[n] += MX;
    }

    return data;
}

static uint32_t * xxtea_uint_decrypt(uint32_t * data, size_t len, uint32_t * key) {
    uint32_t n = (uint32_t)len - 1;
    uint32_t z, y = data[0], p, q = 6 + 52 / (n + 1), sum = q * DELTA, e;

    if (n < 1) return data;

    while (sum != 0) {
        e = sum >> 2 & 3;

        for (p = n; p > 0; p--) {
            z = data[p - 1];
            y = data[p] -= MX;
        }

        z = data[n];
        y = data[0] -= MX;
        sum -= DELTA;
    }

    return data;
}

static uint8_t * xxtea_ubyte_encrypt(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len) {
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;

    if (!len) return NULL;

    data_array = xxtea_to_uint_array(data, len, 1, &data_len);
    key_array  = xxtea_to_uint_array(key, 16, 0, &key_len);
    out = xxtea_to_ubyte_array(xxtea_uint_encrypt(data_array, data_len, key_array), data_len, 0, out_len);

    efree(data_array);
    efree(key_array);

    return out;
}

static uint8_t * xxtea_ubyte_decrypt(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len) {
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;

    if (!len) return NULL;

    data_array = xxtea_to_uint_array(data, len, 0, &data_len);
    key_array  = xxtea_to_uint_array(key, 16, 0, &key_len);
    out = xxtea_to_ubyte_array(xxtea_uint_decrypt(data_array, data_len, key_array), data_len, 1, out_len);

    efree(data_array);
    efree(key_array);

    return out;
}

void tinyEncrypt ( const uint32 * plain, const uint32 * key, uint32 *crypt, unsigned int power)
{
    uint32 y,z,a,b,c,d;
    uint32 sum = 0;
    unsigned int i;
    unsigned int rounds = 1<<power;

    y = plain[0];
    z = plain[1];
    a = key[0];
    b = key[1];
    c = key[2];
    d = key[3];

    for (i = 0; i < rounds; i++) {
        sum += TEA_DELTA;
        y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
    }

    crypt[0] = y;
    crypt[1] = z;
}

void tinyDecrypt ( const unsigned int * crypt, const unsigned int * key, unsigned int *plain, unsigned int power)
{
    unsigned int y,z,a,b,c,d;
    unsigned int rounds = 1<<power;
    unsigned int sum = TEA_DELTA<<power;
    unsigned int i;

    y = crypt[0];
    z = crypt[1];
    a = key[0];
    b = key[1];
    c = key[2];
    d = key[3];

    for (i = 0; i < rounds; i++) {
        z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
        y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        sum -= TEA_DELTA;
    }

    plain[0] = y;
    plain[1] = z;
}

char * xTEADecryptWithKey(const char *crypt, uint32 crypt_len, const unsigned char key[16], uint32 * plain_len)
{
    if(crypt == NULL || plain == NULL)
        return NULL;
    const uint32 *tkey   = (const uint32 *)key;
    const uint32 *tcrypt = (const uint32 *)crypt;

    if( crypt_len<1 || crypt_len%8 )
        return NULL;

    int *tplain = (int * )emalloc(crypt_len/4+1);

    uint32  length = crypt_len;
    uint32 pre_plain[2] = {0,0};
    uint32 p_buf[2] = {0};
    uint32 c_buf[2] = {0};

    int padLength = 0;
    int i = 0;

    tinyDecrypt(tcrypt, tkey, p_buf, 4);

    memcpy(pre_plain, p_buf, 8);
    memcpy(tplain, p_buf, 8);

    for (i = 2; i < (int)length/4; i+=2) {
        c_buf[0] = *(tcrypt+i) ^ pre_plain[0];
        c_buf[1] = *(tcrypt+i+1) ^ pre_plain[1];
        tinyDecrypt((const uint32 *)c_buf, tkey, p_buf, 4);
        memcpy(pre_plain, p_buf, 8);
        *(tplain+i) = p_buf[0] ^ *(tcrypt+i-2);
        *(tplain+i+1) = p_buf[1] ^ *(tcrypt+i-1);
    }

    if ( tplain[length/4-1] || (tplain[length/4-2]&0xffffff00))
    {
        efree(tplain); tplain = NULL;
        return NULL;
    }

    padLength = *((unsigned char *)tplain) & 0x07;

    length = (length / 4 + 1)*4 - (padLength+3);    
    memcpy(tplain,(byte*)tplain+padLength+3,length);

    *plain_len = crypt_len - (padLength+3) -7;/*(pad 7 bytes 0x00 at the end)*/

    /*memcpy(plain,tplain,*plain_len);


    efree(tplain); tplain = NULL;
    */
    return tplain;

}
/*================================================================
 *
 * 函 数 名：xTEAEncryptWithKey
 ** Encrypt the plain text to cipher text with the key

 * 参 数：
 *
 * const unsigned long *plain [IN] : the plain text
 * DWORD dwPlainLen[IN]: plain text length
 * const unsigned long *theKey [IN] : the key
 * DWORD dwKeyLen[IN]: key length
 * unsigned long *crypt [[IN,OUT]] : the pointer to cipher text(net order byte)
 * DWORD * pdwCryptLen[IN,OUT]: Valid cipher text length
 *
 * 返 回 值：BOOL-	SUCCESS:TRUE
 *							Fail:NULL
 *
 *
 ================================================================*/

char * xTEAEncryptWithKey(const char *plain, uint32 plain_len, const unsigned char key[16], uint32 * crypt_len )
{
    if(plain == NULL || crypt == NULL)
        return NULL;
    const unsigned char pad[9] = {0xad,0xad,0xad,0xad,0xad,0xad,0xad,0xad,0xad};

    uint32 *tkey = (uint32 *)key;
    uint32 *tplain = (uint32 *)plain;

    if ( plain_len<1 )
    {
        return NULL;
    }

    uint32 pre_plain[2] = {0,0};
    uint32 pre_crypt[2] = {0,0};
    uint32 p_buf[2] = {0};
    uint32 c_buf[2] = {0};

    int padLength = 0;
    int i = 0;

    /* padding data */
    padLength = (plain_len+10)%8;
    padLength = padLength ? 8 - padLength : 0;

    int length = padLength+3+plain_len+7;
    *crypt_len = length;

    int *tcrypt = (int*)emalloc(length/4);

    *((unsigned char*)tcrypt) = 0xa8 | (unsigned char)padLength;
    memcpy ( (byte*)tcrypt+1, (byte*)pad, padLength+2);
    memcpy ( (byte*)tcrypt+padLength+3, (byte*)tplain, plain_len);
    memset ( (byte*)tcrypt+padLength+3+plain_len, 0, 7);

    for (i = 0; i < length/4; i+=2) {
        p_buf[0] = *(tcrypt+i) ^ pre_crypt[0];
        p_buf[1] = *(tcrypt+i+1) ^ pre_crypt[1];
        tinyEncrypt( p_buf, tkey, c_buf, 4);
        *(tcrypt+i) = c_buf[0] ^ pre_plain[0];
        *(tcrypt+i+1) = c_buf[1] ^ pre_plain[1];
        memcpy(pre_crypt, tcrypt+i, 8);
        memcpy(pre_plain, p_buf, 8);
    }

    return tcrypt;

}



ZEND_BEGIN_ARG_INFO_EX(ht_xxtea_encrypt_arginfo, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(ht_xxtea_decrypt_arginfo, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(xxtea_encrypt_arginfo, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(xxtea_decrypt_arginfo, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(xxtea_info_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

#ifndef ZEND_FE_END
#define ZEND_FE_END            { NULL, NULL, NULL }
#endif

/* compiled function list so Zend knows what's in this module */
zend_function_entry xxtea_functions[] = {
    ZEND_FE(ht_xxtea_encrypt, ht_xxtea_encrypt_arginfo)
    ZEND_FE(ht_xxtea_decrypt, ht_xxtea_decrypt_arginfo)
    ZEND_FE(xxtea_encrypt, xxtea_encrypt_arginfo)
    ZEND_FE(xxtea_decrypt, xxtea_decrypt_arginfo)
    ZEND_FE(xxtea_info, xxtea_info_arginfo)
    ZEND_FE_END
};

/* compiled module information */
zend_module_entry xxtea_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_XXTEA_MODULE_NAME,
    xxtea_functions,
    ZEND_MINIT(xxtea),
    ZEND_MSHUTDOWN(xxtea),
    NULL,
    NULL,
    ZEND_MINFO(xxtea),
    PHP_XXTEA_VERSION,
    STANDARD_MODULE_PROPERTIES
};

/* implement standard "stub" routine to introduce ourselves to Zend */
#if defined(COMPILE_DL_XXTEA)
ZEND_GET_MODULE(xxtea)
#endif



/* {{{ proto string ht_xxtea_encrypt(string data, string key)
   Encrypt string using XXTEA algorithm */
ZEND_FUNCTION(ht_xxtea_encrypt) {
    char *data, *key;
    char *result;
    length_t data_len, key_len;
    size_t i, ret_length;
    uint8_t fixed_key[16];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &data, &data_len, &key, &key_len) == FAILURE) {
        return;
    }
    if (data_len == 0) {
        RETURN_EMPTY_STRING();
    }

    if (key_len < 16) {
        memcpy(fixed_key, key, key_len);
        for (i = key_len; i < 16; ++i) fixed_key[i] = 0;
    }
    else if (key_len >= 16) {
        memcpy(fixed_key, key, 16);
    }
    /*
      char * xTEAEncryptWithKey(const char *plain, uint32 plain_len, const unsigned char key[16], uint32 * crypt_len )
    */
    result = (char *)xTEAEncryptWithKey((const uint8_t *)data, (uint32)data_len, fixed_key, &ret_length);
    if (result == NULL) {
        RETURN_FALSE;
    }
    __RETURN_STRINGL(result, ret_length);
}


/* {{{ proto string xxtea_encrypt(string data, string key)
   Encrypt string using XXTEA algorithm */
ZEND_FUNCTION(xxtea_encrypt) {
    char *data, *key;
    char *result;
    length_t data_len, key_len;
    size_t i, ret_length;
    uint8_t fixed_key[16];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &data, &data_len, &key, &key_len) == FAILURE) {
        return;
    }

    if (data_len == 0) {
        RETURN_EMPTY_STRING();
    }

    if (key_len < 16) {
        memcpy(fixed_key, key, key_len);
        for (i = key_len; i < 16; ++i) fixed_key[i] = 0;
    }
    else if (key_len >= 16) {
        memcpy(fixed_key, key, 16);
    }

    result = (char *)xxtea_ubyte_encrypt((const uint8_t *)data, (size_t)data_len, fixed_key, &ret_length);
    if (result == NULL) {
        RETURN_FALSE;
    }
    __RETURN_STRINGL(result, ret_length);
}
/* }}} */

/* {{{ proto string ht_xxtea_decrypt(string data, string key)
   Decrypt string using XXTEA algorithm */
ZEND_FUNCTION(ht_xxtea_decrypt) {
    char *data, *key;
    char *result;
    length_t data_len, key_len;
    size_t i, ret_length;
    uint8_t fixed_key[16];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &data, &data_len, &key, &key_len) == FAILURE) {
        return;
    }
    if (data_len == 0) {
        RETURN_EMPTY_STRING();
    }
    if (key_len < 16) {
        memcpy(fixed_key, key, key_len);
        for (i = key_len; i < 16; ++i) fixed_key[i] = 0;
    }
    else if (key_len >= 16) {
        memcpy(fixed_key, key, 16);
    }
    /*

    char * xTEADecryptWithKey(const char *crypt, uint32 crypt_len, const unsigned char key[16], uint32 * plain_len)

    */
    result = (char *)xTEADecryptWithKey((const uint8_t *)data, (size_t)data_len, fixed_key, &ret_length);
    if (result == NULL) {
        RETURN_FALSE;
    }
    __RETURN_STRINGL(result, ret_length);
}
/* }}} */

/* {{{ proto string xxtea_decrypt(string data, string key)
   Decrypt string using XXTEA algorithm */
ZEND_FUNCTION(xxtea_decrypt) {
    char *data, *key;
    char *result;
    length_t data_len, key_len;
    size_t i, ret_length;
    uint8_t fixed_key[16];

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &data, &data_len, &key, &key_len) == FAILURE) {
        return;
    }
    if (data_len == 0) {
        RETURN_EMPTY_STRING();
    }
    if (key_len < 16) {
        memcpy(fixed_key, key, key_len);
        for (i = key_len; i < 16; ++i) fixed_key[i] = 0;
    }
    else if (key_len >= 16) {
        memcpy(fixed_key, key, 16);
    }
    result = (char *)xxtea_ubyte_decrypt((const uint8_t *)data, (size_t)data_len, fixed_key, &ret_length);
    if (result == NULL) {
        RETURN_FALSE;
    }
    __RETURN_STRINGL(result, ret_length);
}
/* }}} */

zend_class_entry *xxtea_ce;

static zend_function_entry xxtea_method[] = {
    ZEND_ME_MAPPING(encrypt, ht_xxtea_encrypt, ht_xxtea_encrypt_arginfo, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    ZEND_ME_MAPPING(decrypt, ht_xxtea_decrypt, ht_xxtea_decrypt_arginfo, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    ZEND_ME_MAPPING(encrypt, xxtea_encrypt, xxtea_encrypt_arginfo, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    ZEND_ME_MAPPING(decrypt, xxtea_decrypt, xxtea_decrypt_arginfo, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    ZEND_FE_END
};

ZEND_MINIT_FUNCTION(xxtea) {
    zend_class_entry ce;
    INIT_CLASS_ENTRY(ce, "XXTEA", xxtea_method);
    xxtea_ce = zend_register_internal_class(&ce TSRMLS_CC);
    return SUCCESS;
}

ZEND_MSHUTDOWN_FUNCTION(xxtea) {
    return SUCCESS;
}

ZEND_MINFO_FUNCTION(xxtea) {
    php_info_print_table_start();
    php_info_print_table_row(2, "xxtea support", "enabled");
    php_info_print_table_row(2, "xxtea version", PHP_XXTEA_VERSION);
    php_info_print_table_row(2, "xxtea author", PHP_XXTEA_AUTHOR);
    php_info_print_table_row(2, "xxtea homepage", PHP_XXTEA_HOMEPAGE);
    php_info_print_table_end();
}

ZEND_FUNCTION(xxtea_info) {
    array_init(return_value);
    __add_assoc_string(return_value, "ext_version", PHP_XXTEA_VERSION);
    __add_assoc_string(return_value, "ext_build_date", PHP_XXTEA_BUILD_DATE);
    __add_assoc_string(return_value, "ext_author", PHP_XXTEA_AUTHOR);
}
