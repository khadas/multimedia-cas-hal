/*
 * Copyright (C) 2015 Amlogic, Inc.
 *
 *
 */
#ifndef CACRYPTO_H
#define CACRYPTO_H

typedef enum Algo {
    AES_128_ECB_ENCRYPT = 0,
    AES_128_ECB_DECRYPT = 1,
    T_DES_ECB = 2,
    AES_128_ECB,
    AES_128_CBC,
    AES_128_CTR,
    T_DES_CBC,
    DVB_CSA1,
    DVB_CSA2,
    DVB_CSA3,
    AES_128_ECB_TS_CLRTAIL,
    AES_128_CBC_TS_CLRTAIL,
    AES_128_ECB_TS_CLRHEAD,
    AES_128_CBC_TS_CLRHEAD,
    CLEAR,
    MAX = CLEAR
} Algo;

#define MAX_R2R_ENGINES 8

#endif // CACRYPTO_H
