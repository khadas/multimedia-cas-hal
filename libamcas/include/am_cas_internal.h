/*
 * Copyright (C) 2017 Amlogic, Inc. All rights reserved.
 *
 * All information contained herein is Amlogic confidential.
 *
 * This software is provided to you pursuant to Software License
 * Agreement (SLA) with Amlogic Inc ("Amlogic"). This software may be
 * used only in accordance with the terms of this agreement.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification is strictly prohibited without prior written permission
 * from Amlogic.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _AM_CAS_INTERNAL_H
#define _AM_CAS_INTERNAL_H

typedef struct {
   void *private_data;
}CAS_CasInfo_t;

typedef struct {
    CAS_CasInfo_t *cas_handle;
    AM_CA_ServiceInfo_t service_info;
    uint16_t is_descrambling;
    void *private_data;
}CAS_SessionInfo_t;

typedef enum {
    SCRAMBLE_ALGO_CSA,
    SCRAMBLE_ALGO_AES,
    SCRAMBLE_ALGO_INVALID,
    SCRAMBLE_ALGO_NONE
} SCRAMBLE_ALGO_t;

typedef enum {
    SCRAMBLE_MODE_ECB,
    SCRAMBLE_MODE_CBC,
    SCRAMBLE_MODE_INVALID
} SCRAMBLE_MODE_t;

typedef enum {
    SCRAMBLE_ALIGNMENT_LEFT,
    SCRAMBLE_ALIGNMENT_RIGHT,
    SCRAMBLE_ALIGNMENT_INVALID
} SCRAMBLE_ALIGNMENT_t;

struct AM_CA_Impl_t
{
    int (*pre_init)(void);
    int (*init)(CasHandle handle);
    int (*term)(CasHandle handle);
    int (*isSystemIdSupported)(int CA_system_id);
    int (*open_session)(CasHandle handle, CasSession session);
    int (*close_session)(CasSession session);
    int (*start_descrambling)(CasSession session, AM_CA_ServiceInfo_t *service_info);
    int (*update_descrambling_pid)(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);
    int (*stop_descrambling)(CasSession session);
    int (*set_emm_pid)(CasHandle handle, uint16_t emmPid);
    int (*dvr_start)(CasSession session, AM_CA_ServiceInfo_t *service_info);
    int (*dvr_stop)(CasSession session);
    int (*dvr_encrypt)(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
    int (*dvr_decrypt)(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
    int (*dvr_replay)(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
    int (*dvr_stop_replay)(CasSession session);
    int (*get_securebuf)(uint8_t **buf, uint32_t len);
};

#endif
