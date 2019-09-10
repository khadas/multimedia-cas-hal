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

#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "am_debug.h"
#include "am_cas.h"
#include "am_cas_internal.h"

static void *dl_handle = NULL;
struct AM_CA_Impl_t *cas_ops = NULL;
uint8_t g_cas_loaded = 0;

int loadAllCASLibraries(void)
{
    //TODO: now only load verimatrix CAS
    dl_handle = dlopen("libvmx_dvb.so", RTLD_NOW);
    if (!dl_handle) {
	printf("%s , failed to open lib %s\r\n", __func__, dlerror());
	return -1;
    }

    cas_ops = (struct AM_CA_Impl_t *)dlsym(dl_handle, "cas_ops");
    if (!cas_ops) {
        printf("%s, failed to get cas_ops\r\n", __func__);
        dlclose(dl_handle);
        return -1;
    }

    g_cas_loaded = 1;

    return cas_ops->pre_init();
}

/**\brief Wether the specified system id is supported
 * \param CA_system_id
 * \param[in] CA_system_id The system id of the CA system
 * \retval AM_TRUE or AM_FALSE
 * \return Error code
 */
uint8_t AM_CA_IsSystemIdSupported(int CA_system_id)
{
    if (!g_cas_loaded) {
	loadAllCASLibraries();
    }

    if (cas_ops && cas_ops->isSystemIdSupported) {
	return cas_ops->isSystemIdSupported(CA_system_id);
    }
    return 1;
}

/**\brief Instantiate a CA system of the specified system id
 * \param CA_system_id handle
 * \param[in] CA_system_id The system id of the CA system
 * \param[out] handle Return the handle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Init(int CA_system_id, CasHandle* handle)
{
    int ret = 0;
    CAS_ASSERT(handle);

    if (!g_cas_loaded) {
	ret = loadAllCASLibraries();
	if (ret) {
	    CA_DEBUG(2, "CAS load failed or pre-init failed.");
	    return AM_ERROR_NOT_LOAD;
	}
    }

    if(!AM_CA_IsSystemIdSupported(CA_system_id)) {
	printf("[CAS] %#x not supported\r\n", CA_system_id);
	return AM_ERROR_NOT_SUPPORTED;
    }

    if (cas_ops && cas_ops->init) {
	*handle = (CasHandle)malloc(sizeof(CAS_CasInfo_t));
	return cas_ops->init(*handle);
    }

    return AM_ERROR_SUCCESS;
}

/**\brief Terminate a CA system
 * \param handle
 * \param[in] handle The CasHandle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Term(CasHandle handle)
{
    CAS_ASSERT(handle);

    if (!g_cas_loaded) {
	printf("[CAS] %s failed. Not loaded\r\n", __func__);
	return AM_ERROR_NOT_LOAD;
    }

    free((void *)handle);
    return AM_ERROR_SUCCESS;
}

/**\brief Open a session to descramble one or more streams scrambled by the CAS
 * \param handle session
 * \param[in] handle The handle of specified CA system
 * \param[out] session The newly opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_OpenSession(CasHandle handle, CasSession* session)
{
    CAS_ASSERT(session);

    *session = (CasSession)malloc(sizeof(CAS_SessionInfo_t));
    memset((void *)*session, 0x0, sizeof(CAS_SessionInfo_t));
    ((CAS_SessionInfo_t *)(*session))->cas_handle = (CAS_CasInfo_t *)handle;

    return cas_ops->open_session(handle, *session);
}

/**\brief Close the opened descrambling session
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_CloseSession(CasSession session)
{
    CAS_ASSERT(session);

    if (((CAS_SessionInfo_t *)session)->is_descrambling) {
	if (cas_ops && cas_ops->stop_descrambling) {
	    ((CAS_SessionInfo_t *)session)->is_descrambling = 0;
	    cas_ops->stop_descrambling(session);
	}
    }

    free((void *)session);

    return cas_ops->close_session(session);
}

/**\brief Start descrambling for the specified session of the CA system
 * \param session serviceInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The descrambling parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StartDescrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo)
{
    CAS_ASSERT(session);
    CAS_ASSERT(serviceInfo);

    if (serviceInfo->stream_num > MAX_CHAN_COUNT) {
	printf("[CAS] invalid stream_num[%#x]\r\n", serviceInfo->stream_num);
	return AM_ERROR_OVERFLOW;
    }

    if (!cas_ops || !cas_ops->start_descrambling) {
	printf("[CAS] %s failed. Not loaded\r\n", __func__);
	return AM_ERROR_NOT_LOAD;
    }

    ((CAS_SessionInfo_t *)session)->is_descrambling = 1;
    return cas_ops->start_descrambling(session, serviceInfo);
}

/**\brief Stop descrambling for the specified session of the CA system
 * \param session
 * \param [in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StopDescrambling(CasSession session)
{
    CAS_ASSERT(session);

    if (((CAS_SessionInfo_t *)session)->is_descrambling) {
	if (cas_ops && cas_ops->stop_descrambling) {
	    ((CAS_SessionInfo_t *)session)->is_descrambling = 0;
	    return cas_ops->stop_descrambling(session);
	}
    }

    return AM_ERROR_SUCCESS;
}

/**\brief Update the descrambling pid
 * \param session The opened session
 * \param[in] oldStreamPid The stream pid already set.
 * \param[in] newStreamPid The stream pid to be set.
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_UpdateDescramblingPid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid)
{
    CAS_ASSERT(session);

    if (((CAS_SessionInfo_t *)session)->is_descrambling) {
	if (cas_ops && cas_ops->update_descrambling_pid) {
	    return cas_ops->update_descrambling_pid(session, oldStreamPid, newStreamPid);
	}
    }

    return AM_ERROR_GENERAL_ERORR;
}

/**\brief Set EMM Pid for the specified CA system
 * \param handle emmPid
 * \param[in] handle The handle of initialized CA system
 * \param[in] emmPid The emmPid of current ts
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_SetEmmPid(CasHandle handle, uint16_t emmPid)
{
    CAS_ASSERT(handle);

    if (cas_ops && cas_ops->set_emm_pid) {
	return cas_ops->set_emm_pid(handle, emmPid);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Start DVR for the specified session of the CA system
 * \param session serviceInfo privateInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The service information for recording
 * \param[in] privateInfo The private data for extended use
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStart(CasSession session, AM_CA_ServiceInfo_t *serviceInfo, AM_CA_PrivateInfo_t *privateInfo)
{
    CAS_ASSERT(session);
    CAS_ASSERT(serviceInfo);

    if (cas_ops && cas_ops->dvr_start) {
	return cas_ops->dvr_start(session, serviceInfo, privateInfo);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Stop DVR for the specified session of the CA system
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStop(CasSession session)
{
    CAS_ASSERT(session);

    if (cas_ops && cas_ops->dvr_stop) {
	return cas_ops->dvr_stop(session);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Encrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param session cryptoPara storeInfo
 * \param[in] session The opened session
 * \param[in] cryptoPara The encrypt parameters
 * \param[out] storeInfo The returned decrypto key information
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVREncrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara, AM_CA_StoreInfo_t *storeInfo)
{
    CAS_ASSERT(session);
    CAS_ASSERT(cryptoPara);

    if (cas_ops && cas_ops->dvr_encrypt) {
	return cas_ops->dvr_encrypt(session, cryptoPara, storeInfo);
    }

    return AM_ERROR_NOT_LOAD;
}
/**\brief Decrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param session cryptoPara
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRDecrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    CAS_ASSERT(session);
    CAS_ASSERT(cryptoPara);

    if (cas_ops && cas_ops->dvr_decrypt) {
	return cas_ops->dvr_decrypt(session, cryptoPara);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Play recorded streams
 * \param session storeInfo privateInfo
 * \param[in] session The opened session
 * \param[in] storeInfo The decrypto key information
 * \param[in] privateInfo The private data for extended use
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRReplay(CasSession session, AM_CA_StoreInfo_t *storeInfo, AM_CA_PrivateInfo_t *privateInfo)
{
    CAS_ASSERT(session);

    if (cas_ops && cas_ops->dvr_replay) {
	return cas_ops->dvr_replay(session, storeInfo, privateInfo);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Stop DVR replay
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStopReplay(CasSession session)
{
    CAS_ASSERT(session);

    if (cas_ops && cas_ops->dvr_stop_replay) {
	return cas_ops->dvr_stop_replay(session);
    }

    return AM_ERROR_NOT_LOAD;
}

AM_RESULT AM_CA_GetSecureBuffer(uint8_t **buf, uint32_t len) {
    if (cas_ops && cas_ops->get_securebuf) {
	return cas_ops->get_securebuf(buf, len);
    }

    return AM_ERROR_NOT_LOAD;
}
