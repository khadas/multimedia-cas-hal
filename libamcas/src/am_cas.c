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
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "am_cas.h"
#include "am_cas_internal.h"

static void *dl_handle = NULL;
struct AM_CA_Impl_t *cas_ops = NULL;
uint8_t g_cas_loaded = 0;
int loadCASLibrary(void)
{
    DIR *dir = NULL;
    struct dirent *dp = NULL;
    char *path[]={"/product/lib", "/vendor/lib", "/usr/lib"};
    int i;

    for (i = 0; i < sizeof(path)/sizeof(path[0]); i++) {
	if (!(dir = opendir(path[i]))) {
		continue;
	}

	while ((dp = readdir(dir))) {
		const char *pfile = strrchr(dp->d_name, '_');
		if (pfile && (!strcmp(pfile, "_dvb.so"))) {
			CA_DEBUG(0, "CAS plugin %s\/%s found", path[i], dp->d_name);
		} else {
			continue;
		}
		if (!(dl_handle = dlopen(dp->d_name, RTLD_NOW | RTLD_GLOBAL))) {
			CA_DEBUG(0, "dlopen %s failed, %s", dp->d_name,
				 strerror(errno));
			CA_DEBUG(0, "dlerror %s", dlerror());
			continue;
		}
		if (!(cas_ops = (struct AM_CA_Impl_t *)dlsym(dl_handle,
		      "cas_ops"))) {
			CA_DEBUG(0, "dlsym failed, %s", strerror(errno));
			dlclose(dl_handle);
			continue;
		}

		if (strcmp(cas_ops->get_version(), CAS_HAL_VER)) {
			CA_DEBUG(1, "%s cas library[%s] and cas hal[%s] not matched",
				 cas_ops->get_version(), CAS_HAL_VER);
			dlclose(dl_handle);
			continue;
		}

		g_cas_loaded = 1;
		closedir(dir);
		return cas_ops->pre_init();
        }

	closedir(dir);
    }

    return -1;
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
        loadCASLibrary();
    }

    if (cas_ops && cas_ops->isSystemIdSupported) {
        return cas_ops->isSystemIdSupported(CA_system_id);
    }

    return 0;
}

/**\brief Instantiate CA system
 * \param[out] handle Return the handle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Init(CasHandle* handle)
{
    int ret = 0;
    CAS_ASSERT(handle);

    if (g_cas_loaded) {
        CA_DEBUG(2, "CAS loaded already, return");
        return AM_ERROR_SUCCESS;
    }

    ret = loadCASLibrary();
    if (ret) {
        CA_DEBUG(2, "CAS load failed or pre-init failed.");
        *handle = (CasHandle)NULL;
        return AM_ERROR_NOT_LOAD;
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
AM_RESULT AM_CA_OpenSession(CasHandle handle, CasSession* session, CA_SERVICE_TYPE_t service_type)
{
    CAS_ASSERT(handle);
    CAS_ASSERT(session);

    *session = (CasSession)malloc(sizeof(CAS_SessionInfo_t));
    memset((void *)*session, 0x0, sizeof(CAS_SessionInfo_t));
    ((CAS_SessionInfo_t *)(*session))->cas_handle = (CAS_CasInfo_t *)handle;

    return cas_ops->open_session(handle, *session, service_type);
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
AM_RESULT AM_CA_SetEmmPid(CasHandle handle, int dmx_dev, uint16_t emmPid)
{
    CAS_ASSERT(handle);

    if (cas_ops && cas_ops->set_emm_pid) {
      return cas_ops->set_emm_pid(handle, dmx_dev, emmPid);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Start DVR for the specified session of the CA system
 * \param session serviceInfo privateInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The service information for recording
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRSetPreParam(CasSession session, AM_CA_PreParam_t *param)
{
    CAS_ASSERT(session);

    if (cas_ops && cas_ops->dvr_set_pre_param) {
      return cas_ops->dvr_set_pre_param(session, param);
    }

    return AM_ERROR_NOT_LOAD;
}


/**\brief Start DVR for the specified session of the CA system
 * \param session serviceInfo privateInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The service information for recording
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStart(CasSession session, AM_CA_ServiceInfo_t *serviceInfo)
{
    CAS_ASSERT(session);
    CAS_ASSERT(serviceInfo);

    if (cas_ops && cas_ops->dvr_start) {
      return cas_ops->dvr_start(session, serviceInfo);
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
 * \param[in] session The opened session
 * \param[in] cryptoPara The encrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVREncrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    CAS_ASSERT(session);
    CAS_ASSERT(cryptoPara);

    if (cas_ops && cas_ops->dvr_encrypt) {
	return cas_ops->dvr_encrypt(session, cryptoPara);
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
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRReplay(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    CAS_ASSERT(session);
    CAS_ASSERT(cryptoPara);

    if (cas_ops && cas_ops->dvr_replay) {
	return cas_ops->dvr_replay(session, cryptoPara);
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

/**\brief delete ca record private file
 * \param location
 * \param[in] location The record file's location
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRDeleteRecordFile(const char *location)
{
    CAS_ASSERT(location);

    if (cas_ops && cas_ops->dvr_deleterecordfile) {
      return cas_ops->dvr_deleterecordfile(location);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Create Secmem
 * \param type paddr size
 * \param[in] type The binded service type
 * \param[out] paddr The secure buffer address
 * \param[out] size The secure buffer size
 * \retval SecMemHandle On success
 * \return NULL
 */
SecMemHandle AM_CA_CreateSecmem(CasSession session, CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size)
{
    if (cas_ops && cas_ops->create_secmem) {
        return cas_ops->create_secmem(session, type, pSecBuf, size);
    }

    return (SecMemHandle)NULL;
}

/**\brief Destroy Secmem
 * \param handle
 * \param[in] handle The SecMem handle
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DestroySecmem(CasSession session, SecMemHandle handle)
{
    CAS_ASSERT(handle);

    if (cas_ops && cas_ops->destroy_secmem) {
        return cas_ops->destroy_secmem(session, handle);
    }

    return AM_ERROR_NOT_LOAD;

}
/**\brief Register event callback
 * \param handle event_fn
 * \param[in] session The opened session
 * \param[in] event_fn The event callback function
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_RegisterEventCallback(CasSession session, CAS_EventFunction_t event_fn)
{
    if (cas_ops && cas_ops->register_event_cb) {
        return cas_ops->register_event_cb(session, event_fn);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief CAS Ioctl
 * \param handle in_json out_json out_len
 * \param[in] session The opened session
 * \param[in] in_json The input cmd string
 * \param[out] out_json The output string
 * \param[out] out_len The output string length
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Ioctl(CasSession session, const char *in_json, char *out_json, uint32_t out_len)
{
    if (cas_ops && cas_ops->ioctl) {
        return cas_ops->ioctl(session, in_json, out_json, out_len);
    }

    return AM_ERROR_NOT_LOAD;
}

/**\brief Wether the specified cas system need whole section data
 * \retval AM_TRUE or AM_FALSE
 * \return Error code
 */
uint8_t AM_CA_IsNeedWholeSection(void)
{
	if (cas_ops && cas_ops->isNeedWholeSection) {
		return cas_ops->isNeedWholeSection();
	}

	return 0;
}

/**\brief Report Section
 * \param[in] pAttr the attribute of section
 * \param[in] pData The pointer of section data buffer
 * \param[in] len The length of section data
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_ReportSection(AM_CA_SecAttr_t *pAttr, uint8_t *pData, uint16_t len)
{
	CAS_ASSERT(pData);
	if (cas_ops && cas_ops->report_section) {
		return cas_ops->report_section(pAttr, pData, len);
	}

	return AM_ERROR_NOT_LOAD;
}

/**\brief get all region of store info
 * \param[in] session The opened session
 * \param[out] region of store info
 * \param[out] region count
 * \retval am_success on success
 * \return error code
 */
AM_RESULT AM_CA_GetStoreRegion(CasSession session, AM_CA_StoreRegion_t *region, uint8_t *reg_cnt)
{
	CAS_ASSERT(region);
	if (cas_ops && cas_ops->get_store_region) {
		return cas_ops->get_store_region(session, region, reg_cnt);
	}

	return AM_ERROR_NOT_LOAD;
}
