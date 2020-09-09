#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#include "am_cas.h"
#include "am_cas_internal.h"
#include "ird_cas.h"
#include "ird_cas_internal.h"
#include "caclientapi.h"
/****zyl***/
#include "UniversalClient_Common_API.h"
/****zyl***/


#define PVR_CRYPTO_ENABLE
#define SECURE_MEMORY_ENABLE
//#define DSC_911_MODE

#define MAX_SECTION_BUFF_SIZE (1024)

#define RECORD_SECURE_BUF_SIZE (2*1024*1024)
#define PLAYBACK_SECURE_BUF_SIZE (1*1024*1024)

typedef struct {
	int used;
	CasSession session;
	int service_handle_id;
}ird_svc_idx_t;

typedef struct {
    int dmx_dev;
    int dsc_dev;
    int service_index;
    int pipe_id;
    uint32_t pvr_crypto_handle;
    CA_SERVICE_TYPE_t service_type;
    CAS_EventFunction_t event_cb;
}IRD_PrivateInfo_t;

typedef struct {
    int used;
    int dmx_dev;
    char *pPmtBuffer;
    int	nPmtLength;
}program_section_t;

typedef struct {
    char *pCatBuffer;
    int nCatLength;
    char *pNitBuffer;
    int nNitLength;
}global_section_t;

typedef struct {
    void *secbuf;
}secmem_handle_t;


static ird_svc_idx_t g_svc_idx[MAX_CHAN_COUNT];
static program_section_t g_program_section[MAX_CHAN_COUNT];
static global_section_t g_global_section;

static CAS_EventFunction_t g_event_cb = NULL;
static int g_global_service_idx = -1;
static int g_live_dmxid = -1;

#ifdef DSC_911_MODE
static uint8_t clear_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
#endif

static int ird_pre_init(void);
static int ird_init(CasHandle handle);
static int ird_term(CasHandle handle);
static int ird_isSystemId_supported(int CA_system_id);
static int ird_open_session(CasHandle handle, CasSession session);
static int ird_close_session(CasSession session);
static int ird_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo);
static int ird_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);
static int ird_stop_descrambling(CasSession session);
static int ird_dvr_set_pre_param(CasSession session, AM_CA_PreParam_t *param);
static int ird_set_emm_pid(CasHandle handle, int dmx_dev, uint16_t emmPid);
static int ird_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info);
static int ird_dvr_stop(CasSession session);
static int ird_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int ird_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int ird_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int ird_dvr_stop_replay(CasSession session);
static int ird_dvr_delete_record_file(const char *location);
static SecMemHandle ird_create_secmem(CasSession session, CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size);
static int ird_destroy_secmem(CasSession session, SecMemHandle handle);
static int ird_register_event_cb(CasSession session, CAS_EventFunction_t event_fn);
static int ird_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len);
static int ird_isNeed_whole_section(void);
static int ird_report_section(AM_CA_SecAttr_t *pAttr, uint8_t *pData, uint16_t len);
static char *ird_get_version(void);

static int find_section_idx(int dmx_dev);
static int alloc_section_idx(int dmx_dev);
static int alloc_service_idx(CasSession session, int service_handle_id);
static void free_service_idx(int idx);

/****zyl***/
static int get_service_handle_id(CasSession session);
/****zyl***/

const struct AM_CA_Impl_t cas_ops =
{
	.pre_init = ird_pre_init,
	.init = ird_init,
	.term = ird_term,
	.isSystemIdSupported = ird_isSystemId_supported,
	.open_session = ird_open_session,
	.close_session = ird_close_session,
	.start_descrambling = ird_start_descrambling,
	.update_descrambling_pid = ird_update_descrambling_pid,
	.stop_descrambling = ird_stop_descrambling,
	.set_emm_pid = ird_set_emm_pid,
	.dvr_set_pre_param = ird_dvr_set_pre_param,
	.dvr_start = ird_dvr_start,
	.dvr_stop = ird_dvr_stop,
	.dvr_encrypt = ird_dvr_encrypt,
	.dvr_decrypt = ird_dvr_decrypt,
	.dvr_replay = ird_dvr_replay,
	.dvr_stop_replay = ird_dvr_stop_replay,
	.dvr_deleterecordfile = ird_dvr_delete_record_file,
	.create_secmem = ird_create_secmem,
	.destroy_secmem = ird_destroy_secmem,
	.register_event_cb = ird_register_event_cb,
	.ioctl = ird_ioctl,
	.isNeedWholeSection = ird_isNeed_whole_section,
	.report_section = ird_report_section,
	.get_version = ird_get_version,
};

static void _cas_msg_notify(char *p_json)
{
#if 0
    IRD_PrivateInfo_t *private_data = NULL;

	if (g_svc_idx[0].used == 1)
	{
		CA_DEBUG(0, "[%s]: session[%d] is valid [%x]\n", __FUNCTION__, 0, g_svc_idx[0].session);
		private_data = (IRD_PrivateInfo_t *)((CAS_SessionInfo_t *)g_svc_idx[0].session)->private_data;
		private_data->event_cb(g_svc_idx[0].session, p_json);
	}
#endif
	g_event_cb((CasSession)NULL, p_json);
}

static int ird_pre_init(void)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_client_init();

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_init(CasHandle handle)
{
	int service_handle_id = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_client_start();

	// dmx_dev not use for EMM service
	service_handle_id = ird_open_service(-1, IRD_PLAY_EMM);
	g_global_service_idx = alloc_service_idx((CasSession)NULL, service_handle_id);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_term(CasHandle handle)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (g_svc_idx[g_global_service_idx].used == 1)
	{
		ird_close_service(g_svc_idx[g_global_service_idx].service_handle_id);
		free_service_idx(g_global_service_idx);
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_isSystemId_supported(int CA_system_id)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: CA_system_id: %x, do nothing for irdeto\n", __FUNCTION__, CA_system_id);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 1;
}

static int ird_open_session(CasHandle handle, CasSession session)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
	int index = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: session: %x\n", __FUNCTION__, session);

    ird_pri_info = (IRD_PrivateInfo_t *)malloc(sizeof(IRD_PrivateInfo_t));
    memset((void *)ird_pri_info, 0x00, sizeof(IRD_PrivateInfo_t));
    ird_pri_info->event_cb = NULL;
    ((CAS_SessionInfo_t *)session)->private_data = ird_pri_info;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_close_session(CasSession session)
{
    IRD_PrivateInfo_t *private_data = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: session: %x\n", __FUNCTION__, session);

    private_data = ((CAS_SessionInfo_t *)session)->private_data;
    free(private_data);
    ((CAS_SessionInfo_t *)session)->private_data = NULL;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo)
{
	IRD_PrivateInfo_t *ird_pri_info = NULL;
	pipeline_mode_e pipeline_mode;
	int service_handle_id = -1;
	int idx = -1;
	int pipe_id = -1;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: dump service infor, dmx_dev: %d, dsc_dev: %d, dvr_dev: %d, service_type: %d \n", __FUNCTION__, \
					serviceInfo->dmx_dev, serviceInfo->dsc_dev, serviceInfo->dvr_dev, serviceInfo->service_type);

	ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

	pipeline_mode = PIPELINE_MODE_LIVE;
	ret = pipeline_create(serviceInfo->dmx_dev, pipeline_mode, &pipe_id);
	CA_DEBUG(0, "[%s]: create pipeline, ret: %d, pipeline_mode: %d, pipe_id: %d\n", __FUNCTION__, \
												ret, pipeline_mode, pipe_id);

	service_handle_id = ird_open_service(serviceInfo->dmx_dev, IRD_PLAY_LIVE);

	ird_pri_info->dmx_dev = serviceInfo->dmx_dev;
	ird_pri_info->dsc_dev = serviceInfo->dsc_dev;
	ird_pri_info->service_index = alloc_service_idx(session, service_handle_id);
	ird_pri_info->pipe_id = pipe_id;

	g_live_dmxid = serviceInfo->dmx_dev;

	idx = find_section_idx(serviceInfo->dsc_dev);
	if (idx != -1)
	{
		ird_process_pmt(service_handle_id, g_program_section[idx].pPmtBuffer, g_program_section[idx].nPmtLength);
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_stop_descrambling(CasSession session)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
    int service_idx = -1;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

	ret = pipeline_release(ird_pri_info->pipe_id);
	CA_DEBUG(0, "[%s]: release pipeline, ret: %d, pipe_id: %d \n", __FUNCTION__, ret, ird_pri_info->pipe_id);
	ird_pri_info->pipe_id = -1;

    service_idx = get_service_idx(session);
	if (g_svc_idx[service_idx].used == 1)
	{
		ird_close_service(g_svc_idx[service_idx].service_handle_id);
		free_service_idx(service_idx);
	}

	ird_clear_screen_msg();

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_set_emm_pid(CasHandle handle, int dmx_dev, uint16_t emmPid)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_set_pre_param(CasSession session, AM_CA_PreParam_t *param)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: pre-parameter dmx_dev: %d\n", __FUNCTION__, param->dmx_dev);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;
	ird_pri_info->dmx_dev = param->dmx_dev;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
	pipeline_mode_e pipeline_mode;
	int service_handle_id = -1;
	int idx = -1;
	int pipe_id = -1;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: dump service infor, dmx_dev: %d, dsc_dev: %d, dvr_dev: %d, service_type: %d\n", __FUNCTION__, service_info->dmx_dev, service_info->dsc_dev, service_info->dvr_dev, service_info->service_type);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

#ifdef SECURE_MEMORY_ENABLE
	pipeline_mode = PIPELINE_MODE_SMP_RECORD;
#else
	pipeline_mode = PIPELINE_MODE_RECORD;
#endif

	ret = pipeline_create(service_info->dmx_dev, pipeline_mode, &pipe_id);
	CA_DEBUG(0, "[%s]: create pipeline, ret: %d, pipeline_mode: %d, pipe_id: %d\n", __FUNCTION__, \
											ret, pipeline_mode, pipe_id);

	ret = pipeline_set_mode(pipe_id, pipeline_mode);
	CA_DEBUG(0, "[%s]: set pipeline mode, ret: %d, pipeline_mode: %d, pipe_id: %d\n", __FUNCTION__, \
											ret, pipeline_mode, pipe_id);

	service_handle_id = ird_open_service(service_info->dmx_dev, IRD_PLAY_RECORD);

	ird_pri_info->dmx_dev = service_info->dmx_dev;
	ird_pri_info->dsc_dev = service_info->dsc_dev;
	ird_pri_info->service_index = alloc_service_idx(session, service_handle_id);
	ird_pri_info->pipe_id = pipe_id;

	idx = find_section_idx(service_info->dsc_dev);
	if (idx != -1)
	{
		ird_process_pmt(service_handle_id, g_program_section[idx].pPmtBuffer, g_program_section[idx].nPmtLength);
	}

#ifdef PVR_CRYPTO_ENABLE
	pvr_crypto_open_params_t pvr_crypto_params;
	pvr_crypto_mode_t crypto_mode;
	pvr_crypto_handle_t pvr_crypto_handle;

	/* Open crypto device */
	memset(&pvr_crypto_params, 0, sizeof(pvr_crypto_params));
	pvr_crypto_params.dmx_id = ird_pri_info->dmx_dev;
	pvr_crypto_params.is_playback = 0;
	pvr_crypto_params.pvr_handle = 0;
	ret = PVR_OpenCrypto(&pvr_crypto_params, &pvr_crypto_handle);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s]: pvr open crypto fail, ret: %d\n", __FUNCTION__, ret);
        goto exit;
	}

	ird_pri_info->pvr_crypto_handle = pvr_crypto_handle;
	CA_DEBUG(0, "[%s]: pvr open crypto success, pvr_crypto_handle: %d\n", __FUNCTION__, pvr_crypto_handle);

	/* Set Crypto mode */
	crypto_mode = PVR_CRYPTO_MODE_TS_CLEAR_TAIL;
	ret = PVR_SetCryptoMode(pvr_crypto_handle, crypto_mode);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s]: pvr set crypto mode fail, ret: %d\n", __FUNCTION__, ret);
		goto exit;
	}

#ifdef DSC_911_MODE
	pvr_crypto_algo_t algo = PVR_CRYPTO_ALGO_AES;
	k_buffer_t key;
	uint8_t session_key[32] = {0};

	ret = PVR_SetCryptoAlgo(pvr_crypto_handle, algo);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s]: pvr set crypto algo fail, ret: %d\n", __FUNCTION__, ret);
		goto exit;
	}

	memset(session_key, 0, sizeof(session_key));
	memcpy(session_key, clear_key, 16);

	key.p_data = session_key;
	key.data_len = 16;
	ret = PVR_SetCryptoKey(pvr_crypto_handle, &key);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s]: pvr set crypto algo key fail, pvr_crypto_handle: %x, ret: %d\n", __FUNCTION__, \
												ird_pri_info->pvr_crypto_handle, ret);
		goto exit;
	}
#endif

#endif

	// start secure PVR record
	ird_start_record(service_handle_id);

exit:

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_stop(CasSession session)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
    int service_idx = -1;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

	ret = pipeline_release(ird_pri_info->pipe_id);
	CA_DEBUG(0, "[%s]: release pipeline, ret: %d, pipe_id: %d \n", __FUNCTION__, ret, ird_pri_info->pipe_id);
	ird_pri_info->pipe_id = -1;

    service_idx = get_service_idx(session);
	if (g_svc_idx[service_idx].used == 1)
	{
		ird_stop_record(service_idx);
		ird_close_service(g_svc_idx[service_idx].service_handle_id);
		free_service_idx(service_idx);
	}

#ifdef PVR_CRYPTO_ENABLE
	PVR_CloseCrypto(ird_pri_info->pvr_crypto_handle);
#endif

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: buf_in->type: %d, buf_out->type: %d\n", __FUNCTION__, cryptoPara->buf_in.type, cryptoPara->buf_out.type);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

#ifdef PVR_CRYPTO_ENABLE
	Ird_status_t result = IRD_FAILURE;
	int ret = -1;

	result =  Spi_Wait_SetPVRSession_Key();
	if (result == IRD_NO_ERROR)
	{
		ret = PVR_RunCrypto(ird_pri_info->pvr_crypto_handle,
			(uint8_t *)cryptoPara->buf_in.addr, cryptoPara->buf_in.size,
			(uint8_t *)cryptoPara->buf_out.addr, &cryptoPara->buf_out.size,
			1);
		if (ret != 0)
		{
			CA_DEBUG(0, "[%s]: pvr run crypto fail, pvr_crypto_handle: %x, ret: %d\n", __FUNCTION__, \
												ird_pri_info->pvr_crypto_handle, ret);
			goto exit;
		}
		else
		{
			CA_DEBUG(0, "[%s]: pvr run crypto success, buf_in: %d, buf_out: %d\n", __FUNCTION__, cryptoPara->buf_in.size, cryptoPara->buf_out.size);
		}

		cryptoPara->buf_len = cryptoPara->buf_out.size;
	}
	else
	{
		CA_DEBUG(0, "[%s]: pvr session key not set\n", __FUNCTION__);
	}

#else
	memcpy((void *)cryptoPara->buf_out.addr, (void *)cryptoPara->buf_in.addr, cryptoPara->buf_in.size);
	cryptoPara->buf_out.size = cryptoPara->buf_in.size;
	cryptoPara->buf_len = cryptoPara->buf_in.size;
#endif

	{
		/****zyl***/
	    int serviceHandleid = -1;
		IRD_Metadata_PVRCryptoPara_t stPVRCryptoPara;
		Ird_status_t	IrdRet = IRD_NO_ERROR;
		uc_service_handle hServiceHandle;

	    serviceHandleid = get_service_handle_id(session);
		if (serviceHandleid == -1)
		{
			CA_DEBUG(0, "[%s]:call get_service_handle_id is error!\n", __FUNCTION__);
			goto exit;
		}

		IrdRet = ird_metadata_GetServiceHandle(serviceHandleid, &hServiceHandle);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(0, "call ird_metadata_GetServiceHandle is error!");
			goto exit;
		}

		memset(&stPVRCryptoPara, 0, sizeof(IRD_Metadata_PVRCryptoPara_t));
		stPVRCryptoPara.segment_id = cryptoPara->segment_id;
		stPVRCryptoPara.offset = cryptoPara->offset;
		memcpy(stPVRCryptoPara.location, cryptoPara->location, MAX_LOCATION_SIZE);
		IrdRet = ird_metadata_SetRecordCryptoPara(hServiceHandle, &stPVRCryptoPara);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(0, "call ird_metadata_SetRecordCryptoPara is error!");
			goto exit;
		}
		/****zyl***/
	}

exit:

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: buf_in->type: %d, buf_out->type: %d\n", __FUNCTION__, cryptoPara->buf_in.type, cryptoPara->buf_out.type);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

#ifdef PVR_CRYPTO_ENABLE
	Ird_status_t result = IRD_FAILURE;
	int ret = -1;

	result =  Spi_Wait_SetPVRSession_Key();
	if (result == IRD_NO_ERROR)
	{
		ret = PVR_RunCrypto(ird_pri_info->pvr_crypto_handle,
			(uint8_t *)cryptoPara->buf_in.addr, cryptoPara->buf_in.size,
			(uint8_t *)cryptoPara->buf_out.addr, &cryptoPara->buf_out.size,
			0);
		if (ret != 0)
		{
			CA_DEBUG(0, "[%s]: pvr run crypto fail, pvr_crypto_handle: %x, ret: %d\n", __FUNCTION__, \
												ird_pri_info->pvr_crypto_handle, ret);
			goto exit;
		}
		else
		{
			CA_DEBUG(0, "[%s]: pvr run crypto success, buf_in: %d, buf_out: %d\n", __FUNCTION__, cryptoPara->buf_in.size, cryptoPara->buf_out.size);
		}

		cryptoPara->buf_len = cryptoPara->buf_out.size;
	}
	else
	{
		CA_DEBUG(0, "[%s]: pvr session key not set\n", __FUNCTION__);
	}

#else
	memcpy((void *)cryptoPara->buf_out.addr, (void *)cryptoPara->buf_in.addr, cryptoPara->buf_in.size);
	cryptoPara->buf_out.size = cryptoPara->buf_in.size;
	cryptoPara->buf_len = cryptoPara->buf_in.size;
#endif

	{
		/****zyl***/
	    int serviceHandleid = -1;
		IRD_Metadata_PVRCryptoPara_t stPVRCryptoPara;
		Ird_status_t	IrdRet = IRD_NO_ERROR;
		uc_service_handle hServiceHandle;

	    serviceHandleid = get_service_handle_id(session);
		if (serviceHandleid == -1)
		{
			CA_DEBUG(0, "[%s]:call get_service_handle_id is error!\n", __FUNCTION__);
			goto exit;
		}

		IrdRet = ird_metadata_GetServiceHandle(serviceHandleid, &hServiceHandle);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(0, "call ird_metadata_GetServiceHandle is error!");
			goto exit;
		}

		memset(&stPVRCryptoPara, 0, sizeof(IRD_Metadata_PVRCryptoPara_t));
		stPVRCryptoPara.segment_id = cryptoPara->segment_id;
		stPVRCryptoPara.offset = cryptoPara->offset;
		memcpy(stPVRCryptoPara.location, cryptoPara->location, MAX_LOCATION_SIZE);
		IrdRet = ird_metadata_SubmitPVRCryptoInfo(hServiceHandle, &stPVRCryptoPara);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(0, "call ird_metadata_SubmitPVRCryptoInfo is error!");
			goto exit;
		}
		/****zyl***/
	}

exit:

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
	pipeline_mode_e pipeline_mode;
	int service_handle_id = -1;
	int idx = -1;
	int ret = -1;
	int pipe_id = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

	service_handle_id = ird_open_service(0, IRD_PLAY_PLAYBACK);
	ird_pri_info->service_index = alloc_service_idx(session, service_handle_id);

#ifdef PVR_CRYPTO_ENABLE
		pvr_crypto_open_params_t pvr_crypto_params;
		pvr_crypto_mode_t crypto_mode;
		pvr_crypto_handle_t pvr_crypto_handle;

		/* Open crypto device */
		memset(&pvr_crypto_params, 0, sizeof(pvr_crypto_params));
		pvr_crypto_params.dmx_id = ird_pri_info->dmx_dev;
		pvr_crypto_params.is_playback = 1;
		pvr_crypto_params.pvr_handle = 0;
		ret = PVR_OpenCrypto(&pvr_crypto_params, &pvr_crypto_handle);
		if (ret != 0)
		{
			CA_DEBUG(0, "[%s]: pvr open crypto fail, ret: %d\n", __FUNCTION__, ret);
			goto exit;
		}

		ird_pri_info->pvr_crypto_handle = pvr_crypto_handle;
		CA_DEBUG(0, "[%s]: pvr open crypto success, pvr_crypto_handle: %d\n", __FUNCTION__, pvr_crypto_handle);

		/* Set Crypto mode */
		crypto_mode = PVR_CRYPTO_MODE_TS_CLEAR_TAIL;
		ret = PVR_SetCryptoMode(pvr_crypto_handle, crypto_mode);
		if (ret != 0)
		{
			CA_DEBUG(0, "[%s]: pvr set crypto mode fail, ret: %d\n", __FUNCTION__, ret);
			goto exit;
		}

#ifdef DSC_911_MODE
		pvr_crypto_algo_t algo = PVR_CRYPTO_ALGO_AES;
		k_buffer_t key;
		uint8_t session_key[32] = {0};

		ret = PVR_SetCryptoAlgo(pvr_crypto_handle, algo);
		if (ret != 0)
		{
			CA_DEBUG(0, "[%s]: pvr set crypto algo fail, ret: %d\n", __FUNCTION__, ret);
			goto exit;
		}

		memset(session_key, 0, sizeof(session_key));
		memcpy(session_key, clear_key, 16);

		key.p_data = session_key;
		key.data_len = 16;
		ret = PVR_SetCryptoKey(pvr_crypto_handle, &key);
		if (ret != 0)
		{
			CA_DEBUG(0, "[%s]: pvr set crypto algo key fail, pvr_crypto_handle: %x, ret: %d\n", __FUNCTION__, \
													ird_pri_info->pvr_crypto_handle, ret);
			goto exit;
		}
#endif
#endif

	{
		/****zyl***/
	    int serviceHandleid = -1;
		IRD_Metadata_PVRCryptoPara_t stPVRCryptoPara;
		Ird_status_t	IrdRet = IRD_NO_ERROR;
		uc_service_handle hServiceHandle;

	    serviceHandleid = get_service_handle_id(session);
		if (serviceHandleid == -1)
		{
			CA_DEBUG(0, "[%s]:call get_service_handle_id is error!\n", __FUNCTION__);
			goto exit;
		}

		IrdRet = ird_metadata_GetServiceHandle(serviceHandleid, &hServiceHandle);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(0, "call ird_metadata_GetServiceHandle is error!");
			goto exit;
		}

		memset(&stPVRCryptoPara, 0, sizeof(IRD_Metadata_PVRCryptoPara_t));
		stPVRCryptoPara.segment_id = cryptoPara->segment_id;
		stPVRCryptoPara.offset = cryptoPara->offset;
		memcpy(stPVRCryptoPara.location, cryptoPara->location, MAX_LOCATION_SIZE);
		IrdRet = ird_metadata_SubmitFirstPVRCryptoInfo(hServiceHandle, &stPVRCryptoPara);
		if (IrdRet != IRD_NO_ERROR)
		{
			CA_DEBUG(0, "call ird_metadata_SubmitPVRCryptoInfo is error!");
			goto exit;
		}
		/****zyl***/
	}

exit:

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_stop_replay(CasSession session)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
    int service_idx = -1;
	int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

    service_idx = get_service_idx(session);
	if (g_svc_idx[service_idx].used == 1)
	{
		ird_close_service(g_svc_idx[service_idx].service_handle_id);
		free_service_idx(service_idx);
	}

#ifdef PVR_CRYPTO_ENABLE
	PVR_CloseCrypto(ird_pri_info->pvr_crypto_handle);
#endif

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_delete_record_file(const char *location)
{
    char destfname[MAX_LOCATION_SIZE];
    int offset;
	char cmd[MAX_LOCATION_SIZE];

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	memset(destfname, 0, sizeof(MAX_LOCATION_SIZE));
    strncpy(destfname, location, strlen(location));
    offset = strlen(location);
    strncpy(destfname + offset, "*", 1);
    offset += 1;
    strncpy(destfname + offset, ".ird.dat", 8);

	memset(cmd, 0, sizeof(MAX_LOCATION_SIZE));
	snprintf(cmd, MAX_LOCATION_SIZE, "rm -f %s", destfname);
	CA_DEBUG(0, "[%s]: cmd:%s\n", __FUNCTION__, cmd);
	system(cmd);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static SecMemHandle ird_create_secmem(CasSession session, CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
    uint32_t secbuf = 0;
    secmem_handle_t *handle = NULL;
    uint32_t bufsize = 0;
    int ret = -1;

	CA_DEBUG(0, "[%s] step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s] session: %x, service type: %d\n", __FUNCTION__, session, type);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;
	ird_pri_info->service_type = type;

    switch (type)
	{
        case SERVICE_PVR_RECORDING:
			bufsize = RECORD_SECURE_BUF_SIZE;
            break;

        case SERVICE_PVR_PLAY:
			bufsize = PLAYBACK_SECURE_BUF_SIZE;
            break;

        case SERVICE_LIVE_PLAY:
        default:
            goto exit;
    }

	if (ird_pri_info->service_type == SERVICE_PVR_PLAY)
	{
		pipeline_mode_e pipeline_mode;
		int pipe_id = -1;

#ifdef SECURE_MEMORY_ENABLE
		pipeline_mode = PIPELINE_MODE_SMP_PLAYBACK;
#else
		pipeline_mode = PIPELINE_MODE_PLAYBACK;
#endif

		ret = pipeline_create(ird_pri_info->dmx_dev, pipeline_mode, &pipe_id);
		CA_DEBUG(0, "[%s]: create pipeline, ret: %d, dmx_dev: %d, pipeline_mode: %d, pipe_id: %d\n", __FUNCTION__, \
												ret, ird_pri_info->dmx_dev, pipeline_mode, pipe_id);

		ret = pipeline_set_mode(pipe_id, pipeline_mode);
		CA_DEBUG(0, "[%s]: set pipeline mode, ret: %d, pipeline_mode: %d, pipe_id: %d\n", __FUNCTION__, \
												ret, pipeline_mode, pipe_id);

		ird_pri_info->pipe_id = pipe_id;
	}

#ifdef SECURE_MEMORY_ENABLE

	CA_DEBUG(0, "[%s] alloc secmem for pipeline, id: %d, bufsize: %x\n", __FUNCTION__, ird_pri_info->pipe_id, bufsize);
	ret = pipeline_alloc_secmem(ird_pri_info->pipe_id, bufsize, &secbuf);
	if (ret != 0)
	{
		CA_DEBUG(0, "[%s] alloc secmem for pipeline(%d) error, ret = %d\n", __FUNCTION__, ird_pri_info->pipe_id, ret);
        goto exit;
	}
#endif

    handle = (secmem_handle_t *)malloc(sizeof(secmem_handle_t));
    if (!handle)
	{

#ifdef SECURE_MEMORY_ENABLE
       pipeline_free_secmem(ird_pri_info->pipe_id, secbuf);
#endif
        goto exit;
    }

    handle->secbuf = (void*)secbuf;

exit:
    if (secbuf && pSecBuf)
	{
        *pSecBuf = (void*)secbuf;
        *size = bufsize;
    }

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

    return (SecMemHandle)handle;
}

static int ird_destroy_secmem(CasSession session, SecMemHandle handle)
{
    IRD_PrivateInfo_t *ird_pri_info = NULL;
    int ret = -1;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s] session: %x\n", __FUNCTION__, session);

    ird_pri_info = ((CAS_SessionInfo_t *)session)->private_data;

#ifdef SECURE_MEMORY_ENABLE
		CA_DEBUG(0, "[%s] free secmem for pipeline, id: %d\n", __FUNCTION__, ird_pri_info->pipe_id);
		ret = pipeline_free_secmem(ird_pri_info->pipe_id, (uint32_t)((secmem_handle_t *)handle)->secbuf);
#endif

	if (ird_pri_info->service_type == SERVICE_PVR_PLAY)
	{
		ret = pipeline_release(ird_pri_info->pipe_id);
		CA_DEBUG(0, "[%s]: release pipeline, ret: %d, pipe_id: %d \n", __FUNCTION__, ret, ird_pri_info->pipe_id);
		ird_pri_info->pipe_id = -1;
	}

    free((void *)handle);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

    return ret;
}

static int ird_register_event_cb(CasSession session, CAS_EventFunction_t event_fn)
{
    IRD_PrivateInfo_t *private_data = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

    if (!session)
	{
		g_event_cb = event_fn;
    }
	else
	{
		private_data = (IRD_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
		private_data->event_cb = event_fn;
    }

	ird_register_msg_notify(_cas_msg_notify);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

    return 0;
}

static int ird_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

    return 0;
}

static int ird_isNeed_whole_section(void)
{
	return 1;
}

static int ird_report_section(AM_CA_SecAttr_t *pAttr, uint8_t *pData, uint16_t len)
{
	int idx = -1;
	int i = 0;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: dmx_dev: %d, service_id: %x, section_type: %d, len:%d\n", __FUNCTION__, \
								pAttr->dmx_dev, pAttr->service_id, pAttr->section_type, len);

	switch (pAttr->section_type)
	{
		case AM_CA_SECTION_PMT:
		{
			idx = alloc_section_idx(pAttr->dmx_dev);
			if (idx == -1)
			{
				CA_DEBUG(0, "can not find a valid section idx\n");
				break;
			}

			if (g_program_section[idx].pPmtBuffer == NULL)
			{
				g_program_section[idx].pPmtBuffer = malloc(MAX_SECTION_BUFF_SIZE);
				memset(g_program_section[idx].pPmtBuffer, 0x00, sizeof(MAX_SECTION_BUFF_SIZE));
				memcpy(g_program_section[idx].pPmtBuffer, pData, len);
				g_program_section[idx].nPmtLength = len;
			}
			else
			{
				if (0 != memcmp(g_program_section[idx].pPmtBuffer, pData, len))
				{
					memset(g_program_section[idx].pPmtBuffer, 0x00, sizeof(MAX_SECTION_BUFF_SIZE));
					memcpy(g_program_section[idx].pPmtBuffer, pData, len);
					g_program_section[idx].nPmtLength = len;
				}
				else
				{
					CA_DEBUG(0, "the same pmt section, not update\n");
				}
			}
			break;
		}

		case AM_CA_SECTION_CAT:
		{
			/* workround: not support record across the frequency now, so only dispose one CAT section*/
			int bReport = 0;

			if (g_global_section.pCatBuffer == NULL)
			{
				g_global_section.pCatBuffer = malloc(MAX_SECTION_BUFF_SIZE);
				memset(g_global_section.pCatBuffer, 0x00, sizeof(MAX_SECTION_BUFF_SIZE));
				memcpy(g_global_section.pCatBuffer, pData, len);
				g_global_section.nCatLength = len;
				bReport = 1;
			}
			else
			{
				if (0 != memcmp(g_global_section.pCatBuffer, pData, len))
				{
					memset(g_global_section.pCatBuffer, 0x00, sizeof(MAX_SECTION_BUFF_SIZE));
					memcpy(g_global_section.pCatBuffer, pData, len);
					g_global_section.nCatLength = len;
					bReport = 1;
				}
				else
				{
					CA_DEBUG(0, "the same cat section, not update\n");
				}
			}

			if (bReport)
			{
				ird_process_cat(g_svc_idx[g_global_service_idx].service_handle_id, g_global_section.pCatBuffer, g_global_section.nCatLength);
			}
			break;
		}
	}

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static char *ird_get_version(void)
{
    return CAS_HAL_VER;
}

static int find_section_idx(int dmx_dev)
{
    int i = 0;

    for (i = 0; i < MAX_CHAN_COUNT; i++)
	{
		if ((g_program_section[i].used) && (g_program_section[i].dmx_dev == dmx_dev))
		{
			return i;
		}
    }

    CA_DEBUG(0, "can not find exist section idx.");
    return -1;
}

static int alloc_section_idx(int dmx_dev)
{
    int i = 0;
	int idx = -1;

	idx = find_section_idx(dmx_dev);
	if (idx == -1)
	{
		for (i = 0; i < MAX_CHAN_COUNT; i++)
		{
			if (!g_program_section[i].used)
			{
				CA_DEBUG(0, "allocated irdeto section idx: %d", i);
				g_program_section[i].used = 1;
				g_program_section[i].dmx_dev = dmx_dev;
				return i;
			}
		}
	}

    CA_DEBUG(0, "find exist section idx: %d", idx);
    return idx;
}


static int alloc_service_idx(CasSession session, int service_handle_id)
{
    int i = 0;

    for (i = 0; i < MAX_CHAN_COUNT; i++)
	{
		if (!g_svc_idx[i].used)
		{
		    CA_DEBUG(0, "allocated irdeto svc idx: %d", i);
		    g_svc_idx[i].used = 1;
		    g_svc_idx[i].session = session;
			g_svc_idx[i].service_handle_id = service_handle_id;
		    return i;
		}
    }

    CA_DEBUG(2, "alloc irdeto svc idx failed.");
    return -1;
}

static void free_service_idx(int idx)
{
    int i = 0;

    for (i = 0; i < MAX_CHAN_COUNT; i++)
	{
		if (g_svc_idx[i].used && (i == idx))
		{
		    CA_DEBUG(0, "free irdeto svc idx %d", i);
		    g_svc_idx[i].used = 0;
		    g_svc_idx[i].session = 0;
		    return;
		}
    }

    CA_DEBUG(0, "free irdeto svc idx failed.");
    return;
}

CasSession get_service_session(int idx)
{
    if (g_svc_idx[idx].used)
	{
		return g_svc_idx[idx].session;
    }

    return (CasSession)NULL;
}

int get_service_idx(CasSession session)
{
    int i = 0;

    for (i = 0; i < MAX_CHAN_COUNT; i++)
	{
		if ((g_svc_idx[i].used) && (g_svc_idx[i].session == session))
		{
		    return i;
		}
    }

    CA_DEBUG(0, "%s not found session:%#x", __FUNCTION__, session);
    return -1;
}

/****zyl***/
static int get_service_handle_id(CasSession session)
{
    int i = 0;

    for (i = 0; i < MAX_CHAN_COUNT; i++)
	{
		if ((g_svc_idx[i].used) && (g_svc_idx[i].session == session))
		{
		    return g_svc_idx[i].service_handle_id;
		}
    }

    CA_DEBUG(0, "%s not found session:%#x", __FUNCTION__, session);
    return -1;
}
/****zyl***/

void AM_APP_NotifyCat(void)
{
	if (g_global_section.pCatBuffer != NULL)
	{
		CA_DEBUG(0, "%s notify cat!", __FUNCTION__);
		ird_process_cat(g_svc_idx[g_global_service_idx].service_handle_id, g_global_section.pCatBuffer, g_global_section.nCatLength);
	}
}
