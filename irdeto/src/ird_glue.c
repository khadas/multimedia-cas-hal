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

#define MAX_SECTION_BUFF_SIZE 1024

typedef struct {
    int used;
    CasSession session;
}ird_svc_idx_t;

typedef struct {
    CAS_EventFunction_t event_cb;
}IRD_PrivateInfo_t;

static ird_svc_idx_t g_svc_idx[MAX_CHAN_COUNT];

static uint8_t s_pmt_section[MAX_SECTION_BUFF_SIZE] = {0};
static uint16_t s_pmt_len = 0;
static uint8_t s_cat_section[MAX_SECTION_BUFF_SIZE] = {0};
static uint16_t s_cat_len = 0;

static CAS_EventFunction_t g_event_cb;

static int ird_pre_init(void);
static int ird_init(CasHandle handle);
static int ird_term(CasHandle handle);
static int ird_isSystemId_supported(int CA_system_id);
static int ird_open_session(CasHandle handle, CasSession session);
static int ird_close_session(CasSession session);
static int ird_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo);
static int ird_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);
static int ird_stop_descrambling(CasSession session);
static int ird_set_emm_pid(CasHandle handle, uint16_t emmPid);
static int ird_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info);
static int ird_dvr_stop(CasSession session);
static int ird_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int ird_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int ird_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int ird_dvr_stop_replay(CasSession session);
static SecMemHandle ird_create_secmem(CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size);
static int ird_destroy_secmem(SecMemHandle handle);
static int ird_register_event_cb(CasSession session, CAS_EventFunction_t event_fn);
static int ird_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len);
static int ird_isNeed_whole_section(void);
static int ird_report_section(AM_CA_SecAttr_t *pAttr, uint8_t *pData, uint16_t len);
static char *ird_get_version(void);

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
	.dvr_start = ird_dvr_start,
	.dvr_stop = ird_dvr_stop,
	.dvr_encrypt = ird_dvr_encrypt,
	.dvr_decrypt = ird_dvr_decrypt,
	.dvr_replay = ird_dvr_replay,
	.dvr_stop_replay = ird_dvr_stop_replay,
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
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_client_start();
	ird_open_service(IRD_PLAY_EMM);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_term(CasHandle handle)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
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

#if 0
	for (index = 0; index < MAX_CHAN_COUNT; index++)
	{
		if (g_svc_idx[index].used == 0)
		{
			break;
		}
	}

	if (index == MAX_CHAN_COUNT)
	{
		CA_DEBUG(2, "No valid seesion number");
		return -1;
	}

	g_svc_idx[index].session = session;
	g_svc_idx[index].used = 1;
#endif

    ird_pri_info = (IRD_PrivateInfo_t *)malloc(sizeof(IRD_PrivateInfo_t));
    memset((void *)ird_pri_info, 0x00, sizeof(IRD_PrivateInfo_t));
    ird_pri_info->event_cb = NULL;
    ((CAS_SessionInfo_t *)session)->private_data = ird_pri_info;

	//CA_DEBUG(0, "[%s]: service_type: %d\n", __FUNCTION__, ((CAS_SessionInfo_t *)session)->service_info.service_type);
	ird_open_service(IRD_PLAY_LIVE);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_close_session(CasSession session)
{
    IRD_PrivateInfo_t *private_data = NULL;

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

    private_data = ((CAS_SessionInfo_t *)session)->private_data;
    free(private_data);
    ((CAS_SessionInfo_t *)session)->private_data = NULL;

	//CA_DEBUG(0, "[%s]: service_type: %d\n", __FUNCTION__, ((CAS_SessionInfo_t *)session)->service_info.service_type);
	ird_close_service(IRD_PLAY_LIVE);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_process_pmt(s_pmt_section, s_pmt_len);

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
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	ird_clear_screen_msg();

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_set_emm_pid(CasHandle handle, uint16_t emmPid)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_stop(CasSession session)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	memcpy((void *)cryptoPara->buf_out.addr, (void *)cryptoPara->buf_in.addr, cryptoPara->buf_in.size);
	cryptoPara->buf_out.size = cryptoPara->buf_in.size;
	cryptoPara->buf_len = cryptoPara->buf_in.size;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_dvr_stop_replay(CasSession session)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static SecMemHandle ird_create_secmem(CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_destroy_secmem(SecMemHandle handle)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
    return 0;
}

static int ird_register_event_cb(CasSession session, CAS_EventFunction_t event_fn)
{
    IRD_PrivateInfo_t *private_data;

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
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: dmx_dev: %d, service_id: %x, section_type: %d, len:%d\n", __FUNCTION__, \
								pAttr->dmx_dev, pAttr->service_id, pAttr->section_type, len);

	switch (pAttr->section_type)
	{
		case AM_CA_SECTION_PMT:
		{
			if (0 != memcmp(s_pmt_section, pData, len))
			{
				memset(s_pmt_section, 0x00, sizeof(s_pmt_section));
				memcpy(s_pmt_section, pData, len);
				s_pmt_len = len;
			}
			else
			{
				CA_DEBUG(0, "the same pmt section, not update\n");
			}
			break;
		}

		case AM_CA_SECTION_CAT:
		{
			if (0 != memcmp(s_cat_section, pData, len))
			{
				memset(s_cat_section, 0x00, sizeof(s_cat_section));
				memcpy(s_cat_section, pData, len);
				s_cat_len = len;

				ird_process_cat(s_cat_section, s_cat_len);
			}
			else
			{
				CA_DEBUG(0, "the same pmt section, not update\n");
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
