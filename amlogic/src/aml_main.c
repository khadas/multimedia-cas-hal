#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "ca.h"
#include "am_ca.h"
#include "am_key.h"
#include "am_cas.h"
#include "am_cas_internal.h"

typedef struct {
    int dmx_dev;
    int dsc_chan_handle[MAX_CHAN_COUNT];
    int dsc_chan_count;
    int key_index[MAX_CHAN_COUNT*2];
    int key_index_count;
} AML_PrivateInfo_t;

static int aml_pre_init(void);
static int aml_init(CasHandle handle);
static int aml_term(CasHandle handle);
static int aml_open_session(CasHandle handle, CasSession session);
static int aml_close_session(CasSession session);
static int aml_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *service_info);
static int aml_stop_descrambling(CasSession session);
static int aml_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len);
static char *aml_get_version(void);

const struct AM_CA_Impl_t cas_ops = 
{
.pre_init = aml_pre_init,
.init = aml_init,
.term = aml_term,
.open_session = aml_open_session,
.close_session = aml_close_session,
.start_descrambling = aml_start_descrambling,
.stop_descrambling = aml_stop_descrambling,
.ioctl = aml_ioctl,
.get_version = aml_get_version
};

static int g_keyfd;
#if 1
static char gOddKey[8] = {0x11, 0x11, 0x11, 0x33, 0x11, 0x11, 0x11, 0x33};
static char gEvenKey[8] = {0x11, 0x11, 0x11, 0x33, 0x11, 0x11, 0x11, 0x33};
#else
static char gOddKey[8] = {0xe6, 0x2a, 0x3b, 0x4b, 0xd0, 0x0e, 0x38, 0x16};
static char gEvenKey[8] = {0xe6, 0x3c, 0x7c, 0x9e, 0x00, 0x43, 0xc6, 0x09};
#endif

static int aml_pre_init(void)
{
    ca_init();
    g_keyfd = key_open();

    return 0;
}

static int aml_init(CasHandle handle)
{
    UNUSED(handle);
    return 0;
}

static int aml_term(CasHandle handle)
{
    UNUSED(handle);
    key_close(g_keyfd);

    return 0;
}

static int aml_open_session(CasHandle handle, CasSession session)
{
    UNUSED(handle);
    AML_PrivateInfo_t *aml_priv_info = NULL;

    aml_priv_info = (AML_PrivateInfo_t *)malloc(sizeof(AML_PrivateInfo_t));
    memset((void *)aml_priv_info, 0, sizeof(AML_PrivateInfo_t));

    ((CAS_SessionInfo_t *)session)->private_data = aml_priv_info;

    return 0;
}

static int aml_close_session(CasSession session)
{
    AML_PrivateInfo_t *aml_priv_info = NULL;
    CAS_ASSERT(session);
    aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;
    CAS_ASSERT(aml_priv_info);
    free(aml_priv_info);
    ((CAS_SessionInfo_t *)session)->private_data = NULL;

    return 0;
}

static int aml_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *service_info)
{
    int i;
    int ret;
    int dsc_algo = CA_ALGO_CSA2;
    int dsc_type = CA_DSC_COMMON_TYPE;
    int key_algo = KEY_ALGO_CSA2;
    int key_userid = DSC_NETWORK;

    int ca_index, key_index;

    AML_PrivateInfo_t *aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;;

    for (i = 0; i < service_info->stream_num; i++) {
	ret = ca_open(service_info->dmx_dev);
	if (!ret) {
	    ca_index = ca_alloc_chan(service_info->dmx_dev,
				service_info->stream_pids[i],
				dsc_algo, dsc_type);
	    key_index = key_malloc(g_keyfd, key_userid, key_algo, 0);
	    key_set(g_keyfd, key_index, gOddKey, sizeof(gOddKey));
	    ca_set_key(service_info->dmx_dev, ca_index, CA_KEY_EVEN_TYPE, key_index);
	    aml_priv_info->key_index[i] = key_index;
	    aml_priv_info->key_index_count++;

	    key_index = key_malloc(g_keyfd, key_userid, key_algo, 0);
	    key_set(g_keyfd, key_index, gEvenKey, sizeof(gEvenKey));
	    ca_set_key(service_info->dmx_dev, ca_index, CA_KEY_ODD_TYPE, key_index);
	    aml_priv_info->key_index[MAX_CHAN_COUNT + i] = key_index;
	    aml_priv_info->key_index_count++;

	    aml_priv_info->dsc_chan_count++;
	    aml_priv_info->dsc_chan_handle[i] = ca_index;
	    aml_priv_info->dmx_dev = service_info->dmx_dev;

	    CA_DEBUG(0, "Associate key_index[%d] to ca_index[%d] for es pid %#x",
			key_index, ca_index, service_info->stream_pids[i]);
	}
    }

    return 0;
}

static int aml_stop_descrambling(CasSession session)
{
    int i;
    AML_PrivateInfo_t *aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;

    for (i = 0; i < aml_priv_info->dsc_chan_count; i++) {
	CA_DEBUG(0, "free ca_index[%d]", aml_priv_info->dsc_chan_handle[i]);
	ca_free_chan(aml_priv_info->dmx_dev, aml_priv_info->dsc_chan_handle[i]);
	CA_DEBUG(0, "free key_index[%d] and key_index[%d]", i, MAX_CHAN_COUNT + i);
	key_free(g_keyfd, aml_priv_info->key_index[i]);
	key_free(g_keyfd, aml_priv_info->key_index[MAX_CHAN_COUNT + i]);
    }

    return 0;
}

static int aml_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len)
{
    UNUSED(session);
    UNUSED(in_json);
    UNUSED(out_json);
    UNUSED(out_len);

    return 0;
}

static char *aml_get_version(void)
{
    return CAS_HAL_VER;
}
