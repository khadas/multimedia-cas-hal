#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "ca.h"
#include "am_ca.h"
#include "am_cas.h"
#include "am_cas_internal.h"
#include "desc_client.h"

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
static int aml_isSystemIdSupported(int systemId);
static int aml_open_session(CasHandle handle, CasSession session);
static int aml_close_session(CasSession session);
static int aml_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *service_info);
static int aml_stop_descrambling(CasSession session);
static int aml_ioctl(CasSession session, const char *in_json, char *out_json, uint32_t out_len);
static char *aml_get_version(void);

const struct AM_CA_Impl_t cas_ops =
{
.pre_init = aml_pre_init,
.init = aml_init,
.term = aml_term,
.isSystemIdSupported = aml_isSystemIdSupported,
.open_session = aml_open_session,
.close_session = aml_close_session,
.start_descrambling = aml_start_descrambling,
.stop_descrambling = aml_stop_descrambling,
.ioctl = aml_ioctl,
.get_version = aml_get_version
};

//#define CLEAR_CW_TEST

#define CA_SYSTEM_ID 0x3000
#ifdef CLEAR_CW_TEST
static uint8_t CW[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
#else   //keyladder test
static uint8_t ECW[] =
  {0x6a, 0xce, 0x8d, 0xfc, 0x91, 0x63, 0x34, 0xd4, 0x64, 0xff, 0x48, 0xe8, 0xfd, 0xe7, 0x21, 0x77};
static uint8_t EK1[] =
  {0x7f, 0x1d, 0xbe, 0xeb, 0x14, 0xdc, 0xae, 0xd4, 0x37, 0x1b, 0xca, 0x09, 0x0e, 0xd0, 0x03, 0x0c};
static uint8_t EK2[] =
  {0x93, 0x1b, 0x86, 0xb4, 0x49, 0x91, 0xf0, 0xb3, 0xf4, 0xdf, 0x64, 0xd8, 0x8c, 0x64, 0x80, 0x27}; //with SCK0
  //{0x3E, 0x92, 0xAB, 0x16, 0xB3, 0x4E, 0x69, 0xD2, 0x31, 0xAC, 0xE6, 0x10, 0x2F, 0xCE, 0xD4, 0x28}; //with SCK1
  //{0x4B, 0xB8, 0xCB, 0x11, 0xC8, 0x9B, 0x62, 0xDC, 0x57, 0xAD, 0x4B, 0x51, 0x91, 0x01, 0x82, 0x41}; //with SCK2
  //{0xC0, 0x60, 0xA5, 0xC0, 0x89, 0xB2, 0xB4, 0xCF, 0x8A, 0x85, 0x0B, 0xA2, 0x88, 0x59, 0xBA, 0x3A}; //with SCK3
#endif

static int aml_pre_init(void)
{
    ca_init();
    return 0;
}

static int aml_init(CasHandle handle)
{
    int ret;
    ret = DESC_Init();
    CA_DEBUG(0, "desc init return %#x", ret);
    UNUSED(handle);
    return 0;
}

static int aml_term(CasHandle handle)
{
    DESC_Deinit();
    UNUSED(handle);
    return 0;
}

static int aml_isSystemIdSupported(int systemId)
{
    return (systemId == CA_SYSTEM_ID ? 1: 0);
}

static int aml_open_session(CasHandle handle, CasSession session)
{
    UNUSED(handle);
    AML_PrivateInfo_t *aml_priv_info = NULL;

    aml_priv_info = (AML_PrivateInfo_t *)malloc(sizeof(AML_PrivateInfo_t));
    if (aml_priv_info == NULL) {
        CA_DEBUG(0, "malloc error!");
        return -1;
    }
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

#ifdef CLEAR_CW_TEST
static int set_clear_cw(CasSession session)
{
    int i;
    int ret;
    AML_PrivateInfo_t *aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;

    for (i = 0; i < aml_priv_info->key_index_count; i++) {
        CA_DEBUG(0, "set clear cw, key_index[%d]", aml_priv_info->key_index[i]);
        ret = DESC_SetClearKey(
                aml_priv_info->key_index[i],
                CW,
                DSC_ALGO_CSA2,
                USER_TSN,
                8);
        CA_DEBUG(2, "SetClearKey return %#x", ret);
    }

    return 0;
}
#else
static int keyladder_run(CasSession session)
{
    int i;
    int ret;
    kl_run_conf_t kl_conf;
    AML_PrivateInfo_t *aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;

    for (i = 0; i < aml_priv_info->key_index_count; i++) {
        memset(&kl_conf, 0, sizeof(kl_conf));
        memcpy(kl_conf.ecw, ECW, 16);
        memcpy(kl_conf.ek1, EK1, 16);
        memcpy(kl_conf.ek2, EK2, 16);
        kl_conf.size = 16;
        kl_conf.module_id = 0xA5; //ETSI module id
        kl_conf.ladder_size = 3;
        kl_conf.kl_algo = KL_ALGO_AES;
        kl_conf.kte = aml_priv_info->key_index[i];
        kl_conf.kt_algo = DSC_ALGO_CSA2;
        kl_conf.user_id = USER_TSN;

        ret = DESC_Keyladder_Run(&kl_conf);
        CA_DEBUG(0, "run keyladder return %#x", ret);
    }

    return ret;
}
#endif

static int aml_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *service_info)
{
    int i;
    int ret;
    int dsc_algo = CA_ALGO_CSA2;
    int dsc_type = CA_DSC_COMMON_TYPE;
    uint32_t ca_index, key_index;

    AML_PrivateInfo_t *aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;;

    ret = DESC_AllocateKey(KEY_TYPE_ODD, &key_index);
    if (ret) {
        CA_DEBUG(2, "allocate kte failed %#x\n", ret);
        return ret;
    }
    aml_priv_info->key_index[aml_priv_info->key_index_count++] = key_index;

    ret = ca_open(service_info->dmx_dev);
    if (ret) {
        CA_DEBUG(2, "ca open failed %#x\n", ret);
        return ret;
    }

    for (i = 0; i < service_info->stream_num; i++) {
        ca_index = ca_alloc_chan(service_info->dmx_dev,
                service_info->stream_pids[i],
                dsc_algo, dsc_type);
        ca_set_key(service_info->dmx_dev, ca_index, CA_KEY_EVEN_TYPE, key_index);
        ca_set_key(service_info->dmx_dev, ca_index, CA_KEY_ODD_TYPE, key_index);

        aml_priv_info->dsc_chan_count++;
        aml_priv_info->dsc_chan_handle[i] = ca_index;
        aml_priv_info->dmx_dev = service_info->dmx_dev;

        CA_DEBUG(0, "Associate  key_index[%d] to ca_index[%d] for es pid %#x",
            key_index, ca_index, service_info->stream_pids[i]);
    }

#ifdef CLEAR_CW_TEST
    set_clear_cw(session);
#else
    keyladder_run(session);
#endif

    return 0;
}

static int aml_stop_descrambling(CasSession session)
{
    int i;
    AML_PrivateInfo_t *aml_priv_info = ((CAS_SessionInfo_t *)session)->private_data;

    for (i = 0; i < aml_priv_info->dsc_chan_count; i++) {
        CA_DEBUG(0, "free ca_index[%d]", aml_priv_info->dsc_chan_handle[i]);
        ca_free_chan(aml_priv_info->dmx_dev, aml_priv_info->dsc_chan_handle[i]);
    }

    for (i = 0; i < aml_priv_info->key_index_count; i++) {
        CA_DEBUG(0, "free key_index[%d]", aml_priv_info->key_index[i]);
        DESC_FreeKey(aml_priv_info->key_index[i]);
    }

    return 0;
}

static int aml_ioctl(CasSession session, const char *in_json, char *out_json, uint32_t out_len)
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
