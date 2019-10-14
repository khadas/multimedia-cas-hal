#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <dlfcn.h>

#include "bc_consts.h"
#include "caclientapi.h"

#include "am_debug.h"
#include "am_cas.h"
#include "am_cas_internal.h"

#define DVR_SIZE (1024*1024)

#define SHM_R2R_MAGIC           0x00523252
#define SHM_R2R_TYPE_REE        0x01
#define SHM_R2R_TYPE_TEE        0x02
#define SHM_R2R_TYPE_SEC        0x03

#define USE_SECMEM
typedef struct {
       uint32_t magic;
       uint32_t type;
       uint8_t *paddr;
       uint8_t *vaddr;
       uint32_t size;
} shm_r2r_t;

typedef struct {
    int service_index;
    int dsc_svc_handle;
    int dsc_chan_handle[MAX_CHAN_COUNT];
    int dsc_chan_count;
    uint8_t *dvr_shm;
    uint8_t dvr_channelid;

    void *secmem_session;
    uint8_t *secmem_buf;
}VMX_PrivateInfo_t;

enum {
  SECMEM_SOURCE_NONE = 0,
  SECMEM_SOURCE_VDEC,
  SECMEM_SOURCE_CODEC_MM
};

typedef struct vmx_svc_idx {
    int used;
}vmx_svc_idx_t;

typedef struct vmx_dvr_channelid {
    int used;
}vmx_dvr_channelid_t;

struct AM_CA_Impl_t * get_cas_ops(void);
static int vmx_pre_init(void);
static int vmx_init(CasHandle handle);
static int vmx_term(CasHandle handle);
static int vmx_isSystemId_supported(int CA_system_id);
static int vmx_open_session(CasHandle handle, CasSession session);
static int vmx_close_session(CasSession session);
static int vmx_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo);
static int vmx_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);
static int vmx_stop_descrambling(CasSession session);
static int vmx_set_emm_pid(CasHandle handle, uint16_t emmPid);
static int vmx_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info, AM_CA_PrivateInfo_t *info);
static int vmx_dvr_stop(CasSession session);
static int vmx_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara, AM_CA_StoreInfo_t *storeInfo);
static int vmx_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_replay(CasSession session, AM_CA_StoreInfo_t *storeInfo, AM_CA_PrivateInfo_t *info);
static int vmx_dvr_stop_replay(CasSession session);
static int vmx_get_securebuf(uint8_t **buf, uint32_t len);

static void *sec_mem_handle = NULL;
/*Sec mem V2, open once session can only alloc once mem, no free API, close session will free it*/
typedef uint32_t (*def_secmem_init_session)(void *session, uint32_t source,
  uint32_t flags, uint32_t paddr, uint32_t msize);
typedef uint32_t (*def_secmem_create_session)(void **session);
typedef uint32_t (*def_secmem_destroy_session)(void **session);
typedef uint32_t (*def_secmem_alloc)(void *session, uint32_t *addr, uint32_t *size);
static def_secmem_init_session secmem_init_session = NULL;
static def_secmem_create_session secmem_create_session = NULL;
static def_secmem_destroy_session secmem_destroy_session = NULL;
static def_secmem_alloc secmem_alloc = NULL;

const struct AM_CA_Impl_t vmx_cas_ops =
{
.pre_init = vmx_pre_init,
.init = vmx_init,
.term = vmx_term,
.isSystemIdSupported = vmx_isSystemId_supported,
.open_session = vmx_open_session,
.close_session = vmx_close_session,
.start_descrambling = vmx_start_descrambling,
.update_descrambling_pid = vmx_update_descrambling_pid,
.stop_descrambling = vmx_stop_descrambling,
.set_emm_pid = vmx_set_emm_pid,
.dvr_start = vmx_dvr_start,
.dvr_stop = vmx_dvr_stop,
.dvr_encrypt = vmx_dvr_encrypt,
.dvr_decrypt = vmx_dvr_decrypt,
.dvr_replay = vmx_dvr_replay,
.dvr_stop_replay = vmx_dvr_stop_replay,
.get_securebuf = vmx_get_securebuf
};

static uint8_t *g_dvr_shm = NULL;
static vmx_svc_idx_t g_svc_idx[MAX_CHAN_COUNT];
static vmx_dvr_channelid_t g_dvr_channelid[MAX_CHAN_COUNT];
static pthread_t bcThread = ( pthread_t )NULL;
static pthread_mutex_t vmx_bc_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

struct AM_CA_Impl_t * get_cas_ops(void)
{
    return &vmx_cas_ops;
}

static int alloc_service_idx(void)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (!g_svc_idx[i].used) {
	    AM_DEBUG(0, "allocated vmx svc idx %d", i);
	    g_svc_idx[i].used = 1;
	    return i;
	}
    }

    AM_DEBUG(2, "alloc vmx svc idx failed.");
    return -1;
}

static void free_service_idx(int idx)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (g_svc_idx[i].used && (i == idx)) {
	    AM_DEBUG(0, "freed vmx svc idx %d", i);
	    g_svc_idx[i].used = 0;
	    return;
	}
    }

    AM_DEBUG(0, "free vmx svc idx failed.");
}

static int alloc_dvr_channelid(void)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (!g_dvr_channelid[i].used) {
	    AM_DEBUG(0, "allocated dvr channelid %d", i);
	    g_dvr_channelid[i].used = 1;
	    return i;
	}
    }

    AM_DEBUG(0, "alloc dvr channelid failed.");
    return -1;
}

static void free_dvr_channelid(int id)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (g_dvr_channelid[i].used && (i == id)) {
	    AM_DEBUG(0, "freed dvr channelid %d", i);
	    g_dvr_channelid[i].used = 0;
	    break;
	}
    }

    AM_DEBUG(2, "free dvr channelid failed.");
}

static int get_dvbsi_time( time_t timeseconds, uint8_t dvbtime[5] )
{
    int mjd;
    struct tm tm;
    gmtime_r( &timeseconds, &tm );
    mjd = ( timeseconds / 86400 ) + 40587;
    dvbtime[0] = ( mjd & 0xff00 ) >> 8;
    dvbtime[1] = mjd & 0xff;
    dvbtime[2] = (tm.tm_hour / 10) * 16 + (tm.tm_hour % 10);
    dvbtime[3] = (tm.tm_min / 10) * 16 + (tm.tm_min % 10);
    dvbtime[4] = (tm.tm_sec / 10) * 16 + (tm.tm_sec % 10);
    return 0;
}

void vmx_bc_lock(void)
{
    int e = pthread_mutex_lock(&vmx_bc_mutex);
    if (e) {
        CA_DEBUG(0, "pthread_mutex_lock: %s", strerror(e));
    }
}

void vmx_bc_unlock(void)
{
    int e = pthread_mutex_unlock(&vmx_bc_mutex);
    if (e) {
        CA_DEBUG(0, "pthread_mutex_lock: %s", strerror(e));
    }
}

static void *bcHandlingThread(void *pParam)
{
    CA_DEBUG( 0, "BC thread is called\n" );
    while ( 1 ) {
        vmx_bc_lock();
        BC_Task();
        vmx_bc_unlock();
        usleep( 10 * 1000 ); /* in mill sec */
    }
    return NULL;
}

static void print_scinfo(void)
{
    uint8_t ser[35] = {0};
    uint16_t serlen = sizeof(ser);
    int16_t bcret;

    vmx_bc_lock();
    bcret = BC_CheckNSc();
    vmx_bc_unlock();
    CA_DEBUG(0, "\nBC_CheckNSc ret=%d, %s\n",
        bcret,
        bcret == k_BcSuccess ?
            "NSc implementation exists and stb is individualized" :
            bcret == k_BcError ?
                "NSc implementation exists but stb is not individualized" :
                "NSc implementation does not exist"
            );
    vmx_bc_lock();
    bcret = BC_GetSCNo(ser, serlen);
    vmx_bc_unlock();
    CA_DEBUG(0, "BC_GetSCNo ret=%d, serial number:%s\n\n", bcret, ser );
}

static int vmx_pre_init(void)
{
    int16_t bcRet;
    uint8_t version[32];
    uint8_t date[20];
    uint8_t timestr[20];

    CA_init();
    vmx_port_init();

    vmx_bc_lock();
    bcRet = BC_Init();
    vmx_bc_unlock();
    CA_DEBUG(0, "BC-Init: %04x\n", (uint16_t)bcRet);

    vmx_bc_lock();
    BC_GetVersion(version, date, timestr );
    vmx_bc_unlock();
    CA_DEBUG(0, "ver %s %s %s\n", version, date, timestr);

    BC_InitWindow(1920, 1080, NULL);

    pthread_create( &bcThread, NULL, bcHandlingThread, NULL );
    print_scinfo();

    return 0;
}

static int vmx_init(CasHandle handle)
{
    uint8_t *buf = NULL;
    uint8_t tmp_buf[32] = {0};
    static uint8_t *live_secmem_session = NULL;
    static uint8_t *dvr_secmem_session = NULL;
    uint32_t secmem_size = DVR_SIZE;

    CA_DEBUG(0, "%s", __func__);

    g_dvr_shm = (uint8_t *)ree_shm_alloc(DVR_SIZE);
    memset(g_svc_idx, 0, sizeof(vmx_svc_idx_t)*MAX_CHAN_COUNT);

#ifdef USE_SECMEM //for secmem lib
    if (CA_GetSecureBuffer(&buf, DVR_SIZE)) {
	CA_DEBUG(0, "CA get secure buffer failed");
	return -1;
    }
    ((CAS_CasInfo_t *)handle)->secure_buf = buf;

    sec_mem_handle = dlopen("libsecmem.so", RTLD_NOW);
    if (!sec_mem_handle) {
        CA_DEBUG(0, "%s, failed to open libsecmem %s\n", __func__, dlerror());
        return -1;
    } else {
        CA_DEBUG(0, "%s, open lib secmem success\n", __func__);

        secmem_init_session = (def_secmem_init_session)dlsym(sec_mem_handle, "Secure_V2_Init");
        if (!secmem_init_session) {
            CA_DEBUG(0, "%s, failed to get secmem_init_session\n", __func__);
            dlclose(sec_mem_handle);
            return -1;
        }
        secmem_create_session = (def_secmem_create_session)dlsym(sec_mem_handle, "Secure_V2_SessionCreate");
        if (!secmem_create_session) {
            CA_DEBUG(0, "%s, failed to get secmem_create_session\n", __func__);
            dlclose(sec_mem_handle);
            return -1;
        }
        secmem_destroy_session = (def_secmem_destroy_session)dlsym(sec_mem_handle, "Secure_V2_SessionDestroy");
        if (!secmem_destroy_session) {
            CA_DEBUG(0, "%s, failed to get secmem_destroy_session\n", __func__);
            dlclose(sec_mem_handle);
            return -1;
        }
        secmem_alloc = (def_secmem_alloc)dlsym(sec_mem_handle, "Secure_V2_ResourceAlloc");
        if (!secmem_alloc) {
            CA_DEBUG("%s, failed to get secmem_alloc\n", __func__);
            dlclose(sec_mem_handle);
            return -1;
        }
        CA_DEBUG("%s, secmem Init success\n", __func__);
    }

    //to protect vdec buffer
    if (secmem_create_session(&live_secmem_session)){
	CA_DEBUG(0, "Create basic secmem session failed.");
    } else {
	if (secmem_init_session(live_secmem_session, SECMEM_SOURCE_VDEC, 0x1, 0, 0)) {
	    CA_DEBUG(0, "Init basic secmem session failed.");
	}
    }

    //to alloc secmem for asyncfifo buffer
    if (secmem_create_session(&dvr_secmem_session)) {
	CA_DEBUG(0, "Create dvr secmem session failed.");
	return -1;
    }
    if (secmem_init_session(dvr_secmem_session, SECMEM_SOURCE_VDEC, 0x100, 0, 0)) {
	CA_DEBUG(0, "Init dvr secmem session failed");
	secmem_destroy_session(&dvr_secmem_session);
	return -1;
    }
    if (secmem_alloc(dvr_secmem_session, &buf, &secmem_size)) {
	CA_DEBUG(0, "Alloc dvr secmem buffer failed");
	secmem_destroy_session(&dvr_secmem_session);
	return -1;
    }

    sprintf(tmp_buf, "%d", buf);
    AM_FileEcho("/sys/class/stb/asyncfifo0_secure_enable", "1");
    AM_FileEcho("/sys/class/stb/asyncfifo0_secure_addr", tmp_buf);

    buf += 512*1024;
    sprintf(tmp_buf, "%d", buf);
    AM_FileEcho("/sys/class/stb/asyncfifo1_secure_enable", "1");
    AM_FileEcho("/sys/class/stb/asyncfifo1_secure_addr", tmp_buf);

    AM_FileEcho( "/sys/class/stb/demux_reset", "1");
#else
    if (CA_GetSecureBuffer(&buf, DVR_SIZE)) {
	CA_DEBUG(0, "CA get secure buffer failed");
	return -1;
    }

    sprintf(tmp_buf, "%d", buf);
    AM_FileEcho("/sys/class/stb/asyncfifo0_secure_enable", "1");
    AM_FileEcho("/sys/class/stb/asyncfifo0_secure_addr", tmp_buf);
    AM_FileEcho( "/sys/class/stb/demux_reset", "1");

    ((CAS_CasInfo_t *)handle)->secure_buf = buf;
#endif

    return 0;
}

static int vmx_term(CasHandle handle)
{
    CA_uninit();
    vmx_port_deinit();
    pthread_join(bcThread, NULL);

    return 0;
}

static int vmx_isSystemId_supported(int CA_system_id)
{
    CA_DEBUG(0, "CA_system_id[%#x]", CA_system_id);
    vmx_bc_lock();
    if (BC_Get_CASystemID() != CA_system_id){
	CA_DEBUG(0, "not supported CA_system_id[%#x], VMX systemID is %#x",
		CA_system_id, BC_Get_CASystemID());
	vmx_bc_unlock();
    	return 0;
    }
    vmx_bc_unlock();

    return 1;
}

static int vmx_open_session(CasHandle handle, CasSession session)
{
    int ret;
    int dsc_svc_handle;
    VMX_PrivateInfo_t *vmx_pri_info = NULL;

    ret = CA_OpenService(&dsc_svc_handle);
    if (ret) {
	CA_DEBUG(2, "CA_OpenService failed %d", ret);
	return -1;
    }

    vmx_pri_info = (VMX_PrivateInfo_t *)malloc(sizeof(VMX_PrivateInfo_t));
    memset((void *)vmx_pri_info, 0x0, sizeof(VMX_PrivateInfo_t));
    vmx_pri_info->dsc_svc_handle = dsc_svc_handle;
    vmx_pri_info->dvr_channelid = -1;
    ((CAS_SessionInfo_t *)session)->private_data = vmx_pri_info;

    return 0;
}

static int vmx_close_session(CasSession session)
{
    VMX_PrivateInfo_t *private_data = NULL;

    private_data = ((CAS_SessionInfo_t *)session)->private_data;
    CA_CloseService(private_data->dsc_svc_handle);
    free(private_data);
    ((CAS_SessionInfo_t *)session)->private_data = NULL;

    return 0;
}

static int vmx_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo)
{
    uint8_t *p;
    int i, ret;
    int dsc_chan_handle = 0;
    ca_service_info_t ca_svc_info;
    VMX_PrivateInfo_t *vmx_pri_info = NULL;

    uint16_t ecmPid[MAX_CHAN_COUNT];
    uint16_t streamPid[MAX_CHAN_COUNT];

    vmx_pri_info = ((CAS_SessionInfo_t *)session)->private_data;
    memcpy(&(((CAS_SessionInfo_t *)session)->service_info), (void *)serviceInfo, sizeof(AM_CA_ServiceInfo_t));
    memset(&ca_svc_info, 0x0, sizeof(ca_service_info_t));
    for (i = 0; i < serviceInfo->stream_num; i++) {
	ret = CA_DscOpen(serviceInfo->dsc_dev, &dsc_chan_handle);
	if (!ret) {
	    CA_DscSetPid(serviceInfo->dsc_dev, dsc_chan_handle, serviceInfo->stream_pids[i]);
	    ca_svc_info.channel[i] = dsc_chan_handle;
	    vmx_pri_info->dsc_chan_count++;
	    vmx_pri_info->dsc_chan_handle[i] = dsc_chan_handle;
	}

	ca_svc_info.pid[i] = serviceInfo->stream_pids[i];
    }

    ca_svc_info.service_index = alloc_service_idx();
    ca_svc_info.service_type = SERVICE_PLAY;
    ca_svc_info.dsc_dev_no = serviceInfo->dsc_dev;
    ca_svc_info.dvr_dev_no = serviceInfo->dvr_dev;
    ca_svc_info.stream_num = serviceInfo->stream_num;
    ca_svc_info.algo = SCRAMBLE_ALGO_CSA;

    vmx_pri_info->service_index = ca_svc_info.service_index;

    p = serviceInfo->ca_private_data;
    if (serviceInfo->ca_private_data_len > 0) {
        if (((p[0] & 0xE0) >> 5) == 1) {
            ca_svc_info.algo = SCRAMBLE_ALGO_AES;
	    if (((p[0] & 0x8) >> 3) == 0) {
		ca_svc_info.mode = SCRAMBLE_MODE_ECB;
	    } else {
		ca_svc_info.mode = SCRAMBLE_MODE_CBC;
	    }
	    ca_svc_info.alignment = ((p[0] & 0x4) >> 2);
	    CA_DEBUG(0, "found Algo-AES, Mode-%d", ca_svc_info.mode);
	}
    }
    CA_SetServiceInfo(vmx_pri_info->dsc_svc_handle, &ca_svc_info);

    vmx_bc_lock();
    for (i = 0; i < serviceInfo->stream_num; i++) {
	ecmPid[i] = serviceInfo->ecm_pid;
	streamPid[i] = serviceInfo->stream_pids[i];
    }
    CA_DEBUG(0, "Start Descrambling[%d] [%d %d %#x %#x %#x %d]", \
		serviceInfo->dsc_dev, serviceInfo->service_id, serviceInfo->stream_num, \
		ecmPid[0], streamPid[0], streamPid[1], vmx_pri_info->service_index);
    BC_StartDescrambling(serviceInfo->service_id, serviceInfo->stream_num, \
	&ecmPid[0], &streamPid[0], vmx_pri_info->service_index);
    vmx_bc_unlock();
    return 0;
}

static int vmx_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid)
{
    //TODO: support audio track select
    return 0;
}

static int vmx_stop_descrambling(CasSession session)
{
    int i, ret;
    uint16_t svc_id;
    VMX_PrivateInfo_t *private_data;

    vmx_bc_lock();
    svc_id = ((CAS_SessionInfo_t *)session)->service_info.service_id;
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    if (!private_data) {
	CA_DEBUG(2, "Stop Descrambling failed, no session private data.");
	vmx_bc_unlock();
	return -1;
    }

    ret = BC_StopDescrambling(svc_id, private_data->service_index);
    CA_DEBUG(0, "BC_StopDescrambling ret[%d] (%#x, %#x).", ret, svc_id, private_data->service_index);
    for (i = 0; i < private_data->dsc_chan_count; i++) {
	ret = CA_DscClose(((CAS_SessionInfo_t *)session)->service_info.dsc_dev, private_data->dsc_chan_handle[i]);
	if (ret) {
	    CA_DEBUG(2, "CA_DscClose failed[%d].", ret);
	} else {
	    CA_DEBUG(0, "CA_DscClose fd[%d].", private_data->dsc_chan_handle[i]);
	}
    }

    free_service_idx(private_data->service_index);

    vmx_bc_unlock();

    return 0;
}

static int vmx_set_emm_pid(CasHandle handle, uint16_t emmPid)
{
    vmx_bc_lock();
    BC_SetEMM_Pid(emmPid);
    vmx_bc_unlock();

    return 0;
}

static int vmx_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info, AM_CA_PrivateInfo_t *info)
{
    int ret;
    uint16_t rc;
    uint8_t dvbtime[5], channelid;
    VMX_PrivateInfo_t *private_data;

    if (info == NULL) {
	CA_DEBUG(1, "no private info for DVR start");
	return -1;
    }

    ret = vmx_start_descrambling(session, service_info);
    if (ret) {
	CA_DEBUG(2, "Start descrambling for DVR failed");
	return -1;
    }

    vmx_bc_lock();
    BC_Task();
    vmx_bc_unlock();
    vmx_bc_lock();
    BC_Task();
    vmx_bc_unlock();

    get_dvbsi_time(time(NULL), dvbtime);

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    if (private_data && (private_data->dvr_shm == NULL)) {
	private_data->dvr_shm = g_dvr_shm;
    }

    channelid = alloc_dvr_channelid();
    private_data->dvr_channelid = channelid;
    CA_DEBUG(0, "CAS DVR record [%#x %#x %#x], shm[%#x]", private_data->service_index,
		channelid, info->infoLen, g_dvr_shm);
    rc = BC_DVRRecord(private_data->service_index, channelid, info->info, info->infoLen, dvbtime);
    vmx_bc_unlock();
    if (rc != k_BcSuccess) {
	CA_DEBUG(2, "BC_DVRRecord faild, rc = %d", rc);
	vmx_stop_descrambling(session);
    }

    return 0;
}

static int vmx_dvr_stop(CasSession session)
{
    int ret;
    uint8_t channelid;
    VMX_PrivateInfo_t * private_data;

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;

    channelid = private_data->dvr_channelid;
    CA_DEBUG(0, "CAS DVR[%d] Stop", channelid);
    ret = BC_DVRStop(channelid);
    if (ret) {
	CA_DEBUG(0, "BC_DVRStop failed, rc = %d", ret);
	vmx_bc_unlock();
	return -1;
    }

    free_dvr_channelid(channelid);

    if (private_data && private_data->dvr_shm) {
	private_data->dvr_shm = NULL;
    }

    ret = vmx_stop_descrambling(session);
    if (ret) {
	CA_DEBUG(2, "Stop descrambling for DVR failed");
	vmx_bc_unlock();
	return -1;
    }

    vmx_bc_unlock();
    return 0;
}

static int vmx_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara, AM_CA_StoreInfo_t *storeInfo)
{
    uint16_t rc;
    uint8_t channelid;
    VMX_PrivateInfo_t * private_data;
    shm_r2r_t shm_in, shm_out;

    if (storeInfo == NULL) {
       CA_DEBUG(2, "invalid param for dvr encryption");
       return -1;
    }

    if (cryptoPara->buf_len > DVR_SIZE) {
       CA_DEBUG(2, "encrypt buffer overflow DVR_SIZE");
       return -1;
    }

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    CA_update_afifo_pos(cryptoPara->buf_in);

    memset(&shm_in, 0x0, sizeof(shm_r2r_t));
    shm_in.magic = SHM_R2R_MAGIC;
    shm_in.type = SHM_R2R_TYPE_SEC;
    shm_in.paddr = cryptoPara->buf_in;
    shm_in.size = cryptoPara->buf_len;

    memset(&shm_out, 0x0, sizeof(shm_r2r_t));
    shm_out.magic = SHM_R2R_MAGIC;
    shm_out.type = SHM_R2R_TYPE_REE;
    shm_out.vaddr = private_data->dvr_shm;
    shm_out.size = cryptoPara->buf_len;

    channelid = private_data->dvr_channelid;
    storeInfo->actualStoreInfoLen = MAX_STOREINFO_LEN;

    CA_DEBUG(0, "CAS DVR Encrypt[%d] (%#x, %#x, %#x)",
		channelid, shm_in.paddr, shm_out.vaddr, shm_in.size);
    vmx_bc_unlock();

    rc = BC_DVREncrypt(channelid, (uint8_t *)&shm_out,
		(uint8_t *)&shm_in, sizeof(shm_r2r_t),
		storeInfo->storeInfo, &storeInfo->actualStoreInfoLen);
    if (rc != k_BcSuccess) {
	CA_DEBUG(0, "BC_DVREncrypt failed, rc = %d", rc);
	storeInfo->actualStoreInfoLen = 0;
    }

    CA_DEBUG(0, "hanyh: store len = %d", storeInfo->actualStoreInfoLen);
    ree_shm_update_tee(shm_out.vaddr, shm_out.size);
    memcpy(cryptoPara->buf_out, shm_out.vaddr, shm_out.size);
    cryptoPara->buf_type = 0;
    vmx_bc_unlock();

    return 0;
}

static int vmx_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    uint16_t rc;
    shm_r2r_t shm_in, shm_out;
    VMX_PrivateInfo_t * private_data;

    if (cryptoPara->buf_len > DVR_SIZE) {
	CA_DEBUG(2, "decrypt buffer overflow DVR_SIZE");
	return -1;
    }

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    memcpy(private_data->dvr_shm, cryptoPara->buf_in, cryptoPara->buf_len);
    memset(&shm_in, 0x0, sizeof(shm_r2r_t));
    shm_in.magic = SHM_R2R_MAGIC;
    shm_in.type = SHM_R2R_TYPE_REE;
    shm_in.vaddr = private_data->dvr_shm;
    shm_in.size = cryptoPara->buf_len;

    memset(&shm_out, 0x0, sizeof(shm_r2r_t));
    shm_out.magic = SHM_R2R_MAGIC;
    shm_out.type = SHM_R2R_TYPE_SEC;
#ifdef USE_SECMEM //for secmem lib
    shm_out.paddr = private_data->secmem_buf;
#else
    shm_out.paddr = ((CAS_CasInfo_t *)((CAS_SessionInfo_t *)session)->cas_handle)->secure_buf + 0x400000;
#endif
    shm_out.size = cryptoPara->buf_len;

    ree_shm_update_ree(shm_in.paddr, shm_in.size);
    rc = BC_DVRDecrypt(private_data->dvr_channelid,
		(uint8_t *)&shm_out, (uint8_t *)&shm_in,
		sizeof(shm_r2r_t));
    cryptoPara->buf_type = 1;
    cryptoPara->buf_out = shm_out.paddr;

    if(rc != k_BcSuccess) {
	CA_DEBUG(0, "BC_DVRDecrypt failed, rc = %d", rc);
	vmx_bc_unlock();
	return -1;
    }

    vmx_bc_unlock();

    return 0;
}

static int vmx_dvr_replay(CasSession session, AM_CA_StoreInfo_t *storeInfo, AM_CA_PrivateInfo_t *info)
{
    uint16_t rc;
    uint8_t *buf = NULL;
    void *secmem_session = NULL;
    uint32_t secmem_size = DVR_SIZE;
    uint8_t dvbtime[5];
    ca_service_info_t ca_svc_info;
    VMX_PrivateInfo_t *private_data;

    if ((storeInfo == NULL) || (info == NULL)) {
	CA_DEBUG(2, "invalid storeInfo or private info for DVR replay");
	return -1;
    }

    vmx_bc_lock();
    get_dvbsi_time(time(NULL), dvbtime);
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    if (private_data == NULL) {
	CA_DEBUG(2, "error, not open session");
	vmx_bc_unlock();
	return -1;
    }

#ifdef USE_SECMEM //for secmem lib
    //to alloc secmem for decryption output buffer
    if (secmem_create_session(&secmem_session)) {
	CA_DEBUG(0, "Create decryption secmem session failed.");
	vmx_bc_unlock();
	return -1;
    }
    if (secmem_init_session(secmem_session, SECMEM_SOURCE_VDEC, 0x101, 0, 0)) {
	CA_DEBUG(0, "Init decryption secmem session failed");
	secmem_destroy_session(&secmem_session);
	vmx_bc_unlock();
	return -1;
    }
    if (secmem_alloc(secmem_session, &buf, &secmem_size)) {
	CA_DEBUG(0, "Alloc decryption secmem buffer failed");
	secmem_destroy_session(&secmem_session);
	vmx_bc_unlock();
	return -1;
    }
    private_data->secmem_session = secmem_session;
    private_data->secmem_buf = buf;
#endif

    private_data->dvr_shm = g_dvr_shm;
    private_data->dvr_channelid = alloc_dvr_channelid();

    memset(&ca_svc_info, 0x0, sizeof(ca_service_info_t));
    ca_svc_info.service_index = private_data->dvr_channelid | 0x80;
    ca_svc_info.algo = SCRAMBLE_ALGO_NONE;
    ca_svc_info.mode = SCRAMBLE_MODE_CBC;
    ca_svc_info.alignment = SCRAMBLE_ALIGNMENT_LEFT;
    CA_SetServiceInfo(private_data->dsc_svc_handle, &ca_svc_info);

    if (info->infoLen == 0) {
	info->infoLen = sizeof(info->info);
	memset(info->info, 0, sizeof(info->info));
    }

#if 0
    {
	int i;
	for (i = 0; i < storeInfo->actualStoreInfoLen; i+=8) {
	    CA_DEBUG(0, "%02x %02x %02x %02x %02x %02x %02x %02x", storeInfo->storeInfo[i], 
		storeInfo->storeInfo[i+1], storeInfo->storeInfo[i+2], storeInfo->storeInfo[i+3],
		storeInfo->storeInfo[i+4], storeInfo->storeInfo[i+5], storeInfo->storeInfo[i+6], storeInfo->storeInfo[i+7]);
	}
    }
#endif

    rc = BC_DVRReplay(private_data->dvr_channelid, info->info,
		info->infoLen, storeInfo->storeInfo,
		storeInfo->actualStoreInfoLen, dvbtime);

    CA_DEBUG(0, "CAS Replay start(%d, %d, %#x, %#x), shm[%#x]", 
	private_data->dvr_channelid, ca_svc_info.service_index,
	info->infoLen, storeInfo->actualStoreInfoLen, private_data->dvr_shm);

    if (rc != k_BcSuccess) {
	CA_DEBUG(0, "BC_DVRReplay failed, rc = %d", rc);
	free_dvr_channelid(private_data->dvr_channelid);
	vmx_bc_unlock();
	return -1;
    }

    vmx_bc_unlock();

    return 0;
}

static int vmx_dvr_stop_replay(CasSession session)
{
    int ret;
    uint8_t channelid;
    VMX_PrivateInfo_t *private_data;

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    channelid = private_data->dvr_channelid;

    CA_DEBUG(0, "CAS DVR Replay[%d] stopped.", channelid);
    ret = BC_DVRStop(channelid);
    if (ret) {
	CA_DEBUG(0, "BC_DVRStop failed, rc = %d", ret);
	vmx_bc_unlock();
	return -1;
    }

    if (private_data && private_data->dvr_shm) {
	private_data->dvr_shm = NULL;
    }

#ifdef USE_SECMEM //for secmem lib
    if (private_data->secmem_session) {
	secmem_destroy_session(&private_data->secmem_session);
	private_data->secmem_session = NULL;
	private_data->secmem_buf = NULL;
    }
#endif

    free_dvr_channelid(channelid);

    vmx_bc_unlock();

    return 0;
}

static int vmx_get_securebuf(uint8_t **buf, uint32_t len) {
    return CA_GetSecureBuffer(buf, len);
}
