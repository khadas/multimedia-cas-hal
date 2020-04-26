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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/un.h>
#include <list.h>

#include "bc_consts.h"
#include "bc_main.h"
#include "caclientapi.h"
#include "am_cas.h"
#include "am_cas_internal.h"

#define DVR_SIZE (1024*1024)
#define MAX_STOREINFO_LEN (1024)

#define SHM_R2R_MAGIC           0x00523252
#define SHM_R2R_TYPE_REE        0x01
#define SHM_R2R_TYPE_TEE        0x02
#define SHM_R2R_TYPE_SEC        0x03
#define VMX_MAGIC_NUM           0xBEEFBEEF
#define NODE_IS_REWIND(p) \
    (p->end <= p->start ? 1 : 0)

typedef struct {
       uint32_t magic;
       uint32_t type;
       uint8_t *paddr;
       uint8_t *vaddr;
       uint32_t size;
} shm_r2r_t;

typedef struct vmx_svc_idx {
    int used;
    CasSession session;
}vmx_svc_idx_t;

typedef struct vmx_dvr_channelid {
    int used;
}vmx_dvr_channelid_t;

typedef struct {
	uint8_t info[16];
	uint32_t len;
}vmx_recinfo_t;

typedef struct {
	uint8_t info[MAX_STOREINFO_LEN];
	uint32_t len;
}vmx_storeinfo_t;

typedef struct
{
    struct list_head list;
    uint64_t start;
    uint64_t end;
    uint32_t info_len;
    uint8_t *info_data;
} vmx_crypto_storeinfo_t;

typedef struct {
    int dmx_dev;
    int service_index;
    int dsc_svc_handle;
    int dsc_chan_handle[MAX_CHAN_COUNT];
    int dsc_chan_count;
    uint8_t *dvr_shm;
    uint8_t dvr_channelid;

    int dvr_dev;
    FILE *dat_fp;
    int segment_id;
    vmx_crypto_storeinfo_t storeinfo_ctx;
}VMX_PrivateInfo_t;

typedef struct {
    void *session;
    void *secbuf;
}secmem_handle_t;

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
static int vmx_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info);
static int vmx_dvr_stop(CasSession session);
static int vmx_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_stop_replay(CasSession session);
static SecMemHandle vmx_create_secmem(CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size);
static int vmx_destroy_secmem(SecMemHandle handle);
static int vmx_file_echo(const char *name, const char *cmd);
static int vmx_get_fname(char fname[MAX_LOCATION_SIZE],
    const char location[MAX_LOCATION_SIZE],
    uint64_t segment_id);

/*Sec mem V2, open once session can only alloc once mem, no free API, close session will free it*/
extern uint32_t Secure_V2_Init(void *session, uint32_t source,
  uint32_t flags, uint32_t paddr, uint32_t msize);
extern uint32_t Secure_V2_SessionCreate(void **session);
extern uint32_t Secure_V2_SessionDestroy(void **session);
extern uint32_t Secure_V2_ResourceAlloc(void *session, uint32_t *addr, uint32_t *size);
enum {
    SECMEM_SOURCE_NONE = 0,
    SECMEM_SOURCE_VDEC,
    SECMEM_SOURCE_CODEC_MM
};

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
.create_secmem = vmx_create_secmem,
.destroy_secmem = vmx_destroy_secmem
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

int vmx_file_echo(const char *name, const char *cmd)
{
    int fd, ret, len;
    fd = open(name, O_WRONLY);
    if(fd==-1)
    {
        CA_DEBUG(1, "cannot open file \"%s\"", name);
        return -1;
    }

    len = strlen(cmd);

    ret = write(fd, cmd, len);
    if(ret!=len)
    {
        CA_DEBUG(1, "write failed file:\"%s\" cmd:\"%s\" error:\"%s\"", name, cmd, strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int vmx_get_fname(char fname[MAX_LOCATION_SIZE],
    const char location[MAX_LOCATION_SIZE],
    uint64_t segment_id)
{
    int offset;

    memset(fname, 0, MAX_LOCATION_SIZE);
    strncpy(fname, location, strlen(location));
    offset = strlen(location);
    strncpy(fname + offset, "-", 1);
    offset += 1;
    sprintf(fname + offset, "%04llu", segment_id);
    offset += 4;
    strncpy(fname + offset, ".vmx.dat", 8);

    return 0;
}

static int vmx_parser_storeinfo(FILE *dat_fp,
    vmx_crypto_storeinfo_t *storeinfo_ctx)
{
    loff_t offset;
    uint32_t infolen;
    vmx_crypto_storeinfo_t *pstoreinfo;

    INIT_LIST_HEAD(&storeinfo_ctx->list);

    do {
        if(fread(&offset, sizeof(offset), 1, dat_fp) != 1) {
            break;
        }
        if (fread(&infolen, sizeof(infolen), 1, dat_fp) != 1) {
            break;
        }
        CA_DEBUG(0, "find vmx store info len:%#x, offset:%lld",
                infolen, offset);
        pstoreinfo = malloc(sizeof(vmx_crypto_storeinfo_t));
        pstoreinfo->info_data = malloc(infolen);
        pstoreinfo->info_len = infolen;
        pstoreinfo->start = offset;
        pstoreinfo->end = VMX_MAGIC_NUM;
        if (fread(pstoreinfo->info_data, 1, infolen, dat_fp) != infolen) {
            break;
        }
        list_add_tail(&pstoreinfo->list, &storeinfo_ctx->list);
    } while(1);

    CA_DEBUG(0, "%s done.", __func__);
    return 0;
}

static int vmx_get_storeinfo(
    vmx_crypto_storeinfo_t *storeinfo_ctx,
    loff_t offset,
    vmx_storeinfo_t *sinfo)
{
    struct list_head *pos, *q;
    vmx_crypto_storeinfo_t *pstoreinfo;

    list_for_each_safe(pos, q, &storeinfo_ctx->list) {
        pstoreinfo = list_entry(pos, vmx_crypto_storeinfo_t, list);
        if (NODE_IS_REWIND(pstoreinfo)) {
            if (offset > pstoreinfo->start || offset >= pstoreinfo->end) {
                sinfo->len = pstoreinfo->info_len;
                memcpy(sinfo->info, pstoreinfo->info_data, pstoreinfo->info_len);
                CA_DEBUG(0, "found revind store info, offset:%d, len:%#x",
                    pstoreinfo->start, pstoreinfo->info_len);
                return 0;
            }
        } else {
            if (offset > pstoreinfo->start && offset <= pstoreinfo->end) {
                sinfo->len = pstoreinfo->info_len;
                memcpy(sinfo->info, pstoreinfo->info_data, pstoreinfo->info_len);
                CA_DEBUG(0, "found store info, offset:%lld, len:%#x",
                    pstoreinfo->start, pstoreinfo->info_len);
                return 0;
            }
        }
    }

    CA_DEBUG(2, "found store info failed");
    return -1;
}

static int vmx_free_storeinfo(
    vmx_crypto_storeinfo_t *storeinfo_ctx)
{
    struct list_head *pos, *q;
    vmx_crypto_storeinfo_t *pstoreinfo;

    list_for_each_safe(pos, q, &storeinfo_ctx->list) {
        pstoreinfo = list_entry(pos, vmx_crypto_storeinfo_t, list);
        list_del(pos);
        free(pstoreinfo->info_data);
        free(pstoreinfo);
    }

    return 0;
}

static int create_secmem(void **session, uint32_t secmemflag,
        void **ppSecBuf, uint32_t size, uint32_t allocflag)
{
    if (Secure_V2_SessionCreate(session)) {
        CA_DEBUG(0, "Create secmem session (%#x) failed", secmemflag);
        return -1;
    }

    if (Secure_V2_Init(*session, SECMEM_SOURCE_VDEC, secmemflag, 0, 0)) {
        Secure_V2_SessionDestroy(session);
        CA_DEBUG(0, "Init secmem session(%#x) failed.", secmemflag);
        return -1;
    }

    if (!allocflag) {
        return 0;
    }

    if (Secure_V2_ResourceAlloc(*session, ppSecBuf, &size)) {
        Secure_V2_SessionDestroy(session);
        return -1;
    }

    return 0;
}

static int destroy_secmem(void **session)
{
    int ret = -1;

    if (*session) {
       ret =  Secure_V2_SessionDestroy(session);
    }

    return ret;
}

static int alloc_service_idx(CasSession session)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (!g_svc_idx[i].used) {
	    CA_DEBUG(0, "allocated vmx svc idx %d", i);
	    g_svc_idx[i].used = 1;
	    g_svc_idx[i].session = session;
	    return i;
	}
    }

    CA_DEBUG(2, "alloc vmx svc idx failed.");
    return -1;
}

static void free_service_idx(int idx)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (g_svc_idx[i].used && (i == idx)) {
	    CA_DEBUG(0, "freed vmx svc idx %d", i);
	    g_svc_idx[i].used = 0;
	    g_svc_idx[i].session = 0;
	    return;
	}
    }

    CA_DEBUG(0, "free vmx svc idx failed.");
}

int get_dmx_dev(int svc_idx)
{
    VMX_PrivateInfo_t *vmx_pri_info = NULL;

    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
        if (g_svc_idx[i].used && (i == svc_idx)) {
            vmx_pri_info = ((CAS_SessionInfo_t *)g_svc_idx[i].session)->private_data;
            return vmx_pri_info->dmx_dev;
        }
    }

    CA_DEBUG(0, "svc idx[%d] not found", svc_idx);
    return -1;
}

static int alloc_dvr_channelid(void)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (!g_dvr_channelid[i].used) {
	    CA_DEBUG(0, "allocated dvr channelid %d", i);
	    g_dvr_channelid[i].used = 1;
	    return i;
	}
    }

    CA_DEBUG(0, "alloc dvr channelid failed.");
    return -1;
}

static void free_dvr_channelid(int id)
{
    int i;

    for (i = 0; i < MAX_CHAN_COUNT; i++) {
	if (g_dvr_channelid[i].used && (i == id)) {
	    CA_DEBUG(0, "freed dvr channelid %d", i);
	    g_dvr_channelid[i].used = 0;
	    break;
	}
    }

    CA_DEBUG(2, "free dvr channelid failed.");
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

    CA_DEBUG(0, "%s", __func__);

    g_dvr_shm = (uint8_t *)ree_shm_alloc(DVR_SIZE);
    memset(g_svc_idx, 0, sizeof(vmx_svc_idx_t)*MAX_CHAN_COUNT);

    if (CA_GetSecureBuffer(&buf, DVR_SIZE)) {
	    CA_DEBUG(0, "CA get secure buffer failed");
	    return -1;
    }
    vmx_file_echo("/sys/class/stb/dsc0_source", "dmx0");
    vmx_file_echo("/sys/class/stb/dsc1_source", "dmx1");

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
    vmx_pri_info->dat_fp = NULL;
    vmx_pri_info->segment_id = -1;
    memset(&vmx_pri_info->storeinfo_ctx, 0, sizeof(vmx_crypto_storeinfo_t));
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

    ca_svc_info.service_index = alloc_service_idx(session);
    ca_svc_info.service_type = SERVICE_LIVE_PLAY;
    ca_svc_info.dsc_dev_no = serviceInfo->dsc_dev;
    ca_svc_info.dvr_dev_no = serviceInfo->dvr_dev;
    ca_svc_info.stream_num = serviceInfo->stream_num;
    ca_svc_info.algo = SCRAMBLE_ALGO_CSA;

    vmx_pri_info->dmx_dev = serviceInfo->dmx_dev;
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
    CA_DEBUG(0, "Start Descrambling[%d] dmx%d [%d %d %#x %#x %#x %d]", \
		serviceInfo->dsc_dev, vmx_pri_info->dmx_dev, serviceInfo->service_id, serviceInfo->stream_num, \
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

static int vmx_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info)
{
    int ret;
    uint16_t rc;
    vmx_recinfo_t recinfo;
    uint8_t dvbtime[5], channelid;
    VMX_PrivateInfo_t *private_data;

	CA_DEBUG(0, "%s line %d", __func__, __LINE__);

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

    private_data->dvr_dev = service_info->dvr_dev;
    memset(&recinfo, 0, sizeof(vmx_recinfo_t));
    recinfo.len = sizeof(recinfo.info);

    channelid = alloc_dvr_channelid();
    private_data->dvr_channelid = channelid;
    CA_DEBUG(0, "CAS DVR record [%#x %#x %#x], shm[%#x]", private_data->service_index,
		channelid, recinfo.len, g_dvr_shm);
    rc = BC_DVRRecord(private_data->service_index, channelid, recinfo.info, recinfo.len, dvbtime);
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
    if (private_data->dat_fp) {
        fclose(private_data->dat_fp);
        private_data->dat_fp = NULL;
    }

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

static int vmx_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    uint16_t rc;
    uint8_t channelid;
    vmx_storeinfo_t storeinfo;
    VMX_PrivateInfo_t * private_data;
    shm_r2r_t shm_in, shm_out;

	CA_DEBUG(0, "%s line %d", __func__, __LINE__);

    if (cryptoPara->buf_len > DVR_SIZE) {
       CA_DEBUG(2, "encrypt buffer overflow DVR_SIZE");
       return -1;
    }

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;

    if (!private_data->dat_fp ||
        private_data->segment_id != cryptoPara->segment_id) {
        char dat_fname[MAX_LOCATION_SIZE];

        if (private_data->dat_fp) {
            fclose(private_data->dat_fp);
            private_data->dat_fp = NULL;
        }

        memset(dat_fname, 0, sizeof(dat_fname));
        vmx_get_fname(dat_fname, cryptoPara->location, cryptoPara->segment_id);
        private_data->dat_fp = fopen(dat_fname, "w+");
        if (!private_data->dat_fp) {
            CA_DEBUG(2, "%s open %s failed, %s", __func__, dat_fname, strerror(errno));
            vmx_bc_unlock();
            return -1;
        }
        private_data->segment_id = cryptoPara->segment_id;

	    CA_DEBUG(0, "%s %s created", __func__, dat_fname);
    }
	CA_DEBUG(0, "%s %d", __func__, __LINE__);
	CA_DEBUG(0, "crypto [iaddr:%#x, size:%#x] [oaddr:%#x, size:%#x]",
                cryptoPara->buf_in.addr, cryptoPara->buf_in.size,
                cryptoPara->buf_out.addr, cryptoPara->buf_out.size);

    CA_update_afifo_pos(cryptoPara->buf_in.addr);

    memset(&shm_in, 0x0, sizeof(shm_r2r_t));
    shm_in.magic = SHM_R2R_MAGIC;
    shm_in.type = SHM_R2R_TYPE_SEC;
    shm_in.paddr = (void *)cryptoPara->buf_in.addr;
    shm_in.size = cryptoPara->buf_in.size;

    memset(&shm_out, 0x0, sizeof(shm_r2r_t));
    shm_out.magic = SHM_R2R_MAGIC;
    shm_out.type = SHM_R2R_TYPE_REE;
    shm_out.vaddr = private_data->dvr_shm;
    shm_out.size = cryptoPara->buf_out.size;

    channelid = private_data->dvr_channelid;
    memset(&storeinfo, 0, sizeof(vmx_storeinfo_t));
    storeinfo.len = MAX_STOREINFO_LEN;

    CA_DEBUG(0, "CAS DVR Encrypt[%d] (%#x, %#x, %#x)",
		channelid, shm_in.paddr, shm_out.vaddr, shm_in.size);

    rc = BC_DVREncrypt(channelid, (uint8_t *)&shm_out,
		(uint8_t *)&shm_in, sizeof(shm_r2r_t),
		storeinfo.info, &storeinfo.len);
    if (rc != k_BcSuccess) {
	    CA_DEBUG(0, "BC_DVREncrypt failed, rc = %d", rc);
	    storeinfo.len = 0;
    }
    if (storeinfo.len) {
        int error;
        loff_t offset;
        uint32_t len;

        offset = cryptoPara->offset;
        error = fwrite(&offset, 1, sizeof(offset), private_data->dat_fp);
        CA_DEBUG(0, "Enc write offset: %lld, writed:%d", offset, error);
        len = storeinfo.len;;
        error = fwrite(&len, 1, sizeof(len), private_data->dat_fp);
        CA_DEBUG(0, "Enc write len: %#x, writed:%d", len, error);
        error = fwrite(storeinfo.info, 1, storeinfo.len, private_data->dat_fp);
        CA_DEBUG(0, "Enc write data, writed:%d", error);

        fflush(private_data->dat_fp);
    }

    ree_shm_update_tee(shm_out.vaddr, shm_out.size);
    memcpy((void *)cryptoPara->buf_out.addr, shm_out.vaddr, cryptoPara->buf_in.size);
    cryptoPara->buf_out.size = cryptoPara->buf_in.size;
    cryptoPara->buf_len = cryptoPara->buf_in.size;
    vmx_bc_unlock();

    return 0;
}

static int vmx_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    uint16_t rc;
    shm_r2r_t shm_in, shm_out;
    VMX_PrivateInfo_t * private_data;
    vmx_crypto_storeinfo_t storeinfo;

    if (cryptoPara->buf_len > DVR_SIZE) {
	CA_DEBUG(2, "decrypt buffer overflow DVR_SIZE");
	return -1;
    }

    vmx_bc_lock();
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;

    //vmx_get_storeinfo(&private_data->storeinfo_ctx, cryptoPara->offset, &storeinfo);
    //if () {
        //TODO:replay with updated StoreInfo
    //}


    memcpy(private_data->dvr_shm, (void *)cryptoPara->buf_in.addr, cryptoPara->buf_in.size);
    memset(&shm_in, 0x0, sizeof(shm_r2r_t));
    shm_in.magic = SHM_R2R_MAGIC;
    shm_in.type = SHM_R2R_TYPE_REE;
    shm_in.vaddr = private_data->dvr_shm;
    shm_in.size = cryptoPara->buf_in.size;

    memset(&shm_out, 0x0, sizeof(shm_r2r_t));
    shm_out.magic = SHM_R2R_MAGIC;
    shm_out.type = SHM_R2R_TYPE_SEC;
    shm_out.paddr = (void *)cryptoPara->buf_out.addr;
    shm_out.size = cryptoPara->buf_in.size;

    CA_DEBUG(0, "CAS DVR Decrypt[%d] (%#x, %#x, %#x)",
		private_data->dvr_channelid, shm_in.vaddr, shm_out.paddr, shm_in.size);

    ree_shm_update_ree(shm_in.paddr, shm_in.size);
    rc = BC_DVRDecrypt(private_data->dvr_channelid,
		(uint8_t *)&shm_out, (uint8_t *)&shm_in,
		sizeof(shm_r2r_t));

    if(rc != k_BcSuccess) {
	CA_DEBUG(0, "BC_DVRDecrypt failed, rc = %d", rc);
	vmx_bc_unlock();
	return -1;
    }

    //cryptoPara->buf_out.type = DVR_BUFFER_TYPE_SECURE;
    cryptoPara->buf_out.size = shm_out.size;
    cryptoPara->buf_len = shm_out.size;

    vmx_bc_unlock();

    return 0;
}

static int vmx_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    uint16_t rc;
    uint8_t dvbtime[5];
    vmx_recinfo_t recinfo;
    vmx_storeinfo_t storeinfo;
    ca_service_info_t ca_svc_info;
    VMX_PrivateInfo_t *private_data;

    vmx_bc_lock();
    get_dvbsi_time(time(NULL), dvbtime);
    private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
    if (private_data == NULL) {
	CA_DEBUG(2, "error, not open session");
	vmx_bc_unlock();
	return -1;
    }

    private_data->dvr_shm = g_dvr_shm;
    private_data->dvr_channelid = alloc_dvr_channelid();

    memset(&ca_svc_info, 0x0, sizeof(ca_service_info_t));
    ca_svc_info.service_index = private_data->dvr_channelid | 0x80;
    ca_svc_info.algo = SCRAMBLE_ALGO_NONE;
    ca_svc_info.mode = SCRAMBLE_MODE_CBC;
    ca_svc_info.alignment = SCRAMBLE_ALIGNMENT_LEFT;
    CA_SetServiceInfo(private_data->dsc_svc_handle, &ca_svc_info);

	memset(recinfo.info, 0, sizeof(recinfo.info));
	recinfo.len = sizeof(recinfo.info);

    if (!private_data->dat_fp) {
        char dat_fname[MAX_LOCATION_SIZE];

        memset(dat_fname, 0, sizeof(dat_fname));
        vmx_get_fname(dat_fname, cryptoPara->location, cryptoPara->segment_id);
        private_data->dat_fp = fopen(dat_fname, "r");
        if (!private_data->dat_fp) {
            CA_DEBUG(2, "%s open %s failed, %s", __func__, dat_fname, strerror(errno));
            vmx_bc_unlock();
            return -1;
        }
        vmx_parser_storeinfo(private_data->dat_fp, &private_data->storeinfo_ctx);
    }

    vmx_get_storeinfo(&private_data->storeinfo_ctx, cryptoPara->offset, &storeinfo);
#if 0
    {
	int i;
	for (i = 0; i < storeinfo.len; i+=8) {
	    CA_DEBUG(0, "%02x %02x %02x %02x %02x %02x %02x %02x", storeinfo.info[i], 
		storeinfo.info[i+1], storeinfo.info[i+2], storeinfo.info[i+3],
		storeinfo.info[i+4], storeinfo.info[i+5], storeinfo.info[i+6], storeinfo.info[i+7]);
	}
    }
#endif

    rc = BC_DVRReplay(private_data->dvr_channelid, recinfo.info,
		recinfo.len, storeinfo.info,
		storeinfo.len, dvbtime);

    CA_DEBUG(0, "CAS Replay start(%d, %d, %#x, %#x), shm[%#x]", 
	private_data->dvr_channelid, ca_svc_info.service_index,
	recinfo.len, storeinfo.len, private_data->dvr_shm);

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

    free_dvr_channelid(channelid);
    if (private_data->dat_fp) {
        fclose(private_data->dat_fp);
        vmx_free_storeinfo(&private_data->storeinfo_ctx);
    }

    vmx_bc_unlock();

    return 0;
}

static SecMemHandle vmx_create_secmem(CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size)
{
    uint32_t allocflag = 0;
    uint32_t secmemflag = 0;
    void *secbuf = NULL;
    void *session = NULL;
    secmem_handle_t *handle = NULL;

    uint32_t bufsize = DVR_SIZE/2;

    switch (type) {
        case SERVICE_LIVE_PLAY:
            allocflag = 0;
            secmemflag = 0x2001;
            break;

        case SERVICE_PVR_RECORDING:
            allocflag = 1;
            secmemflag = 0x4000;
            break;

        case SERVICE_PVR_PLAY:
            allocflag = 1;
            secmemflag = 0x6001;
            break;

        default:
            goto exit;
    }

    if (create_secmem(&session, secmemflag, &secbuf, bufsize, allocflag)) {
        goto exit;
    }

    handle = (secmem_handle_t *)malloc(sizeof(secmem_handle_t));
    if (!handle) {
        destroy_secmem(&session);
        goto exit;
    }

    handle->session = session;
    handle->secbuf = secbuf;

exit:
    if (secbuf && pSecBuf) {
        *pSecBuf = secbuf;
        *size = bufsize;
        return (SecMemHandle)handle;
    }

    return (SecMemHandle)NULL;
}

static int vmx_destroy_secmem(SecMemHandle handle)
{
    int ret;

    ret =  destroy_secmem(&((secmem_handle_t *)handle)->session);
    free((void *)handle);

    return ret;
}
