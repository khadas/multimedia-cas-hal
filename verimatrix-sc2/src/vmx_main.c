#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#define BC_DVR_INCLUDED
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
#include <cutils/properties.h>
#include <byteswap.h>

#include "bc_consts.h"
#include "bc_main.h"
#include "vmxca_clientapi.h"

#include "ca.h"
#include "am_ca.h"
#include "am_cas.h"
#include "am_cas_internal.h"

#define INDIV_AUTO
#define DSC_DEV_COUNT (2)
#define DMX_DEV_COUNT (3)
#define DVR_SIZE (188*1024)
#define MAX_STOREINFO_LEN (1024)
#define VMX_CAS_STRING "Verimatrix"

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

typedef struct dsc_dev {
	int dmx_dev;
	int ref_cnt;
} dsc_dev_t;

typedef struct {
	int dmx_dev;
	uint16_t emmpid;
} vmx_emm_info_t;

typedef struct vmx_svc_idx {
	int used;
	uint8_t svc_idx;
	CasSession session;
} vmx_svc_idx_t;

typedef struct vmx_dvr_channelid {
	int used;
} vmx_dvr_channelid_t;

typedef struct {
	uint8_t info[16];
	uint16_t len;
} vmx_recinfo_t;

typedef struct {
	uint8_t info[MAX_STOREINFO_LEN];
	uint16_t len;
} vmx_storeinfo_t;

typedef struct {
	struct list_head list;
	uint64_t start;
	uint64_t end;
	uint32_t info_len;
	uint8_t *info_data;
} vmx_crypto_storeinfo_t;

typedef struct {
	uint32_t evenkey;
	uint32_t eveniv;
	uint32_t oddkey;
	uint32_t oddiv;
} keytable_index_t;

typedef struct {
	pipeline_mode_t mode;
	pipeline_handle_t handle;
	dsc_session_t dsc_session;
	keytable_index_t indexs;
} vmx_pipeline_t;

typedef struct {
	int fend_dev;
	int dsc_dev;
	int dmx_dev;
	uint8_t service_index;
	int dsc_chan_handle[MAX_CHAN_COUNT];
	int dsc_chan_count;
	vmx_pipeline_t pipeline;

	int emm_pid;
	uint8_t dvr_channelid;

	int dvr_dev;
	uint32_t wait_enc_len;
	FILE *dat_fp;
	int segment_id;
	uint32_t blocksize;
	uint16_t recinfolen;
	uint8_t *recinfo;
	vmx_crypto_storeinfo_t storeinfo_ctx;
	vmx_storeinfo_t cur_storeinfo;

	CAS_EventFunction_t event_cb;
} VMX_PrivateInfo_t;

typedef struct {
	void *session;
	void *secbuf;
} secmem_handle_t;

static int vmx_pre_init(void);
static int vmx_init(CasHandle handle);
static int vmx_term(CasHandle handle);
static int vmx_isSystemId_supported(int CA_system_id);
static int vmx_open_session(CasHandle handle, CasSession session, CA_SERVICE_TYPE_t service_type);
static int vmx_close_session(CasSession session);
static int vmx_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo);
static int vmx_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);
static int vmx_stop_descrambling(CasSession session);
static int vmx_set_emm_pid(CasHandle handle, int dmx_dev, uint16_t emmPid);
static int vmx_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info);
static int vmx_dvr_stop(CasSession session);
static int vmx_dvr_set_pre_param(CasSession session, AM_CA_PreParam_t *param);
static int vmx_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara);
static int vmx_dvr_stop_replay(CasSession session);
static SecMemHandle vmx_create_secmem(CasSession session, CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size);
static int vmx_destroy_secmem(CasSession session, SecMemHandle handle);
static int vmx_register_event_cb(CasSession session, CAS_EventFunction_t event_fn);
static int vmx_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len);
static char *vmx_get_version(void);
static int vmx_get_store_region(CasSession session, AM_CA_StoreRegion_t *region, uint8_t *reg_cnt);

static int vmx_get_fname(char fname[MAX_LOCATION_SIZE],
	const char location[MAX_LOCATION_SIZE],
	uint64_t segment_id);

extern int vmx_port_init(void);
extern int vmx_port_deinit(void);
extern int am_smc_init(void);
extern void_t vmx_notify_func(enBcNotify_t n);
extern int vmx_interact_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len);

const struct AM_CA_Impl_t cas_ops = {
	.pre_init = vmx_pre_init,
	.init = vmx_init,
	.term = vmx_term,
	.isSystemIdSupported = vmx_isSystemId_supported,
	.open_session = vmx_open_session,
	.close_session = vmx_close_session,
	.start_descrambling = vmx_start_descrambling,
	.update_descrambling_pid = vmx_update_descrambling_pid,
	.stop_descrambling = vmx_stop_descrambling,
	.dvr_set_pre_param = vmx_dvr_set_pre_param,
	.set_emm_pid = vmx_set_emm_pid,
	.dvr_start = vmx_dvr_start,
	.dvr_stop = vmx_dvr_stop,
	.dvr_encrypt = vmx_dvr_encrypt,
	.dvr_decrypt = vmx_dvr_decrypt,
	.dvr_replay = vmx_dvr_replay,
	.dvr_stop_replay = vmx_dvr_stop_replay,
	.create_secmem = vmx_create_secmem,
	.destroy_secmem = vmx_destroy_secmem,
	.register_event_cb = vmx_register_event_cb,
	.ioctl = vmx_ioctl,
	.get_version = vmx_get_version,
	.get_store_region = vmx_get_store_region
};

#define IPTV_OFFSET 4
static CAS_EventFunction_t g_event_cb;
static vmx_emm_info_t g_emm_info[DMX_DEV_COUNT];
static vmx_svc_idx_t g_svc_idx[MAX_CHAN_COUNT];
static vmx_dvr_channelid_t g_dvr_channelid[MAX_CHAN_COUNT];
#ifdef INDIV_AUTO
static pthread_t indiv_thread = (pthread_t)NULL;
#endif
static pthread_t bcThread = (pthread_t)NULL;
static pthread_mutex_t vmx_bc_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

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
				vmx_crypto_storeinfo_t *storeinfo_ctx,
				uint8_t **recinfo,
				uint16_t *recinfolen,
				uint32_t *blksize)
{
	loff_t offset;
	uint32_t blocksize;
	uint16_t infolen;
	uint8_t *info;
	uint16_t storelen;
	vmx_crypto_storeinfo_t *pstoreinfo;

	if (fread(&blocksize, sizeof(blocksize), 1, dat_fp) != 1)
		return -1;
	blocksize = bswap_32(blocksize);

	if (fread(&infolen, sizeof(infolen), 1, dat_fp) != 1)
		return -1;
	infolen = bswap_16(infolen);
	info = malloc(infolen + 1);

	if (fread(info, 1, infolen, dat_fp) != infolen)
		return -1;

	do {
		if (fread(&offset, sizeof(offset), 1, dat_fp) != 1) {
			break;
		}
		offset = bswap_64(offset);

		if (fread(&storelen, sizeof(storelen), 1, dat_fp) != 1) {
			break;
		}
		storelen = bswap_16(storelen);

		pstoreinfo = malloc(sizeof(vmx_crypto_storeinfo_t));
		pstoreinfo->info_data = malloc(storelen);
		pstoreinfo->info_len = storelen;
		pstoreinfo->start = offset;
		pstoreinfo->end = VMX_MAGIC_NUM;
		CA_DEBUG(0, "find vmx store info len:%#x, region %lld ~ %lld",
			infolen, pstoreinfo->start, pstoreinfo->end);
		if (fread(pstoreinfo->info_data, 1, storelen, dat_fp) != storelen) {
			break;
		}
		list_add_tail(&pstoreinfo->list, &storeinfo_ctx->list);
	} while (1);

	*blksize = blocksize;
	*recinfolen = infolen;
	*recinfo = info;

	CA_DEBUG(0, "%s blksize:%#x, infolen:%#x\n", __func__, blocksize,
		 infolen);
	return 0;
}

static int vmx_get_storeinfo(
	vmx_crypto_storeinfo_t *storeinfo_ctx,
	loff_t offset,
	vmx_storeinfo_t *sinfo)
{
	int found = 0;
	struct list_head *pos, *q;
	vmx_crypto_storeinfo_t *pstoreinfo;

	list_for_each_safe(pos, q, &storeinfo_ctx->list) {
		pstoreinfo = list_entry(pos, vmx_crypto_storeinfo_t, list);
		if (NODE_IS_REWIND(pstoreinfo)) {
			if (offset > pstoreinfo->start || offset >= pstoreinfo->end) {
				sinfo->len = pstoreinfo->info_len;
				memcpy(sinfo->info, pstoreinfo->info_data, pstoreinfo->info_len);
				CA_DEBUG(0, "found revind store info, offset:%lld, len:%#x",
					pstoreinfo->start, pstoreinfo->info_len);
				return 0;
			}
		} else {
			if (offset >= pstoreinfo->start && offset <= pstoreinfo->end) {
				sinfo->len = pstoreinfo->info_len;
				memcpy(sinfo->info, pstoreinfo->info_data, pstoreinfo->info_len);
				found = 1;
				//return 0;
			} else {
				break;
			}
		}
	}

	if (found) {
		//CA_DEBUG(0, "found store info, offset:%lld, len:%#x", offset,
		//	 sinfo->len);
		return 0;
	} else {
		CA_DEBUG(2, "found store info failed");
		return -1;
	}
}

static int vmx_get_store_region(CasSession session, AM_CA_StoreRegion_t *region, uint8_t *reg_cnt)
{
	int idx = 0;
	struct list_head *pos, *q;
	vmx_crypto_storeinfo_t *pstoreinfo;
	VMX_PrivateInfo_t * private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
	AM_CA_StoreRegion_t *pr = region;

	list_for_each_safe(pos, q, &private_data->storeinfo_ctx.list) {
		pstoreinfo = list_entry(pos, vmx_crypto_storeinfo_t, list);
		CA_DEBUG(0, "%s %lld ~ %lld", __func__,
			 pstoreinfo->start,
			 pstoreinfo->end);
		pr->start = pstoreinfo->start;
		pr->end   = pstoreinfo->end;
		if (idx >= 1) {
			CA_DEBUG(0, "%s last pos[%d]: %lld", __func__, idx, pr->start);
			pr[-1].end = pr->start - 1;
		}
		idx++;
		pr ++;
	}

	*reg_cnt = idx;
	CA_DEBUG(0, "region count:%d\n", *reg_cnt);

	return 0;
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

static uint8_t alloc_service_idx(CasSession session)
{
	uint8_t i;
	uint8_t offset = 0;

	if (((CAS_SessionInfo_t *)session)->service_info.service_mode == SERVICE_IPTV) {
		offset = IPTV_OFFSET;
	}

	for (i = offset; i < MAX_CHAN_COUNT; i++) {
		if (!g_svc_idx[i].used) {
			g_svc_idx[i].used = 1;
			g_svc_idx[i].session = session;
			break;
		}
	}
	if (i >= MAX_CHAN_COUNT) {
		CA_DEBUG(2, "alloc vmx svc idx failed.");
		return -1;
	}
	if (((CAS_SessionInfo_t *)session)->service_info.service_mode == SERVICE_IPTV) {
		//g_svc_idx[i].svc_idx = (i - offset) |  0x40;
		g_svc_idx[i].svc_idx = 0x40;
	} else if (((CAS_SessionInfo_t *)session)->service_info.service_type == SERVICE_PVR_PLAY) {
		g_svc_idx[i].svc_idx = i | 0x80;
	} else {
		g_svc_idx[i].svc_idx = i;
	}

	CA_DEBUG(0, "allocated vmx svc idx %d. private_data:%p",
		 g_svc_idx[i].svc_idx,
		 (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data);
	return g_svc_idx[i].svc_idx;
}

static void free_service_idx(CasSession session, uint8_t idx)
{
	uint8_t i;
	uint8_t offset = 0;

	if (((CAS_SessionInfo_t *)session)->service_info.service_mode == SERVICE_IPTV) {
		offset = IPTV_OFFSET;
	}

	for (i = offset; i < MAX_CHAN_COUNT; i++) {
		if (g_svc_idx[i].used && (g_svc_idx[i].svc_idx == idx)) {
			CA_DEBUG(0, "freed vmx svc idx %d",
				 g_svc_idx[i].svc_idx);
			g_svc_idx[i].used = 0;
			g_svc_idx[i].session = 0;
			return;
		}
	}

	CA_DEBUG(0, "free vmx svc idx failed.");
}

CasSession get_service_session(int idx)
{
	uint8_t i;

	for (i = 0; i < MAX_CHAN_COUNT; i++) {
		if (g_svc_idx[i].used && g_svc_idx[i].svc_idx == idx) {
			return g_svc_idx[i].session;
		}
	}

	return (CasSession)NULL;
}

int get_service_idx(CasSession session)
{
	int i;
	//VMX_PrivateInfo_t *private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;

	for (i = 0; i < MAX_CHAN_COUNT; i++) {
		if (g_svc_idx[i].used &&
			g_svc_idx[i].session == session) {
			return g_svc_idx[i].svc_idx;
		}
	}
	CA_DEBUG(0, "%s not found session:%#x", __func__, session);
	return -1;
}

CAS_EventFunction_t get_service_event_cb(int idx)
{
	uint8_t i;
	CasSession session;
	VMX_PrivateInfo_t *private_data;

	for (i = 0; i < MAX_CHAN_COUNT; i++) {
		if (g_svc_idx[i].used && g_svc_idx[i].svc_idx == idx) {
			session = g_svc_idx[i].session;
			private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
			return private_data->event_cb;
		}
	}
	return NULL;
}

CAS_EventFunction_t get_global_event_cb(void)
{
	return g_event_cb;
}

static int store_emm_info(int dmx_dev, uint16_t emm_pid)
{
	if (dmx_dev >= DMX_DEV_COUNT) {
		CA_DEBUG(1, "invalid dmx_dev:%d for emm:%#x", dmx_dev, emm_pid);
		return -1;
	}

	g_emm_info[dmx_dev].emmpid = emm_pid;
	CA_DEBUG(1, "store emmpid[%#x] on dmx%d", emm_pid, dmx_dev);
	return 0;
}

int get_dmx_dev(uint8_t svc_idx)
{
	VMX_PrivateInfo_t *vmx_pri_info = NULL;

	uint8_t i;

	for (i = 0; i < MAX_CHAN_COUNT; i++) {
		if (g_svc_idx[i].used && (g_svc_idx[i].svc_idx == svc_idx)) {
			vmx_pri_info = ((CAS_SessionInfo_t *)g_svc_idx[i].session)->private_data;
			CA_DEBUG(0, "find svc_idx[%d], dmx_dev[%d]", svc_idx, vmx_pri_info->dmx_dev);
			return vmx_pri_info->dmx_dev;
		}
	}

	CA_DEBUG(0, "svc idx[%d] not found", svc_idx);
	return -1;
}

int find_dmx_dev(uint16_t emm_pid)
{
	int i;

	for (i = 0; i < DMX_DEV_COUNT; i++) {
		if (g_emm_info[i].emmpid == emm_pid) {
			CA_DEBUG(0, "emmpid[%#x] found on dmx%d", emm_pid, i);
			return i;
		}
	}

	CA_DEBUG(1, "emmpid[%#x] not found, use default dmx0", emm_pid);
	return 0;
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
			return;
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

void vmx_callback(enBcNotify_t n)
{
	CA_DEBUG(0, "%s %#x\n", __func__, n);
	vmx_notify_func(n);
}

static void *bcHandlingThread(void *pParam)
{
	UNUSED(pParam);

	CA_DEBUG( 0, "BC thread is called\n" );
	while ( 1 ) {
		vmx_bc_lock();
		BC_Task();
		vmx_bc_unlock();
		usleep( 10 * 1000 ); /* in mill sec */
	}
	return NULL;
}

#ifdef INDIV_AUTO
static void* vmx_indiv_thread(void *arg)
{
	int ret;
	char ip[PROPERTY_VALUE_MAX] = {0};
	char *vendorid = "/system/bin/vendorid.bin";
	char *vendordata = "/system/bin/vendordata.bin";
	char *providerid = "/system/bin/providerid.bin";
	char *providerdata = "/system/bin/providerdata.bin";
	char *datafile = "/system/bin/datafile.dat";
	char cmd[512] = {0};

	UNUSED(arg);
	while (1) {
		ret = property_get("vmx.indiv.server.ip", ip, NULL);
		if (ret) {
			CA_DEBUG(0, "vmx indiv ip:%s", ip);
			break;
		} else {
			sleep(1);
			CA_DEBUG(0, "Please setprop vmx.indiv.server.ip for Verimatrix individualization");
		}
	}

	CA_DEBUG(0, "Welcome to Verimatrix individualization");
	sprintf(cmd, "vmx_indiv %s %s %s %s %s %s",
		ip, vendorid, vendordata,
		providerid, providerdata, datafile);
	CA_DEBUG(0, "%s", cmd);
	ret = system(cmd);
	if (ret == 0) {
		CA_DEBUG(0, "Verimatrix individualization successed");
	} else {
		CA_DEBUG(2, "Verimatrix individualization failed. ret:%d", ret);
	}

	sprintf(cmd, "restorecon %s*", AM_NVM_FILE);
	CA_DEBUG(0, "%s", cmd);
	ret = system(cmd);
	if (ret == 0) {
		CA_DEBUG(0, "restorecon done");
	} else {
		CA_DEBUG(0, "restorecon failed:%d", ret);
	}

	return NULL;
}
#endif

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
	int bcRet;
	uint8_t version[32];
	uint8_t date[20];
	uint8_t timestr[20];

#ifdef INDIV_AUTO
	char path[64];
	int fileid = 0;
	struct stat buf;

	sprintf(path, "%s%d", AM_NVM_FILE, fileid);
	bcRet = stat(path, &buf);
	if (bcRet == -1 && errno == ENOENT) {
		CA_DEBUG(0, "%s not exist", path);
		pthread_create(&indiv_thread, NULL, vmx_indiv_thread, NULL);
		return -1;
	}
	CA_DEBUG(0, "stat %s, ret:%d", path, bcRet);
#endif
	VMXCA_Init();
	vmx_port_init();
	am_smc_init();

	vmx_bc_lock();
	bcRet = BC_Init();
	CA_DEBUG(0, "BC-Init: %04x\n", (uint16_t)bcRet);

	BC_GetVersion(version, date, timestr );
	CA_DEBUG(0, "ver %s %s %s\n", version, date, timestr);

	bcRet = BC_Ioctl(k_ConnectBc, (void *)vmx_callback, NULL);
	CA_DEBUG(0, "bcRet:%d\n", bcRet);

	BC_InitWindow(1920, 1080, NULL);
	vmx_bc_unlock();

	pthread_create( &bcThread, NULL, bcHandlingThread, NULL );
	print_scinfo();

	return 0;
}

static int vmx_init(CasHandle handle)
{
	UNUSED(handle);
	CA_DEBUG(0, "%s", __func__);

	memset(g_svc_idx, 0, sizeof(vmx_svc_idx_t)*MAX_CHAN_COUNT);
	memset(g_emm_info, 0, sizeof(vmx_emm_info_t)*DMX_DEV_COUNT);

	return 0;
}

static int vmx_term(CasHandle handle)
{
	UNUSED(handle);

	VMXCA_UnInit();
	vmx_port_deinit();
	pthread_join(bcThread, NULL);

	return 0;
}

static int vmx_isSystemId_supported(int CA_system_id)
{
	vmx_bc_lock();
	if (BC_Get_CASystemID() != CA_system_id) {
		CA_DEBUG(0, "not supported CA_system_id[%#x], VMX systemID is %#x",
			CA_system_id, BC_Get_CASystemID());
		vmx_bc_unlock();
		return 0;
	} else {
		CA_DEBUG(0, "supported CA_system_id[%#x]", CA_system_id);
	}
	vmx_bc_unlock();

	return 1;
}

static int vmx_open_session(CasHandle handle, CasSession session, CA_SERVICE_TYPE_t service_type)
{
	int ret;
	VMX_PrivateInfo_t *private_data = NULL;

	pipeline_create_param_t pipeline_param;
	pipeline_handle_t pipeline_handle = -1;

	UNUSED(handle);
	switch (service_type) {
	case SERVICE_LIVE_PLAY:
		pipeline_param.mode = PIPELINE_MODE_LIVE;
		break;

	case SERVICE_PVR_RECORDING:
		pipeline_param.mode = PIPELINE_MODE_RECORD;
		break;

	case SERVICE_PVR_PLAY:
		pipeline_param.mode = PIPELINE_MODE_PLAYBACK;
		break;

	default:
		CA_DEBUG(1, "invalid servie type %d\n", service_type);
		break;
	};

	ret = VMXCA_PipelineCreate(&pipeline_param, &pipeline_handle);
	if (ret != VMXCA_SUCCESS) {
		CA_DEBUG(1, "%s create pipeline %d failed, ret:%d\n",
			__func__, pipeline_param.mode, ret);
		return -1;
	}

	private_data = (VMX_PrivateInfo_t *)malloc(sizeof(VMX_PrivateInfo_t));
	memset((void *)private_data, 0x0, sizeof(VMX_PrivateInfo_t));
	private_data->dvr_channelid = -1;
	private_data->dat_fp = NULL;
	private_data->segment_id = -1;
	private_data->event_cb = NULL;
	private_data->pipeline.mode = pipeline_param.mode;
	private_data->pipeline.handle = pipeline_handle;
	memset(&private_data->storeinfo_ctx, 0, sizeof(vmx_crypto_storeinfo_t));
	memset(&private_data->cur_storeinfo, 0, sizeof(vmx_storeinfo_t));

	((CAS_SessionInfo_t *)session)->private_data = private_data;
	((CAS_SessionInfo_t *)session)->service_info.service_type = service_type;

	return 0;
}

static int vmx_close_session(CasSession session)
{
	VMX_PrivateInfo_t *private_data = NULL;

	private_data = ((CAS_SessionInfo_t *)session)->private_data;
	if (private_data->pipeline.handle != -1) {
		VMXCA_PipelineRelease(private_data->pipeline.handle);
		private_data->pipeline.handle = -1;
	}
	free(private_data);
	((CAS_SessionInfo_t *)session)->private_data = NULL;

	return 0;
}

static int vmx_start_descrambling(CasSession session, AM_CA_ServiceInfo_t *serviceInfo)
{
	uint8_t *p;
	int i, ret;
	int dsc_chan_handle = -1;
	VMX_PrivateInfo_t *vmx_pri_info = NULL;

	int dsc_dev;
	int dsc_algo = CA_ALGO_CSA2;
	int dsc_type = CA_DSC_COMMON_TYPE;
	pipeline_handle_t pipeline_handle = -1;
	pipeline_info_t pipeline_info;
	dsc_session_t dsc_session = -1;
	dsc_session_open_param_t dsc_param;
	dsc_session_info_t dsc_info;

	uint32_t oddkey_index = -1, oddiv_index = -1;
	uint32_t evenkey_index = -1, eveniv_index = -1;

	uint16_t ecmPid[MAX_CHAN_COUNT];
	uint16_t streamPid[MAX_CHAN_COUNT];

	vmx_pri_info = ((CAS_SessionInfo_t *)session)->private_data;
	pipeline_handle = vmx_pri_info->pipeline.handle;

	memset(&dsc_info, 0, sizeof(dsc_info));
	memset(&pipeline_info, 0, sizeof(pipeline_create_param_t));
	pipeline_info.sid = serviceInfo->fend_dev;
	pipeline_info.dmx_id = serviceInfo->dmx_dev;
	pipeline_info.program_num = serviceInfo->service_id;
	ret = VMXCA_PipelineSetInfo(pipeline_handle, &pipeline_info);
	if (ret != VMXCA_SUCCESS) {
		CA_DEBUG(1, "%s set pipeline param failed, ret:%d\n", __func__, ret);
		return -1;
	}
	dsc_dev = serviceInfo->dmx_dev;
	memcpy(&(((CAS_SessionInfo_t *)session)->service_info), (void *)serviceInfo, sizeof(AM_CA_ServiceInfo_t));
	ret = ca_open(dsc_dev);
	if (ret) {
		VMXCA_PipelineRelease(pipeline_handle);
		CA_DEBUG(1, "open dsc%d failed\n", dsc_dev);
		return -1;
	}

	p = serviceInfo->ca_private_data;
	if (serviceInfo->ca_private_data_len > 0) {
		CA_DEBUG(0, "found ca private data: %#x %#x\n", p[1], p[2]);
		if (p[1]) {
			if (((p[2] & 0xE0) >> 5) == 1) {
				dsc_algo = CA_ALGO_AES_ECB_CLR_END;
				dsc_info.algo = DSC_ALGO_AES;
				CA_DEBUG(0, "Algo-AES found.\n");
			}
		} else {
			CA_DEBUG(0, "scrambling descriptor:%#x\n", p[2]);
			switch (p[2]) {
			    case 0x1:
			    case 0x2:
				dsc_algo = CA_ALGO_CSA2;
				dsc_info.algo = DSC_ALGO_CSA2;
				break;
			    case 0x3:
			    case 0x4:
			    case 0x5:
				dsc_algo = CA_ALGO_CSA3;
				dsc_info.algo = DSC_ALGO_CSA3;
			    default:
				break;
			};
		}
	}

	for (i = 0; i < serviceInfo->stream_num; i++) {
		dsc_chan_handle = ca_alloc_chan(dsc_dev,
				serviceInfo->stream_pids[i],
				dsc_algo,
				dsc_type);
		if (dsc_chan_handle >= 0) {
			vmx_pri_info->dsc_chan_count++;
			vmx_pri_info->dsc_chan_handle[i] = dsc_chan_handle;
			CA_DEBUG(1, "alloc dsc channel(%d, %d) ok.", dsc_dev, dsc_chan_handle);
		} else {
			CA_DEBUG(1, "alloc dsc channel(%d) failed.", dsc_dev);
		}
	}

	vmx_pri_info->service_index = alloc_service_idx(session);
	memset(&dsc_param, 0, sizeof(dsc_param));
	dsc_param.svc_index = vmx_pri_info->service_index;
	dsc_param.ecm_pid = serviceInfo->ecm_pid;
	ret = VMXCA_PipelineOpenDscSession(
			pipeline_handle,
			&dsc_param,
			&dsc_session);
	if (ret) {
		CA_DEBUG(2, "open dsc sesion failed %d\n", ret);
	}

	ret = VMXCA_PipelineSetDscSessionInfo(
			pipeline_handle,
			dsc_session,
			&dsc_info);
	if (ret) {
		CA_DEBUG(2, "set dsc sesion failed %d\n", ret);
	}

	ret = VMXCA_PipelineDscSessionAllocKeytable(
			pipeline_handle,
			dsc_session,
			KEY_TYPE_EVEN,
			&evenkey_index);
	if (ret) {
		CA_DEBUG(2, "alloc even keytable failed %d\n", ret);
	}

	ret = VMXCA_PipelineDscSessionAllocKeytable(
			pipeline_handle,
			dsc_session,
			KEY_TYPE_ODD,
			&oddkey_index);
	if (ret) {
		CA_DEBUG(2, "alloc odd keytable failed %d\n", ret);
	}

	if (dsc_algo == DSC_ALGO_AES) {
		ret = VMXCA_PipelineDscSessionAllocKeytable(
				pipeline_handle,
				dsc_session,
				KEY_TYPE_EVEN_IV,
				&eveniv_index);

		ret |= VMXCA_PipelineDscSessionAllocKeytable(
				pipeline_handle,
				dsc_session,
				KEY_TYPE_ODD_IV,
				&oddiv_index);
	}
	CA_DEBUG(0, "set DSC, ret:%d", ret);
	for (i = 0; i < vmx_pri_info->dsc_chan_count; i++) {
		int dsc_chan = vmx_pri_info->dsc_chan_handle[i];

		ca_set_key(dsc_dev, dsc_chan, CA_KEY_EVEN_TYPE, evenkey_index);
		ca_set_key(dsc_dev, dsc_chan, CA_KEY_ODD_TYPE, oddkey_index);
		if (dsc_algo == DSC_ALGO_AES) {
			ca_set_key(dsc_dev, dsc_chan, CA_KEY_EVEN_IV_TYPE, eveniv_index);
			ca_set_key(dsc_dev, dsc_chan, CA_KEY_ODD_IV_TYPE, oddiv_index);
		}
	}

	vmx_pri_info->pipeline.dsc_session = dsc_session;
	vmx_pri_info->pipeline.indexs.evenkey = evenkey_index;
	vmx_pri_info->pipeline.indexs.oddkey = oddkey_index;
	vmx_pri_info->pipeline.indexs.eveniv = eveniv_index;
	vmx_pri_info->pipeline.indexs.oddiv = oddiv_index;
	vmx_pri_info->fend_dev = serviceInfo->fend_dev;
	vmx_pri_info->dsc_dev = dsc_dev;
	vmx_pri_info->dmx_dev = serviceInfo->dmx_dev;

	vmx_bc_lock();
	for (i = 0; i < serviceInfo->stream_num; i++) {
		ecmPid[i] = serviceInfo->ecm_pid;
		streamPid[i] = serviceInfo->stream_pids[i];
	}
	ret = BC_StartDescrambling(serviceInfo->service_id, serviceInfo->stream_num, \
		&ecmPid[0], &streamPid[0], vmx_pri_info->service_index);
	CA_DEBUG(0, "Start Descrambling ret[%d] dmx%d [%d %d %#x %#x %#x %d]", \
		ret, vmx_pri_info->dmx_dev, serviceInfo->service_id, serviceInfo->stream_num, \
		ecmPid[0], streamPid[0], streamPid[1], vmx_pri_info->service_index);

	vmx_bc_unlock();
	return 0;
}

static int vmx_update_descrambling_pid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid)
{
	UNUSED(session);
	UNUSED(oldStreamPid);
	UNUSED(newStreamPid);
	return 0;
}

static int vmx_stop_descrambling(CasSession session)
{
	int i, ret;
	uint16_t svc_id;
	VMX_PrivateInfo_t *private_data;
	vmx_pipeline_t *pipeline;

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
		ret = ca_free_chan(private_data->dsc_dev, private_data->dsc_chan_handle[i]);
		if (ret) {
			CA_DEBUG(2, "free dsc failed[%d].", ret);
		} else {
			CA_DEBUG(0, "free dsc fd[%d].", private_data->dsc_chan_handle[i]);
		}
	}

	pipeline = &private_data->pipeline;
	if (pipeline->handle != -1) {
		if (pipeline->dsc_session != -1) {
			if (pipeline->indexs.evenkey != -1) {
				VMXCA_PipelineDscSessionFreeKeytable(
					pipeline->handle,
					pipeline->dsc_session,
					pipeline->indexs.evenkey);
			}
			if (pipeline->indexs.oddkey != -1) {
				VMXCA_PipelineDscSessionFreeKeytable(
					pipeline->handle,
					pipeline->dsc_session,
					pipeline->indexs.oddkey);
			}
			if (pipeline->indexs.eveniv != -1) {
				VMXCA_PipelineDscSessionFreeKeytable(
					pipeline->handle,
					pipeline->dsc_session,
					pipeline->indexs.eveniv);
			}
			if (pipeline->indexs.oddiv != -1) {
				VMXCA_PipelineDscSessionFreeKeytable(
					pipeline->handle,
					pipeline->dsc_session,
					pipeline->indexs.oddiv);
			}
			VMXCA_PipelineCloseDscSession(
				pipeline->handle,
				pipeline->dsc_session);
			pipeline->dsc_session = -1;
		}
	}

	free_service_idx(session, private_data->service_index);

	vmx_bc_unlock();

	return 0;
}

static int vmx_dvr_set_pre_param(CasSession session, AM_CA_PreParam_t *param)
{
	UNUSED(session);
	CA_DEBUG(1, "vmx_dvr_set_pre_param dmx[%d].", param->dmx_dev);
	return 0;
}


static int vmx_set_emm_pid(CasHandle handle, int dmx_dev, uint16_t emmPid)
{
	UNUSED(handle);

	vmx_bc_lock();
	store_emm_info(dmx_dev, emmPid);
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
	m2m_info_t m2m_info;

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

	private_data->dvr_dev = service_info->dvr_dev;
	memset(&recinfo, 0, sizeof(vmx_recinfo_t));
	recinfo.len = sizeof(recinfo.info);

	channelid = alloc_dvr_channelid();
	private_data->dvr_channelid = channelid;
	CA_DEBUG(0, "CAS DVR record [%#x %#x %#x],",
		private_data->service_index,
		channelid, recinfo.len);

	rc = BC_DVRRecord(private_data->service_index, channelid, recinfo.info, recinfo.len, dvbtime);
	if (rc != k_BcSuccess) {
		CA_DEBUG(2, "BC_DVRRecord faild, rc = %d", rc);
		vmx_bc_unlock();
		vmx_stop_descrambling(session);
		return -1;
	}

	memset(&m2m_info, 0, sizeof(m2m_info_t));
	m2m_info.engine_id = private_data->dvr_channelid;
	m2m_info.hw_mode = 0;
	ret = VMXCA_PipelineSetM2MInfo(private_data->pipeline.handle,  &m2m_info);
	if (ret) {
		CA_DEBUG(0, "Set M2M info failed\n");
		vmx_bc_unlock();
		vmx_stop_descrambling(session);
	}
	vmx_bc_unlock();

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

	free_service_idx(session, private_data->service_index);
	free_dvr_channelid(channelid);
	if (private_data->dat_fp) {
		fclose(private_data->dat_fp);
		private_data->dat_fp = NULL;
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
	uint8_t *aligned_buff_addr = NULL;
	uint32_t block_size = DVR_SIZE;
	vmxca_result_t result;
	m2m_engine_conf_t m2m_eng_conf;
	uint8_t *p_vr_input_buffer = NULL;
	uint8_t *p_vr_output_buffer = NULL;
	uint32_t vr_buffer_len = 0;
	m2m_buffer_t m2m_buf;

	vmx_bc_lock();
	private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
	aligned_buff_addr = (uint8_t *)((uint32_t)cryptoPara->buf_in.addr - private_data->wait_enc_len);
	private_data->wait_enc_len += cryptoPara->buf_in.size;
	if (private_data->wait_enc_len < block_size) {
		cryptoPara->buf_out.size = 0;
		cryptoPara->buf_len = 0;
		vmx_bc_unlock();
		//CA_DEBUG(2, "wait encrypt data length... %#x", private_data->wait_enc_len);
		return 0;
	}

	if (!private_data->dat_fp ||
		private_data->segment_id != cryptoPara->segment_id) {
		uint32_t blk_size;
		uint16_t info_len;
		vmx_recinfo_t info;
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
		blk_size = bswap_32(block_size);
		fwrite(&blk_size, sizeof(blk_size), 1, private_data->dat_fp);

		memset(&info, 0, sizeof(info));
		info_len = bswap_16(sizeof(info.info));
		fwrite(&info_len, sizeof(info_len), 1, private_data->dat_fp);
		fwrite(info.info, 1, sizeof(info.info), private_data->dat_fp);

		if (private_data->cur_storeinfo.len) {
			int error;
			uint16_t storelen;
			loff_t streampos;
			vmx_storeinfo_t *storeinfo = &private_data->cur_storeinfo;

			streampos = bswap_64(cryptoPara->offset);
			error = fwrite(&streampos, 1, sizeof(streampos), private_data->dat_fp);
			storelen = bswap_16(storeinfo->len);
			error = fwrite(&storelen, 1, sizeof(storelen), private_data->dat_fp);
			error = fwrite(storeinfo->info, 1, storeinfo->len, private_data->dat_fp);
			CA_DEBUG(0, "ret:%d, segment %d to segment %d, copy latest storeinfo",
				 error, private_data->segment_id,
				 cryptoPara->segment_id);

			fflush(private_data->dat_fp);
		}

		private_data->segment_id = cryptoPara->segment_id;
		CA_DEBUG(0, "%s %s created", __func__, dat_fname);
	}

	CA_DEBUG(0, "crypto wait_enc_len: %#x", private_data->wait_enc_len);

	channelid = private_data->dvr_channelid;
	memset(&storeinfo, 0, sizeof(vmx_storeinfo_t));
	storeinfo.len = MAX_STOREINFO_LEN;
	memset(&m2m_eng_conf, 0, sizeof(m2m_engine_conf_t));
	m2m_eng_conf.p_in = (uint8_t *)aligned_buff_addr;
	m2m_eng_conf.in_len = block_size;
	m2m_eng_conf.p_out = (uint8_t *)cryptoPara->buf_out.addr;
	m2m_eng_conf.out_len = cryptoPara->buf_out.size;
	m2m_eng_conf.usage = M2M_ENGINE_USAGE_RECORD;

	memset(&m2m_buf, 0, sizeof(m2m_buf));
	m2m_buf.p = m2m_eng_conf.p_in;
	m2m_buf.len = m2m_eng_conf.in_len;
	m2m_buf.is_secure = 1;
	result = VMXCA_GetViewRightInputPadBuffer(channelid, &m2m_buf, &p_vr_input_buffer, &vr_buffer_len);

	m2m_buf.p = m2m_eng_conf.p_out;
	m2m_buf.len = m2m_eng_conf.out_len;
	m2m_buf.is_secure = 0;
	result = VMXCA_GetViewRightOutputPadBuffer(channelid, &m2m_buf, &p_vr_output_buffer, &vr_buffer_len);
	CA_DEBUG(0, "crypto vr_input:%p, vr_out:%p, len:%#x, ret:%#x", p_vr_input_buffer,
			p_vr_output_buffer, vr_buffer_len, result);
	CA_DEBUG(0, "crypto [iaddr:%p, size:%#x] [oaddr:%p, size:%#x]",
                m2m_eng_conf.p_in, m2m_eng_conf.in_len,
                m2m_eng_conf.p_out, m2m_eng_conf.out_len);

	rc = BC_DVREncrypt(channelid, p_vr_output_buffer,
			p_vr_input_buffer, vr_buffer_len,
			storeinfo.info, &storeinfo.len);

	if (rc != k_BcSuccess) {
		CA_DEBUG(0, "BC_DVREncrypt failed, rc = %d", rc);
		storeinfo.len = 0;
	}
	if (storeinfo.len) {
		int error;
		uint16_t storelen;
		loff_t streampos;

		streampos = bswap_64(cryptoPara->offset);
		error = fwrite(&streampos, 1, sizeof(streampos), private_data->dat_fp);
		CA_DEBUG(0, "Enc write offset: %lld, writed:%d", cryptoPara->offset, error);
		storelen = bswap_16(storeinfo.len);
		error = fwrite(&storelen, 1, sizeof(storelen), private_data->dat_fp);
		CA_DEBUG(0, "Enc write len: %#x, writed:%d", storelen, error);
		error = fwrite(storeinfo.info, 1, storeinfo.len, private_data->dat_fp);
		CA_DEBUG(0, "Enc write data, writed:%d", error);

		fflush(private_data->dat_fp);
		memcpy(&private_data->cur_storeinfo, &storeinfo,
		       sizeof(vmx_storeinfo_t));
	}

	result = VMXCA_PipelineM2MEngineRun(
			private_data->pipeline.handle,
			&m2m_eng_conf);
	if (result) {
		CA_DEBUG(2, "Enc M2MEngineRun failed:%d\n", result);
	}

	cryptoPara->buf_len = m2m_eng_conf.out_len;
	cryptoPara->buf_out.size = m2m_eng_conf.out_len;
	private_data->wait_enc_len -= block_size;
	vmx_bc_unlock();

	return 0;
}

static int vmx_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
	uint32_t rc;
	VMX_PrivateInfo_t * private_data;
	uint8_t dvbtime[5];
	vmx_storeinfo_t storeinfo;
	uint8_t *p_vr_input_buffer = NULL;
	uint8_t *p_vr_output_buffer = NULL;
	uint32_t vr_buffer_len = 0;
	m2m_engine_conf_t m2m_eng_conf;
	m2m_buffer_t m2m_buf;
	vmxca_result_t result;

	vmx_bc_lock();
	private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;

	memset(&m2m_buf, 0, sizeof(m2m_buf));
	m2m_buf.p = (uint8_t *)cryptoPara->buf_in.addr;
	m2m_buf.len = cryptoPara->buf_in.size;
	m2m_buf.is_secure = 0;
	result = VMXCA_GetViewRightInputPadBuffer(private_data->dvr_channelid,
			&m2m_buf, &p_vr_input_buffer, &vr_buffer_len);

	m2m_buf.p = (uint8_t *)cryptoPara->buf_out.addr;
	m2m_buf.len = cryptoPara->buf_out.size;
	m2m_buf.is_secure = 1;
	result = VMXCA_GetViewRightOutputPadBuffer(private_data->dvr_channelid,
			&m2m_buf, &p_vr_output_buffer, &vr_buffer_len);
	CA_DEBUG(0, ">> crypto vr_input:%p, vr_out:%p, len:%#x, ret:%#x", p_vr_input_buffer,
			p_vr_output_buffer, vr_buffer_len, result);

	memset(&storeinfo, 0, sizeof(vmx_storeinfo_t));
	vmx_get_storeinfo(&private_data->storeinfo_ctx, cryptoPara->offset, &storeinfo);
	if (memcmp(&storeinfo, &private_data->cur_storeinfo,
		   sizeof(vmx_storeinfo_t))) {

		get_dvbsi_time(time(NULL), dvbtime);
		CA_DEBUG(0, "CAS storeinfo updated, Replay(%d, %#x)",
			private_data->dvr_channelid,
			storeinfo.len);

		rc = BC_DVRReplay(private_data->dvr_channelid, NULL, 0,
				  storeinfo.info, storeinfo.len, dvbtime);
		if (rc != k_BcSuccess) {
			CA_DEBUG(0, "BC_DVRReplay failed, rc = %d", rc);
			vmx_bc_unlock();
			return -1;
		}
		memcpy(&private_data->cur_storeinfo, &storeinfo,
		       sizeof(vmx_storeinfo_t));
	}

	memset(&m2m_eng_conf, 0, sizeof(m2m_engine_conf_t));
	m2m_eng_conf.p_in = (uint8_t *)cryptoPara->buf_in.addr;
	m2m_eng_conf.in_len = cryptoPara->buf_in.size;
	m2m_eng_conf.p_out = (uint8_t *)cryptoPara->buf_out.addr;
	m2m_eng_conf.out_len = cryptoPara->buf_out.size;
	m2m_eng_conf.usage = M2M_ENGINE_USAGE_PLAYBACK;

	CA_DEBUG(0, "CAS DVR Decrypt[%d] (%p, %p, %#x), offset[%lld]",
		 private_data->dvr_channelid,
		 m2m_eng_conf.p_in,
		 m2m_eng_conf.p_out,
		 m2m_eng_conf.in_len,
		 cryptoPara->offset);

	rc = BC_DVRDecrypt(private_data->dvr_channelid,
			   p_vr_output_buffer,
			   p_vr_input_buffer,
			   vr_buffer_len);
	if (rc != k_BcSuccess) {
		CA_DEBUG(0, "BC_DVRDecrypt failed, rc = %d", rc);
		vmx_bc_unlock();
		return -1;
	}

	rc = VMXCA_PipelineM2MEngineRun(private_data->pipeline.handle,
					&m2m_eng_conf);
	if (rc) {
		CA_DEBUG(2, "Dec M2MEngineRun failed:%d\n", rc);
	}
	cryptoPara->buf_out.size = m2m_eng_conf.out_len;
	cryptoPara->buf_len = m2m_eng_conf.out_len;
	CA_DEBUG(0, "DVR Decrypt out len:%#x\n", cryptoPara->buf_len);

	vmx_bc_unlock();
	return 0;
}

static int vmx_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
	uint16_t rc;
	uint8_t dvbtime[5];
	vmx_storeinfo_t storeinfo;
	VMX_PrivateInfo_t *private_data;
	m2m_info_t m2m_info;
	uint8_t *p_vr_input_buffer = NULL;
	uint8_t *p_vr_output_buffer = NULL;
	uint32_t vr_buffer_len = 0;
	m2m_buffer_t m2m_buf;
	vmxca_result_t result;

	vmx_bc_lock();
	memset(&storeinfo, 0, sizeof(vmx_storeinfo_t));
	get_dvbsi_time(time(NULL), dvbtime);
	private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
	if (private_data == NULL) {
		CA_DEBUG(2, "error, not open session");
		vmx_bc_unlock();
		return -1;
	}

	if (!private_data->dat_fp) {
		int location_len = 0;
		char dat_fname[MAX_LOCATION_SIZE];

		private_data->service_index = alloc_service_idx(session);
		private_data->dvr_channelid = alloc_dvr_channelid();

		memset(dat_fname, 0, sizeof(dat_fname));
		location_len = strlen(cryptoPara->location);
		CA_DEBUG(2, "%s , strlen:%d\n", cryptoPara->location, location_len);
		if (location_len > 3) {
			int ret;
			struct stat buf;
			memcpy(dat_fname, cryptoPara->location, location_len - 3);
			sprintf(dat_fname + location_len - 3, ".dat");
			CA_DEBUG(0, "dat_fname: %s\n", dat_fname);
			ret = stat(dat_fname, &buf);
			if (ret == -1 && errno == ENOENT) {
				CA_DEBUG(2, "%s not exist\n", dat_fname);
				vmx_get_fname(dat_fname, cryptoPara->location,cryptoPara->segment_id);
			}
		} else {
			vmx_get_fname(dat_fname, cryptoPara->location,
				      cryptoPara->segment_id);
		}
		private_data->dat_fp = fopen(dat_fname, "r");
		if (!private_data->dat_fp) {
			CA_DEBUG(2, "%s open %s failed, %s", __func__, dat_fname, strerror(errno));
			free_service_idx(session, private_data->service_index);
			free_dvr_channelid(private_data->dvr_channelid);
			vmx_bc_unlock();
			return -1;
		}

		INIT_LIST_HEAD(&private_data->storeinfo_ctx.list);
		vmx_parser_storeinfo(private_data->dat_fp,
				     &private_data->storeinfo_ctx,
				     &private_data->recinfo,
				     &private_data->recinfolen,
				     &private_data->blocksize);

		memset(&m2m_info, 0, sizeof(m2m_info_t));
		m2m_info.engine_id = private_data->dvr_channelid;
		m2m_info.hw_mode = 0;
		rc = VMXCA_PipelineSetM2MInfo(private_data->pipeline.handle,  &m2m_info);
		if (rc) {
			CA_DEBUG(2, "Replay Set M2M info failed\n");
		}

		{
			/*
			 * When DVR replay, VMX library call Check SVP before SEC_M2M_Steup, vmx call 
			 * sequence is wrong, but they don't want change. So we add this workaround code,
			 * sync secure buffer with R2R engine index before replay
			 * */
			memset(&m2m_buf, 0, sizeof(m2m_buf));
			m2m_buf.p = (uint8_t *)cryptoPara->buf_in.addr;
			m2m_buf.len = cryptoPara->buf_in.size;
			m2m_buf.is_secure = 0;
			result = VMXCA_GetViewRightInputPadBuffer(private_data->dvr_channelid,
					&m2m_buf, &p_vr_input_buffer, &vr_buffer_len);

			m2m_buf.p = (uint8_t *)cryptoPara->buf_out.addr;
			m2m_buf.len = cryptoPara->buf_out.size;
			m2m_buf.is_secure = 1;
			result = VMXCA_GetViewRightOutputPadBuffer(private_data->dvr_channelid,
					&m2m_buf, &p_vr_output_buffer, &vr_buffer_len);
			CA_DEBUG(0, "@@ Replay crypto vr_input:%p, vr_out:%p, len:%#x, ret:%#x", p_vr_input_buffer,
					p_vr_output_buffer, vr_buffer_len, result);
		}

		vmx_get_storeinfo(&private_data->storeinfo_ctx, cryptoPara->offset, &storeinfo);
		memcpy(&private_data->cur_storeinfo, &storeinfo, sizeof(vmx_storeinfo_t));
		rc = BC_DVRReplay(private_data->dvr_channelid, private_data->recinfo,
				  private_data->recinfolen, storeinfo.info,
				  storeinfo.len, dvbtime);
		CA_DEBUG(0, "Replay with record info\n");
	} else {
		vmx_get_storeinfo(&private_data->storeinfo_ctx, cryptoPara->offset, &storeinfo);
		memcpy(&private_data->cur_storeinfo, &storeinfo, sizeof(vmx_storeinfo_t));

		rc = BC_DVRReplay(private_data->dvr_channelid, NULL, 0, storeinfo.info,
				  storeinfo.len, dvbtime);
		CA_DEBUG(0, "Replay without record info\n");
	}


	CA_DEBUG(0, "CAS Replay start(%d, %d, %#x)",
		private_data->dvr_channelid,
		private_data->recinfolen,
		storeinfo.len);

	if (rc != k_BcSuccess) {
		CA_DEBUG(0, "BC_DVRReplay failed, rc = %d", rc);
		free_service_idx(session, private_data->service_index);
		free_dvr_channelid(private_data->dvr_channelid);
		vmx_bc_unlock();
		return -1;
	}

	cryptoPara->buf_in.size = private_data->blocksize;
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

	free_service_idx(session, private_data->service_index);
	free_dvr_channelid(channelid);
	if (private_data->dat_fp) {
		fclose(private_data->dat_fp);
		if (private_data->recinfo) {
			free(private_data->recinfo);
			private_data->recinfolen = 0;
		}
		vmx_free_storeinfo(&private_data->storeinfo_ctx);
	}

	vmx_bc_unlock();

	return 0;
}

static SecMemHandle vmx_create_secmem(CasSession session, CA_SERVICE_TYPE_t type, void **pSecBuf, uint32_t *size)
{
	int ret;
	VMX_PrivateInfo_t *private_data;

	UNUSED(type);
	CA_DEBUG(1, "%s called\n", __func__);
	private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
	if (private_data->pipeline.mode == PIPELINE_MODE_LIVE
		|| size == NULL ) {
		CA_DEBUG(1, "wrong param\n");
		return (SecMemHandle)NULL;
	}

	if (*size == 0) {
		*size = DVR_SIZE * 2;
	}

	ret = VMXCA_PipelineAllocSecMem(private_data->pipeline.handle, *size, pSecBuf);
	if (ret) {
		CA_DEBUG(1, "alloc secmem failed. size:%#x, ret:%d\n", *size, ret);
		*pSecBuf = NULL;
	}

	CA_DEBUG(1, "alloc secmem, mode:%d\n", private_data->pipeline.mode);
	return (SecMemHandle) * pSecBuf;
}

static int vmx_destroy_secmem(CasSession session, SecMemHandle handle)
{
	VMX_PrivateInfo_t *private_data;

	private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
	if (private_data->pipeline.handle != -1 && handle) {
		VMXCA_PipelineFreeSecMem(private_data->pipeline.handle, (void *)handle);
	}

	return 0;
}

static int vmx_register_event_cb(CasSession session, CAS_EventFunction_t event_fn)
{
	VMX_PrivateInfo_t *private_data;

	vmx_bc_lock();
	if (!session) {
		g_event_cb = event_fn;
	} else {
		private_data = (VMX_PrivateInfo_t *)((CAS_SessionInfo_t *)session)->private_data;
		private_data->event_cb = event_fn;
	}
	vmx_bc_unlock();

	return 0;
}

static int vmx_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len)
{
	return vmx_interact_ioctl(session, in_json, out_json, out_len);
}

static char *vmx_get_version(void)
{
	return CAS_HAL_VER;
}
