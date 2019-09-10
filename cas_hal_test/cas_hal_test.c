#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <byteswap.h>
#include <signal.h>

#include <am_debug.h>
#include <am_fend.h>
#include <am_dmx.h>
#include <am_smc.h>
#include <am_dsc.h>
#include <am_av.h>
#include <am_misc.h>
#include <am_dvr.h>

#include "am_cas.h"

#define FEND_DEV_NO (0)
#define DMX_DEV_NO (0)
#define AV_DEV_NO (0)
#define DSC_DEV_NO (0)
#define DVR_DEV_NO (0)

#define VMX_SYS_ID (0x1724)
#define DVR_BUFFER_SIZE (512*1024)
#define RECORD_BLOCK_SIZE (256*1024)//same to asyncfifo flush size, it's enc block size and dec block size//65424

#define AML_INFODATA_MAGIC 0x0a31061c
typedef struct __attribute__((__packed__)) aml_infodata_s {
    uint32_t magic;
    uint16_t vpid;
    uint16_t apid;
    uint16_t vfmt;
    uint16_t afmt;
} aml_infodata_t;

typedef enum {
    DEMOD_LOCK,
    LIVE_PLAY,
    DVR_RECORD,
    DVR_PLAY,
    INVALID_TYPE
}CAS_WorkType_t;

typedef struct {
    int vpid;
    int apid;
    int vfmt;
    int afmt;
    int service_id;
    int service_mode;
    int ecm_pid;
    int emm_pid;
    int scrambled;
}Program_Info_t;

typedef struct {
    uint8_t service_idx;
    uint8_t dvrchannelid;
    int tsfd;
    int datfd;
    int dumpfd;
    uint64_t streampos;
    int id;
    pthread_t thread;
    int running;
    uint8_t *crypt_buf;
} DVRData;

static DVRData g_dvr_data = {0};
static CasHandle g_cas_handle = 0;
static CasSession g_cas_session = 0;
static CAS_WorkType_t g_work_type = INVALID_TYPE;

typedef struct {
    unsigned int addr;
    unsigned int len;
}dvr_block;

static void *dvr_record_thread(void *arg)
{
    int ret;
    AM_CA_CryptoPara_t cryptoPara;
    AM_CA_StoreInfo_t storeInfo;
    DVRData *dd = (DVRData *)arg;
    dvr_block blk;

    CA_DEBUG(0, "Data thread for DVR%d start", dd->id);

    while(dd->running)
    {
	memset(&blk, 0x0, sizeof(dvr_block));
	ret = AM_DVR_Read(DVR_DEV_NO, (uint8_t *)&blk, sizeof(dvr_block), 1000);
	if (ret == -1) {
	    sleep(1);
	    CA_DEBUG(2, "dvr read nothing\r\n");
	    continue;
	}
	if(blk.len != RECORD_BLOCK_SIZE) {
	    printf("\nAPP Warnning get dvr len:%d !!!!!!\n\n", blk.len);
	}

	CA_DEBUG(0, "DVR read, addr->%#x, len:%#x, ret:%d\n",
		blk.addr, blk.len, ret);

	cryptoPara.buf_in = (uint8_t *)blk.addr;
	cryptoPara.buf_out = dd->crypt_buf;
	cryptoPara.buf_len = blk.len;

	memset(&storeInfo, 0x0, sizeof(AM_CA_StoreInfo_t));
	ret = AM_CA_DVREncrypt(g_cas_session, &cryptoPara, &storeInfo);
	if (ret) {
	    CA_DEBUG(2, "CAS encrypt failed.\r\n");
	    continue;
	}
	if (storeInfo.actualStoreInfoLen) {
	    uint64_t streampos = bswap_64(dd->streampos);
	    if (write(dd->datfd, &streampos, sizeof(streampos)) != sizeof(streampos)) {
		CA_DEBUG( 0, "%s L%d", __func__, __LINE__);
		return NULL;
	    }
	    uint16_t wrstorelen = bswap_16(storeInfo.actualStoreInfoLen);
	    if (write(dd->datfd, &wrstorelen, sizeof(wrstorelen)) != sizeof(wrstorelen)) {
                CA_DEBUG( 0, "%s L%d", __func__, __LINE__);
                 return NULL;
            }
            if (write(dd->datfd, storeInfo.storeInfo, storeInfo.actualStoreInfoLen) != storeInfo.actualStoreInfoLen) {
                CA_DEBUG( 0, "%s L%d", __func__, __LINE__);
                return NULL;
            }
	}

	if (write(dd->tsfd, cryptoPara.buf_out, blk.len) != blk.len) {
            CA_DEBUG(0, "DVR write file failed: %s", strerror(errno));
            return NULL;
        }

	dd->streampos += blk.len;
    }

    return NULL;
}

static void *dvr_play_thread(void *arg)
{
    DVRData *dd = (DVRData *)arg;

    int ret;
    uint32_t len;
    uint8_t *bufout = NULL;
    uint8_t *tmp_buf = NULL;
    uint32_t blockSize;
    uint16_t infoLen;
    uint8_t *infodata = NULL;
    uint64_t streamPos;
    uint64_t nextStreamPos;
    uint16_t storeInfoLen;
    uint8_t *storeInfo = NULL;
    uint16_t storeInfoMaxLen = 0;
    int needsetinfo = 1;
    uint32_t tspos = 0;

    AM_CA_StoreInfo_t caStoreInfo;
    AM_CA_PrivateInfo_t caPrivateInfo;
    AM_CA_CryptoPara_t cryptoPara;

    if ((len = read(dd->datfd, &blockSize, 4)) != 4) {
	goto fail;
    }
    blockSize = bswap_32(blockSize);
    printf("blockSize = %#x\r\n", blockSize);

    if (AM_CA_GetSecureBuffer(&bufout, blockSize)) {
	goto fail;
    }

    if ((len = read(dd->datfd, &infoLen, 2)) != 2) {
	goto fail;
    }
    infoLen = bswap_16(infoLen);

    if ((infodata = malloc(infoLen + 1)) == NULL) {
	goto fail;
    }

    if ((len = read(dd->datfd, infodata, infoLen)) != infoLen) {
	goto fail;
    }
    infodata[infoLen] = 0;

    CA_DEBUG(0, "infolen [%#x]", infoLen);

    if ((len = read(dd->datfd, &nextStreamPos, 8)) != 8) {
	goto fail;
    }
    nextStreamPos = bswap_64(nextStreamPos);

    tmp_buf = malloc(1024*1024);

    while (dd->running) {
	streamPos = nextStreamPos;
	if (streamPos == ULLONG_MAX) {
	    break;
	}
	if ((len = read(dd->datfd, &storeInfoLen, 2)) != 2) {
	    goto failstop;
	}
	storeInfoLen = bswap_16(storeInfoLen);
	CA_DEBUG(0, "storeInfolen [%#x]", storeInfoLen);
	if (storeInfoLen > storeInfoMaxLen) {
	    uint8_t *p;
	    if ((p = realloc(storeInfo, storeInfoLen)) == NULL) {
		goto failstop;
	    }
	    storeInfo = p;
	    storeInfoMaxLen = storeInfoLen;
	}
        if ((len = read(dd->datfd, storeInfo, storeInfoLen)) != storeInfoLen) {
            goto failstop;
        }
        nextStreamPos = ULLONG_MAX;
        len = read(dd->datfd, &nextStreamPos, 8 );
        nextStreamPos = bswap_64( nextStreamPos );
        printf( "2-read nextStreamPos->%d\n", nextStreamPos);

dvrreplay:
	memcpy(caStoreInfo.storeInfo, storeInfo, storeInfoLen);
	caStoreInfo.actualStoreInfoLen = storeInfoLen;
	memcpy(caPrivateInfo.info, infodata, infoLen);
	caPrivateInfo.infoLen = infoLen;
	ret = AM_CA_DVRReplay(g_cas_session, &caStoreInfo, &caPrivateInfo);
	if (ret) {
	    printf("CAS DVR play failed. [%#x, %#x]\r\n", storeInfoLen, infoLen);
	    goto failstop;
	}
        if (needsetinfo) {
            needsetinfo = 0;
            infoLen = 0;
            free(infodata);
            infodata = NULL;
        }

	while (tspos < nextStreamPos) {
            if ((len = read(dd->tsfd, caPrivateInfo.reserved, blockSize)) < 0) {
                printf("%s L%d", __func__, __LINE__ );
                goto failstop;
            }
            printf("3.read data, bs:%d, len:%d. buf[%#x]\n", blockSize, len, caPrivateInfo.reserved);
            if (len == 0) {
                printf("%s L%d", __func__, __LINE__);
                break;
            }

	    cryptoPara.buf_in = caPrivateInfo.reserved;
	    cryptoPara.buf_out = bufout;
	    cryptoPara.buf_len = blockSize;
	    ret = AM_CA_DVRDecrypt(g_cas_session, &cryptoPara);
	    if (ret) {
		printf("CAS DVR decrypt failed. [%#x, %#x, %#x]\r\n", cryptoPara.buf_in, bufout, blockSize);
		goto failstop;
	    }
	    tspos += blockSize;

	    ret = 0;//CA_CopyNormal(bufout, blockSize, tmp_buf, &len);
	    if (ret < 0) printf("++failed to copy\r\n");
	    if (write(dd->dumpfd, tmp_buf, len) != len) {
		printf("dump write failed\r\n");
	    }
	}
    }
    AM_CA_DVRStopReplay(g_cas_session);
    return 0;

failstop:
    AM_CA_DVRStopReplay(g_cas_session);

fail:
    CA_DEBUG(0, "dvr play thread failed");
    if (infodata) free(infodata);
    if (storeInfo) free(storeInfo);
    if (tmp_buf) free(tmp_buf);
    if (dd->tsfd >= 0) close(dd->tsfd);
    if (dd->datfd >= 0) close(dd->datfd);
    if (dd->dumpfd >= 0) close(dd->dumpfd);
    return (void*)1;
}

static int fend_lock() {
    AM_FEND_OpenPara_t fpara;
    struct dvb_frontend_parameters p;
    fe_status_t status;

    memset(&fpara, 0, sizeof(fpara));
    fpara.mode = FE_QAM;
    AM_TRY(AM_FEND_Open(FEND_DEV_NO, &fpara));

    AM_FEND_SetMode(FEND_DEV_NO, fpara.mode);

    p.frequency = 666000000;
    p.u.qam.symbol_rate = 6870000;
    p.u.qam.fec_inner = FEC_AUTO;
    p.u.qam.modulation = QAM_64;

    AM_TRY(AM_FEND_Lock(FEND_DEV_NO, &p, &status));

    AM_FEND_Close( FEND_DEV_NO );

    if (status & FE_HAS_LOCK) {
        printf("locked\n");
        return 0;
    }
    else {
        printf("unlocked\n");
        return -1;
    }
}

static int dvb_init(void)
{
    int ret;
    AM_DMX_OpenPara_t dmx_para;
    AM_DSC_OpenPara_t dsc_para;
    AM_DVR_OpenPara_t dvr_para;
    AM_AV_OpenPara_t av_para;
    uint8_t *secure_buf = NULL;
    uint8_t tmp_buf[32] = {0};

    memset(&dmx_para, 0x0, sizeof(AM_DMX_OpenPara_t));
    memset(&dsc_para, 0x0, sizeof(AM_DSC_OpenPara_t));
    memset(&dvr_para, 0x0, sizeof(AM_DVR_OpenPara_t));
    memset(&av_para, 0x0, sizeof(AM_AV_OpenPara_t));

    if (AM_AV_Open(AV_DEV_NO, &av_para)) {
	CA_DEBUG(0, "av device open fail\n");
    }

    if (AM_DMX_Open(DMX_DEV_NO, &dmx_para)) {
	CA_DEBUG(0, "dmx device open fail\n");
    }

    if (AM_DSC_Open(DSC_DEV_NO, &dsc_para)) {
	CA_DEBUG(0, "dsc device open fail\n");
    }

    if (AM_DVR_Open(DVR_DEV_NO, &dvr_para)) {
	CA_DEBUG(0, "dvr device open fail\n");
    }

    AM_DMX_SetSource(DMX_DEV_NO, AM_DMX_SRC_TS0);
    AM_AV_SetTSSource(AV_DEV_NO, AM_AV_TS_SRC_DMX0);
    AM_DSC_SetSource(DSC_DEV_NO, AM_DSC_SRC_DMX0);
    AM_DVR_SetSource(DVR_DEV_NO, 0);

    ret = AM_CA_Init(VMX_SYS_ID, &g_cas_handle);
    if (ret) {
	printf("CAS init failed. ret = %d\r\n", ret);
    }
    if (AM_CA_GetSecureBuffer(&secure_buf, DVR_BUFFER_SIZE)) {
	printf("CAS get secure buffer failed. \r\n");
	return -1;
    }
    sprintf(tmp_buf, "%d", secure_buf);
    AM_FileEcho( "/sys/class/stb/asyncfifo0_secure_enable", "1" );//enable secure pvr
    AM_FileEcho( "/sys/class/stb/asyncfifo0_secure_addr", tmp_buf );
    AM_FileEcho( "/sys/class/stb/demux_reset", "1");

    return 0;
}

static Program_Info_t *get_program(unsigned int program_num)
{
    Program_Info_t *prog = NULL;

    prog = (Program_Info_t *)malloc(sizeof(Program_Info_t));
    if (!prog) {
	return NULL;
    }
#if 0
    prog->vpid = 0x22;
    prog->apid = 0x21;
    prog->vfmt = 0;
    prog->afmt = 0;
    prog->service_id = 0xa;
    prog->service_mode = 0;
    prog->scrambled = 0;
#else
    prog->vpid = 0x101;
    prog->apid = 0x102;
    prog->vfmt = 0;
    prog->afmt = 0;
    prog->service_id = 1059;
    prog->service_mode = 0;
    prog->ecm_pid = 0x603;
    prog->emm_pid = 0x1800;
    prog->scrambled = 1;
#endif
    return prog;
}

static int play_program(Program_Info_t *prog)
{
    int ret;

    AM_AV_InjectPara_t play_para;
    AM_CA_ServiceInfo_t cas_para;

    play_para.vid_fmt = prog->vfmt;
    play_para.aud_fmt = prog->afmt;
    play_para.pkg_fmt = PFORMAT_TS;
    play_para.vid_id  = prog->vpid;
    play_para.aud_id  = prog->apid;

    AM_AV_StartTS(AV_DEV_NO, play_para.vid_id, play_para.aud_id, play_para.vid_fmt, play_para.aud_fmt);

    if (!prog->scrambled)
	return 0;

    ret = AM_CA_SetEmmPid(g_cas_handle, prog->emm_pid);
    if (ret) {
	printf("CAS set emm PID failed. ret = %d\r\n", ret);
	return -1;
    }

    ret = AM_CA_OpenSession(g_cas_handle, &g_cas_session);
    if (ret) {
	printf("CAS open session failed. ret = %d\r\n", ret);
	return -1;
    }

    memset(&cas_para, 0x0, sizeof(AM_CA_ServiceInfo_t));
    cas_para.service_id = prog->service_id;
    cas_para.service_mode = prog->service_mode;
    cas_para.service_type = SERVICE_PLAY;
    cas_para.ecm_pid = prog->ecm_pid;
    cas_para.stream_pids[0] = prog->vpid;
    cas_para.stream_pids[1] = prog->apid;
    cas_para.stream_num = 2;
    cas_para.ca_private_data_len = 0;
    ret = AM_CA_StartDescrambling(g_cas_session, &cas_para);
    if (ret) {
	printf("CAS start descrambling failed. ret = %d\r\n", ret);
	return -1;
    }

    return 0;
}

static int record_program(Program_Info_t *prog, char *tspath)
{
    int ret;
    char *datpath = NULL;
    uint32_t len;
    uint16_t infolen;
    aml_infodata_t *a;
    uint32_t blockSize = RECORD_BLOCK_SIZE;

    if ( !tspath)
        return -1;
    len = strlen(tspath);
    datpath = malloc(len + 2);
    if (!datpath)
        return -1;
    if (strcmp(tspath + len - 3, ".ts") == 0) {
        memcpy(datpath, tspath, len - 3);
        strcpy(datpath + len - 3, ".dat");
    }

    AM_DVR_StartRecPara_t dvr_para;
    AM_CA_ServiceInfo_t cas_para;
    AM_CA_PrivateInfo_t cas_pri_info;

    DVRData *dd = (DVRData *)&g_dvr_data;

    if (!prog->scrambled) {
	goto record;
    }

    ret = AM_CA_SetEmmPid(g_cas_handle, prog->emm_pid);
    if (ret) {
	printf("CAS set emm PID failed. ret = %d\r\n", ret);
	return -1;
    }

    ret = AM_CA_OpenSession(g_cas_handle, &g_cas_session);
    if (ret) {
	printf("CAS open session failed. ret = %d\r\n", ret);
	return -1;
    }

    memset(&cas_para, 0x0, sizeof(AM_CA_ServiceInfo_t));
    cas_para.service_id = prog->service_id;
    cas_para.service_mode = prog->service_mode;
    cas_para.service_type = SERVICE_PLAY;
    cas_para.ecm_pid = prog->ecm_pid;
    cas_para.stream_pids[0] = prog->vpid;
    cas_para.stream_pids[1] = prog->apid;
    cas_para.stream_num = 2;
    cas_para.ca_private_data_len = 0;

    memset(&cas_pri_info, 0x0, sizeof(AM_CA_PrivateInfo_t));
    cas_pri_info.infoLen = sizeof(cas_pri_info.info);

    a = (aml_infodata_t*)cas_pri_info.info;
    a->magic = AML_INFODATA_MAGIC;
    a->vpid = prog->vpid;
    a->apid = prog->apid;
    a->vfmt = prog->vfmt;
    a->afmt = prog->afmt;
    ret = AM_CA_DVRStart(g_cas_session, &cas_para, &cas_pri_info);
    if (ret) {
	printf("CAS start DVR failed. ret = %d\r\n", ret);
	return -1;
    }

    dd->crypt_buf = cas_pri_info.reserved;
    CA_DEBUG(0, "R2R out buffer addr: %#x\r\n", dd->crypt_buf);

record:
    dd->tsfd = open( tspath, O_WRONLY | O_CREAT | O_TRUNC, 0666 );
    dd->datfd = open( datpath, O_WRONLY | O_CREAT | O_TRUNC, 0666 );
    free(datpath);

    blockSize = bswap_32(blockSize);
    if (write(dd->datfd, &blockSize, sizeof(blockSize)) != sizeof(blockSize)) {
	CA_DEBUG(0, "DVR record write dat failed[l%d]", __LINE__);
	return -1;
    }

    infolen = bswap_16(cas_pri_info.infoLen);
    if (write(dd->datfd, &infolen, sizeof(infolen)) != sizeof(infolen)) {
	CA_DEBUG(0, "DVR record write dat failed[l%d]", __LINE__);
	return -1;
    }

    infolen = cas_pri_info.infoLen;
    CA_DEBUG(0, "write pri infolen [%#x]", infolen);
    if (write(dd->datfd, cas_pri_info.info, infolen) != infolen) {
	CA_DEBUG(0, "DVR record write dat failed[l%d]", __LINE__);
	return -1;
    }

    dvr_para.pid_count = 2;
    dvr_para.pids[0] = prog->vpid;
    dvr_para.pids[1] = prog->apid;
    ret = AM_DVR_StartRecord(DVR_DEV_NO, &dvr_para);
    if (ret) {
	printf("AM start DVR failed. ret = %d\r\n", ret);
	return -1;
    }

    dd->running = 1;
    pthread_create(&dd->thread, NULL, dvr_record_thread, dd);

    return 0;
}

static int replay_program(Program_Info_t *prog, char *tspath)
{
    int ret;
    int len;
    char *datpath = NULL;
    char *dumppath = NULL;
    DVRData *dd = (DVRData *)&g_dvr_data;
    if (!tspath) {
	return -1;
    }

    len = strlen(tspath);
    datpath = malloc(len + 2);
    dumppath = malloc(len + 6);
    if (!datpath || !dumppath) {
	return -1;
    }
    if (strcmp(tspath + len - 3, ".ts") == 0) {
        memcpy(datpath, tspath, len - 3);
        strcpy(datpath + len - 3, ".dat");
        memcpy(dumppath, tspath, len - 3);
        strcpy(dumppath + len - 3, "_dump.ts");
    }

    dd->running = 1;
    dd->tsfd = open(tspath, O_RDONLY);
    dd->datfd = open(datpath, O_RDONLY);
    dd->dumpfd = open( dumppath, O_WRONLY | O_CREAT | O_TRUNC, 0666 );

    ret = AM_CA_OpenSession(g_cas_handle, &g_cas_session);
    if (ret) {
	printf("CAS open session failed. ret = %d\r\n", ret);
	return -1;
    }
    pthread_create(&dd->thread, NULL, dvr_play_thread, dd);

    return 0;
}

static void handle_signal(int signal)
{
    if (g_work_type == LIVE_PLAY) {
	AM_CA_StopDescrambling(g_cas_session);
	AM_CA_CloseSession(g_cas_session);
    }

    if (g_work_type == DVR_RECORD) {
	AM_CA_DVRStop(g_cas_session);
	AM_CA_CloseSession(g_cas_session);
    }

    if (g_work_type == DVR_PLAY) {
	AM_CA_DVRStopReplay(g_cas_session);
	AM_CA_CloseSession(g_cas_session);
    }

    //free()
    //thread_join

    AM_DVR_Close(0);
    AM_DSC_Close(DSC_DEV_NO);
    AM_DMX_Close(DMX_DEV_NO);
    AM_AV_Close(AV_DEV_NO);

    exit( EXIT_SUCCESS );
}

static void init_signal_handler()
{
    struct sigaction act;
    act.sa_handler = handle_signal;
    sigaction(SIGINT, &act, NULL);
}

int main(int argc, char *argv[])
{
    int ret;
    int running = 1;
    char *tspath = NULL;
    unsigned int prog_num = 1059;
    Program_Info_t *prog = NULL;

    if (argc < 3) {
	printf("Usage: cas_hal_test liveplay program_num\r\n");
	printf("Usage: cas_hal_test dvrrecord path\r\n");
	printf("Usage: cas_hal_test dvrplay path\r\n");
	exit(EXIT_SUCCESS);
    }

    init_signal_handler();

    if (strcmp(argv[1], "demodlock") == 0) {
	g_work_type = DEMOD_LOCK;
    } else if (strcmp(argv[1], "liveplay") == 0) {
	g_work_type = LIVE_PLAY;
    } else if (strcmp(argv[1], "dvrrecord") == 0) {
	tspath = argv[2];
	g_work_type = DVR_RECORD;
    } else if (strcmp(argv[1], "dvrplay") == 0) {
	tspath = argv[2];
	g_work_type = DVR_PLAY;
    }

    printf("@@@in cas_hal_test g_work_type = %d\r\n", g_work_type);

    dvb_init();
    CA_DEBUG(0, "dvb init done");

    prog = get_program(prog_num);
    switch (g_work_type) {
	case DEMOD_LOCK:
	    fend_lock();
	    break;
	case LIVE_PLAY:
	    play_program(prog);
	    break;

	case DVR_RECORD:
	    record_program(prog, tspath);
	    break;

	case DVR_PLAY:
	    replay_program(prog, tspath);
	    break;
    }

    while ( running ) {
        printf( "********************\n" );
        printf( "* commands:\n" );
        printf( "* quit\n" );

        char buf[256];
        memset( buf, 0 , 256 );
        printf( "********************\n" );

        if (fgets( buf, 256, stdin)) {
            if ( !strncmp( buf, "quit", 4 ) ) {
                running = 0;
	    }
	}
    }

    ret = AM_CA_StopDescrambling(g_cas_session);
    ret |= AM_CA_CloseSession(g_cas_session);
    if (ret) {
	printf("CAS stop failed.\r\n");
    }

    AM_AV_StopTS(AV_DEV_NO);
    AM_DVR_Close(0);

    AM_DSC_Close(DSC_DEV_NO);
    AM_DMX_Close(DMX_DEV_NO);
    AM_AV_Close(AV_DEV_NO);

    exit( EXIT_SUCCESS );
}
