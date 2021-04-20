/**
 * \page Test
 * \section Introduction
 * test code with CAS Hal APIs.
 * It supports:
 * \li Live
 * \li Record
 * \li Playback
 * \li Timeshift
 *
 * \section Usage
 *
 * Help msg will be shown if the test runs without parameters.\n
 * There are some general concepts for the parameters:
 *
 * For Live:
 * \code
 *   cas_hal_test live <fend_dev_no> <input_dev_no> <prog_index> <freqM>
 * \endcode
 * For Live local:
 * \code
 *   cas_hal_test local <tsfile> <prog_index>
 * \endcode
 * For playback:
 * \code
 *   cas_hal_test dvrplay <tsfile> <scramble_flag>
 * \endcode
 * the timeshift backgroud recording file will be located in /data/data as:
 * \code
 *   /data/data/timeshifting-xxxx.*
 * \endcode
 *
 * \section FormatCode Format Code
 *
 * \li quit\n
 *             quit the test
 */
#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "AmTsPlayer.h"
#include "dvr_segment.h"
#include "dvr_wrapper.h"
#include "dvb_utils.h"
#include "fend.h"

#ifdef UNUSED
#undef UNUSED
#endif

#include "am_cas.h"
#include "cas_json.h"
#include "scan.h"

#define INF(fmt, ...)       fprintf(stdout, fmt, ##__VA_ARGS__)
#define ERR(fmt, ...)       fprintf(stderr, "error:" fmt, ##__VA_ARGS__)

#define FEND_DEV_NO (0)
#define DMX_DEV_NO (0)
#define DMX_DEV_NO_2ND (1)
#define AV_DEV_NO (0)
#define DSC_DEV_NO (0)
#define DVR_DEV_NO (0)
#define MAX_REC_NUM (4)

#define VMX_CAS_STRING "Verimatrix"

#define INJECT_LENGTH (188*1024)
#define BLOCK_SIZE (188*1024)//same to asyncfifo flush size, it's enc block size and dec block size//65424

#define DVR_STREAM_TYPE_TO_TYPE(_t) (((_t) >> 24) & 0xF)
#define DVR_STREAM_TYPE_TO_FMT(_t)  ((_t) & 0xFFFFFF)

#define has_live(_m_)        ((_m_) & LIVE)
#define has_live_local(_m_)  ((_m_) & LIVE_LOCAL)
#define has_playback(_m_)    ((_m_) & PLAYBACK)
#define has_recording(_m_)   ((_m_) & RECORDING)
#define is_live(_m_)         ((_m_) == LIVE)
#define is_live_local(_m_)   ((_m_) == LIVE_LOCAL)
#define is_playback(_m_)     ((_m_) == PLAYBACK)
#define is_timeshifting(_m_) ((_m_) == TIMESHIFTING)
#define is_ext_playback(_m_)     ((_m_) == EXT_PLAYBACK)

struct vm_config_t {
    uint8_t run;
    uint8_t on;
    uint8_t config;
    uint8_t strength;
} g_vm_config = {0};

struct oc_config_t {
    uint8_t run;
    uint32_t flag;
    uint8_t analog;
    uint8_t cgmsa;
    uint8_t emicci;
} g_oc_config = {0};

typedef struct
{
    CasSession cas_session;
    SecMemHandle secmem_session;
    void *dvr_session; //'DVR_WrapperPlayback_t *' or 'DVR_WrapperRecord_t *'
    am_tsplayer_handle player_session;
    int replayed;
} CasTestSession;

typedef enum {
    PIN_NEED_CHECK,
    PIN_CHECK_SUCCESS,
    PIN_CHECK_FAILED,
    PIN_MAX,
} PIN_STATUS;

static int mode = 0;
static int duration=180000;
static int size=1024*1024*1024;
static char *pfilename = "/data/data/timeshifting.ts";
static int check_pin_status = PIN_MAX;
static int rec_status = 0;

enum {
    LIVE        = 0x01,
    LIVE_LOCAL  = 0x02,
    PLAYBACK    = 0x04,
    RECORDING   = 0x08,
    TIMESHIFTING = PLAYBACK | RECORDING | 0x10,
    EXT_PLAYBACK = PLAYBACK | 0x10,
};

static CasHandle g_cas_handle = 0;
static CasTestSession play;
static CasTestSession recorder[MAX_REC_NUM];
static pthread_t gInjectThread;
static int running = 1;
static int gInjectRunning = 0;

static int watermark_test_config(
	uint8_t on,
	uint8_t config,
	uint8_t strength);
static int output_control_test_config(
	uint32_t flag,
	uint8_t analog,
	uint8_t cgmsa,
	uint8_t emicci);
static AM_RESULT cas_event_cb(CasSession session, char *json);
static void video_callback(void *user_data, am_tsplayer_event *event);
extern int ext_dvr_playback_stop(void);
extern int ext_dvr_playback(const char *path, CasHandle cas_handle);
extern int dvr_wrapper_set_playback_secure_buffer (DVR_WrapperPlayback_t playback,
					    uint8_t *p_secure_buf,
					    uint32_t len);

static int fend_lock(int dev_no, int freqM)
{
    int ret;
    int fend_id;
    int wait_time = 3;
    dmd_delivery_t delivery;
    dmd_tuner_event_t status;

    if (open_fend(dev_no, &fend_id)) {
	ERR("fend open failed\n");
    }

    memset(&delivery, 0, sizeof(delivery));
    delivery.device_type = DMD_CABLE;
    delivery.delivery.cable.frequency = freqM*1000;
    delivery.delivery.cable.symbol_rate = 5217;
    delivery.delivery.cable.modulation = DMD_MOD_QAM;//DMD_MOD_128QAM;
    ret = dmd_lock_c(fend_id, &delivery);

    INF("DVB-C: lock to freq:%d, modulation:%d symbol_rate:%d ret:%d \n",
	delivery.delivery.cable.frequency,
	delivery.delivery.cable.modulation,
	delivery.delivery.cable.symbol_rate,
	ret);

    if (ret) {
	ERR("lock failed, ret:%d\n", ret);
	return -1;
    }

    while (wait_time--){
	sleep(1);
	status = get_dmd_lock_status(fend_id);
	if (status == TUNER_STATE_LOCKED)
	    break;
    }

    return 0;
}

int init_tsplayer_inject(dvb_service_info_t *prog)
{
    int ret;
    am_tsplayer_handle session;
    am_tsplayer_input_source_type tsType = TS_MEMORY;
    am_tsplayer_input_buffer_type drmmode = TS_INPUT_BUFFER_TYPE_NORMAL;

    am_tsplayer_video_params vparam;
    am_tsplayer_audio_params aparam;
    am_tsplayer_init_params  parm = {tsType, drmmode, 0, 0};

    ret = AmTsPlayer_create(parm, &session);
    ret |= AmTsPlayer_setWorkMode(session, TS_PLAYER_MODE_NORMAL);
    ret |= AmTsPlayer_registerCb(session, video_callback, NULL);

    vparam.codectype = prog->i_vformat;

    vparam.pid = prog->i_video_pid;
    ret |= AmTsPlayer_setVideoParams(session, &vparam);

    memset(&aparam, 0, sizeof(aparam));
    aparam.codectype = prog->i_aformat;
    aparam.pid = prog->i_audio_pid;
    //aparam.seclevel = 10;
    ret |= AmTsPlayer_setAudioParams(session, &aparam);

    if (vparam.pid != 0 && vparam.pid != 0x1fff) {
        ret |= AmTsPlayer_startVideoDecoding(session);
	ret |= AmTsPlayer_showVideo(session);
	ret |= AmTsPlayer_setTrickMode(session, AV_VIDEO_TRICK_MODE_NONE);
    }
    if (aparam.pid != 0 && aparam.pid != 0x1fff) {
        ret |= AmTsPlayer_startAudioDecoding(session);
    }

    play.player_session = session;
    INF("%s ret:%d, session:%#x\n", __func__, ret, session);

    return 0;
}

static void *inject_thread(void *arg)
{
    int fd = -1;
    uint8_t buf[INJECT_LENGTH];
    char *tspath = (char *)arg;
    const int kRwTimeout = 30000;
    am_tsplayer_input_buffer ibuf = {TS_INPUT_BUFFER_TYPE_NORMAL, (char *)buf, 0};

    fd = open(tspath, O_RDONLY);
    INF("%s open %s, fd:%d\n", __func__, tspath, fd);
    if (fd == -1) {
	return NULL;
    }
    while (gInjectRunning) {
        int retry = 100;
	int kRwSize = 0;
        am_tsplayer_result res;

	kRwSize = read(fd, buf, INJECT_LENGTH);
	if (kRwSize <= 0) {
	    INF("%s read end of file, loop\n", __func__);
	    lseek(fd, 0, SEEK_SET);
	    continue;
	}
        ibuf.buf_size = kRwSize;

        do {
            res = AmTsPlayer_writeData(play.player_session, &ibuf, kRwTimeout);
            if (res == AM_TSPLAYER_ERROR_RETRY) {
                usleep(50000);
            } else {
		//INF("%#x Bytes injected\n", ibuf.buf_size);
                break;
	    }
        } while(res || retry-- > 0);
    }
    close(fd);
    INF("exit %s\n", __func__);
    return NULL;
}

static int dvb_init(void)
{
    int ret;

    ret = AM_CA_Init(&g_cas_handle);
    ret |= AM_CA_RegisterEventCallback((CasSession)NULL, cas_event_cb);
    INF("CAS init ret = %d\r\n", ret);

    return ret;
}

static AM_RESULT cas_event_cb(CasSession session, char *json)
{
    cJSON* cas;
    cJSON* input;
    cJSON* type;
    cJSON* state;

    UNUSED(session);
    INF("%s:%s\n", __func__, json);
    input = cJSON_Parse(json);
    if (input == NULL) {
	return -1;
    }
    cas = cJSON_GetObjectItemCaseSensitive(input, ITEM_CAS);
    if (!cJSON_IsString(cas) || (strcmp(cas->valuestring, VMX_CAS_STRING))) {
	INF("%s, not Vermatrix cas cmd\n", __func__);
	goto end;
    }
    type = cJSON_GetObjectItemCaseSensitive(input, ITEM_TYPE);
    if (!cJSON_IsString(type) || !type->valuestring) {
	INF("%s invalid cmd\n", __func__);
	goto end;
    }
    if (!strcmp(type->valuestring, ITEM_CHECK_PIN)) {
	check_pin_status = PIN_NEED_CHECK;
	INF("notify pin check status -> PIN_NEED_CHECK \n");
    } else if (!strcmp(type->valuestring, ITEM_PIN_STATE)) {
	state = cJSON_GetObjectItemCaseSensitive(input, ITEM_ERROR_CODE);
	if (!cJSON_IsNumber(state)) {
	    INF("%s invalid state type\n", __func__);
	    goto end;
	}
	if (state) {
	    check_pin_status = PIN_CHECK_SUCCESS;
	    INF("notify pin check status -> PIN_NEED_SUCCESS\n");
	} else {
	    check_pin_status = PIN_CHECK_FAILED;
	    INF("notify pin check status -> PIND_NEED_FAILED");
	}
    }
    return 0;

end:
    if (input) {
	cJSON_Delete(input);
    }

    return 0;
}

static DVR_Result_t encrypt_callback(DVR_CryptoParams_t *params, void *userdata)
{
    int ret;
    CasSession cas_session = *(CasSession *)userdata;
    AM_CA_CryptoPara_t *cryptoPara = (AM_CA_CryptoPara_t *)params;

    if (!cas_session) {
        ERR("%s invalid cas session\n", __func__);
        return -1;
    }

    ret = AM_CA_DVREncrypt(cas_session, cryptoPara);
    if (ret) {
        cryptoPara->buf_len = 0;
        cryptoPara->buf_out.size = 0;
        ERR("%s failed\n", __func__);
        return -1;
    }

    if (cryptoPara->buf_len) {
	//INF("%#x bytes encrypted\n", cryptoPara->buf_len);
    }

    return 0;
}

static DVR_Result_t decrypt_callback(DVR_CryptoParams_t *params, void *userdata)
{
    int ret;
    UNUSED(userdata);

    AM_CA_CryptoPara_t *cryptoPara = (AM_CA_CryptoPara_t *)params;

    if (!play.replayed) {
	ret = AM_CA_DVRReplay(play.cas_session, cryptoPara);
	play.replayed = 1;
	if (check_pin_status == PIN_NEED_CHECK) {
	    do {
		//INF("wait state %d\n", check_pin_status);
		usleep(200*1000);
	    } while (check_pin_status != PIN_CHECK_SUCCESS &&
		     running);
	    AM_CA_DVRReplay(play.cas_session, cryptoPara);
	}
    }
    ret = AM_CA_DVRDecrypt(play.cas_session, cryptoPara);
    if (ret) {
        cryptoPara->buf_len = 0;
        cryptoPara->buf_out.size = 0;
        ERR("%s failed\n", __func__);
        return -1;
    }

    if (cryptoPara->buf_len) {
	//INF("%#x bytes decrypted\n", cryptoPara->buf_len);
    }

    return 0;
}

static DVR_Result_t RecEventHandler(DVR_RecordEvent_t event, void *params, void *userdata)
{
   if (userdata != NULL)
   {
      DVR_WrapperRecordStatus_t *status = (DVR_WrapperRecordStatus_t *)params;

      UNUSED(status);
      switch (event)
      {
         case DVR_RECORD_EVENT_STATUS:
            //INF("Record event %d\n", status->state);
            break;
         default:
            //ERR("Unhandled recording event 0x%x from (%s)\n", event, (char *)userdata);
         break;
      }
   }
   return DVR_SUCCESS;
}

static void video_callback(void *user_data, am_tsplayer_event *event)
{
    UNUSED(user_data);
    INF("video evt callback, type:%d\r\n", event?event->type:0);
    switch (event->type) {
        case AM_TSPLAYER_EVENT_TYPE_VIDEO_CHANGED:
            INF("[evt] video changed\r\n");
            break;

        case AM_TSPLAYER_EVENT_TYPE_FIRST_FRAME:
            INF("[evt] first frame\r\n");
            break;
        default:
            break;
    }
}

static DVR_Result_t PlayEventHandler(DVR_PlaybackEvent_t event, void *params, void *userdata)
{
   UNUSED(params);

   if (userdata != NULL)
   {
      switch (event)
      {
         case DVR_PLAYBACK_EVENT_TRANSITION_OK:
            /**< Update the current player information*/
           //log_play_evt((DVR_WrapperPlaybackStatus_t *)params, userdata);
         break;
         case DVR_PLAYBACK_EVENT_REACHED_END:
            /**< File player's EOF*/
           //PLAY_EVT("EOF (%s)\n", (char *)userdata);
         break;
         default:
           //ERR("Unhandled event 0x%x from (%s)\n", event, (char *)userdata);
         break;
      }
   }
   return DVR_SUCCESS;
}

static void tsplayer_callback(void *user_data, am_tsplayer_event *event)
{
   UNUSED(user_data);

   if (event)
   {
      switch (event->type)
      {
          case AM_TSPLAYER_EVENT_TYPE_PTS:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_PTS: stream_type:%d, pts[%llu]\n",
                  event->event.pts.stream_type,
                  event->event.pts.pts);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_DTV_SUBTITLE:
          {
              uint8_t* pbuf = event->event.mpeg_user_data.data;
              uint32_t size = event->event.mpeg_user_data.len;
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_DTV_SUBTITLE: %x-%x-%x-%x ,size %d\n",
                  pbuf[0], pbuf[1], pbuf[2], pbuf[3], size);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_USERDATA_CC:
          {
              uint8_t* pbuf = event->event.mpeg_user_data.data;
              uint32_t size = event->event.mpeg_user_data.len;
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_USERDATA_CC: %x-%x-%x-%x ,size %d\n",
                  pbuf[0], pbuf[1], pbuf[2], pbuf[3], size);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_USERDATA_AFD:
          {
              uint8_t* pbuf = event->event.mpeg_user_data.data;
              uint32_t size = event->event.mpeg_user_data.len;
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_USERDATA_AFD: %x-%x-%x-%x ,size %d\n",
                  pbuf[0], pbuf[1], pbuf[2], pbuf[3], size);
              //USERDATA_AFD_t afd = *((USERDATA_AFD_t *)pbuf);
              //afd.reserved = afd.pts = 0;
              //INF("[evt] video afd changed: flg[0x%x] fmt[0x%x]\n", afd.af_flag, afd.af);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_VIDEO_CHANGED:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_VIDEO_CHANGED: [width:height] [%d x %d] @%d aspectratio[%d]\n",
              event->event.video_format.frame_width,
              event->event.video_format.frame_height,
              event->event.video_format.frame_rate,
              event->event.video_format.frame_aspectratio);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_AUDIO_CHANGED:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_AUDIO_CHANGED: sample_rate:%d, channels:%d\n",
                  event->event.audio_format.sample_rate,
                  event->event.audio_format.channels);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_DATA_LOSS:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_DATA_LOSS\n");
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_DATA_RESUME:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_DATA_RESUME\n");
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_SCRAMBLING:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_SCRAMBLING: stream_type:%d is_scramling[%d]\n",
                  event->event.scramling.stream_type,
                  event->event.scramling.scramling);
              break;
          }
          case AM_TSPLAYER_EVENT_TYPE_FIRST_FRAME:
          {
              INF("[evt] AM_TSPLAYER_EVENT_TYPE_FIRST_FRAME: ## VIDEO_AVAILABLE ##\n");
              break;
          }
          default:
              break;
      }
   }
}

static int start_descrambling(dvb_service_info_t *prog)
{
    int ret;
    AM_CA_ServiceInfo_t cas_para;
    CA_SERVICE_TYPE_t service_type = SERVICE_LIVE_PLAY;

    if (!prog->scrambled)
	return 0;

    ret = AM_CA_SetEmmPid(g_cas_handle, DMX_DEV_NO, prog->i_ca_pid);
    if (ret) {
        ERR("CAS set emm PID failed. ret = %d\r\n", ret);
    }

    ret = AM_CA_OpenSession(g_cas_handle, &play.cas_session, service_type);
    if (ret) {
        ERR("CAS open session failed. ret = %d\r\n", ret);
        return -1;
    }

    ret = AM_CA_RegisterEventCallback(play.cas_session, cas_event_cb);
    if (ret) {
        ERR("CAS RegisterEventCallback failed. ret = %d\r\n", ret);
    }

    memset(&cas_para, 0x0, sizeof(AM_CA_ServiceInfo_t));
    if (prog->service_type == IPTV_TYPE) {
	cas_para.service_mode = SERVICE_IPTV;
	INF("IPTV service mode:%d\n", cas_para.service_mode);
    } else {
	cas_para.service_mode = SERVICE_DVB;
	INF("DVB service mode:%d\n", cas_para.service_mode);
    }

    cas_para.service_id = prog->i_program_num;
    cas_para.service_type = SERVICE_LIVE_PLAY;
    cas_para.ecm_pid = prog->i_ecm_pid[0];
    cas_para.stream_pids[0] = prog->i_video_pid;
    cas_para.stream_pids[1] = prog->i_audio_pid;
    cas_para.stream_num = 2;
    if (prog->private_data[0]) {
	memcpy(cas_para.ca_private_data, prog->private_data, prog->private_data[0]);
    }
    cas_para.ca_private_data_len = prog->private_data[0];
    ret = AM_CA_StartDescrambling(play.cas_session, &cas_para);
    if (ret) {
        ERR("CAS start descrambling failed. ret = %d\r\n", ret);
        return -1;
    }

    INF("CAS started\r\n");
    return 0;
}

static int start_liveplay(dvb_service_info_t *prog)
{
    uint32_t num;
    am_tsplayer_result ret;
    am_tsplayer_video_params vparam;
    am_tsplayer_audio_params aparam;
    am_tsplayer_init_params param;
    am_tsplayer_avsync_mode avsyncmode = TS_SYNC_VMASTER;

    am_tsplayer_handle player_session;

    INF("vpid:%#x vfmt:%d apid:%#x afmt:%d ecmpid:%#x emmpid:%#x scramble:%d\r\n",
        prog->i_video_pid, prog->i_vformat,
        prog->i_audio_pid, prog->i_aformat,
        prog->i_ecm_pid[0], prog->i_ca_pid, prog->scrambled);

    memset(&param, 0 , sizeof(am_tsplayer_init_params));
    param.source = TS_DEMOD;
    param.dmx_dev_id = DMX_DEV_NO;
    if (prog->scrambled) {
        param.drmmode = TS_INPUT_BUFFER_TYPE_TVP;
	INF("enalbe live TVP\n");
    }

    ret = AmTsPlayer_create(param, &player_session);
    if (ret != AM_TSPLAYER_OK) {
        CA_DEBUG(0, "Create tslayer failed!!!! err:%x", ret);
        return -1;
    }
    play.player_session = player_session;

    ret = AmTsPlayer_getInstansNo(player_session, &num);
    ret |= AmTsPlayer_setWorkMode(player_session, TS_PLAYER_MODE_NORMAL);
    ret |= AmTsPlayer_registerCb(player_session, video_callback, NULL);
    ret |= AmTsPlayer_setSyncMode(player_session, avsyncmode);
    INF("create tsplayer success. session:%#x instance_no:%d ret:%d\r\n", player_session, num, ret);

    vparam.codectype = prog->i_vformat;
    vparam.pid = prog->i_video_pid;
    AmTsPlayer_setVideoParams(player_session, &vparam);
    AmTsPlayer_startVideoDecoding(player_session);

    memset(&aparam, 0, sizeof(aparam));
    aparam.codectype = prog->i_aformat;
    aparam.pid = prog->i_audio_pid;
    //aparam.seclevel = 10;
    AmTsPlayer_setAudioParams(player_session, &aparam);
    AmTsPlayer_startAudioDecoding(player_session);

    AmTsPlayer_showVideo(player_session);
    AmTsPlayer_setTrickMode(player_session, AV_VIDEO_TRICK_MODE_NONE);

    return 0;
}

static int stop_liveplay(void)
{
    if (play.cas_session) {
        AM_CA_StopDescrambling(play.cas_session);
        AM_CA_CloseSession(play.cas_session);
    }

    AmTsPlayer_stopAudioDecoding(play.player_session);
    AmTsPlayer_stopVideoDecoding(play.player_session);
    AmTsPlayer_release(play.player_session);

    memset(&play, 0, sizeof(CasTestSession));

    return 0;
}

static int start_recording(int dev_no, dvb_service_info_t *prog, char *tspath)
{
    DVR_WrapperRecordOpenParams_t rec_open_params;
    DVR_WrapperRecordStartParams_t rec_start_params;
    DVR_WrapperPidsInfo_t *pids_info;
    //char cmd[256];
    int error;

    AM_CA_ServiceInfo_t cas_para;
    CA_SERVICE_TYPE_t service_type = SERVICE_PVR_RECORDING;

    UNUSED(dev_no);
    DVR_WrapperRecord_t recorder_session;
    //sprintf(cmd, "echo ts%d > /sys/class/stb/demux%d_source", tssrc, DMX_DEV_DVR);
    //system(cmd);

    if (dev_no >= MAX_REC_NUM) {
      ERR("wrong device no %d\n", dev_no);
      return -1;
    }
    memset(&rec_open_params, 0, sizeof(DVR_WrapperRecordOpenParams_t));

    rec_open_params.dmx_dev_id = dev_no;
    rec_open_params.segment_size = 100 * 1024 * 1024;/*100MB*/
    rec_open_params.max_size = size;
    rec_open_params.max_time = duration;
    rec_open_params.event_fn = RecEventHandler;
    rec_open_params.event_userdata = "rec0";
    rec_open_params.flags = 0;
    if (is_timeshifting(mode))
        rec_open_params.flags |= DVR_RECORD_FLAG_ACCURATE;

    strncpy(rec_open_params.location, tspath, sizeof(rec_open_params.location));

    rec_open_params.is_timeshift = (is_timeshifting(mode)) ? DVR_TRUE : DVR_FALSE;

    if (prog->scrambled) {
        rec_open_params.crypto_data = &recorder[dev_no].cas_session;
        rec_open_params.crypto_fn = encrypt_callback;
    }

    error = dvr_wrapper_open_record(&recorder_session, &rec_open_params);
    if (error) {
      ERR( "recorder open fail = (0x%x)\n", error);
      return -1;
    }
    recorder[dev_no].dvr_session = (void *)recorder_session;

    INF( "Starting %s recording %p [%ld secs/%llu bytes] [%s.ts]\n",
       (is_timeshifting(mode))? "timeshift" : "normal",
       recorder_session,
       rec_open_params.max_time,
       rec_open_params.max_size,
       rec_open_params.location);

    memset(&rec_start_params, 0, sizeof(rec_start_params));

    if (prog->scrambled) {
        void *buf = NULL;
        uint32_t secmem_size = BLOCK_SIZE*20;
        SecMemHandle secmem_session;

        error = AM_CA_OpenSession(g_cas_handle, &recorder[dev_no].cas_session, service_type);
        if (error) {
            ERR("CAS open session failed. ret = %d\r\n", error);
            dvr_wrapper_close_record(recorder_session);
            return -1;
        }

	if (g_vm_config.run) {
		watermark_test_config(g_vm_config.on,
		g_vm_config.config,
		g_vm_config.strength);
	}

	if (g_oc_config.run) {
		output_control_test_config(g_oc_config.flag,
					   g_oc_config.analog,
					   g_oc_config.cgmsa,
					   g_oc_config.emicci);
	}

        secmem_session = AM_CA_CreateSecmem(
			recorder[dev_no].cas_session,
			SERVICE_PVR_RECORDING,
			&buf,
			&secmem_size);
        if (!secmem_session) {
            ERR("create dvr recording secmem failed\n");
            dvr_wrapper_close_record(recorder_session);
            return -1;
        }
        recorder[dev_no].secmem_session = secmem_session;

        INF("set dvr recording secmem addr:%#x size:%#x\n", (uint32_t)buf, secmem_size);
        error = dvr_wrapper_set_record_secure_buffer(recorder_session, buf, secmem_size);
        if (error) {
            dvr_wrapper_close_record(recorder_session);
            AM_CA_DestroySecmem(recorder[dev_no].cas_session, secmem_session);
            recorder[dev_no].secmem_session = (SecMemHandle)NULL;
            return -1;
        }

        error = AM_CA_SetEmmPid(g_cas_handle, DMX_DEV_NO, prog->i_ca_pid);
        if (error) {
            ERR("CAS set emm PID failed. ret = %d\r\n", error);
            return -1;
        }

        memset(&cas_para, 0x0, sizeof(AM_CA_ServiceInfo_t));
        cas_para.dmx_dev = dev_no;

        cas_para.service_id = prog->i_program_num;
        cas_para.service_type = SERVICE_PVR_RECORDING;
        cas_para.ecm_pid = prog->i_ecm_pid[0];
        cas_para.stream_pids[0] = prog->i_video_pid;
        cas_para.stream_pids[1] = prog->i_audio_pid;
        cas_para.stream_num = 2;
	if (prog->private_data[0]) {
	    memcpy(cas_para.ca_private_data, prog->private_data, prog->private_data[0]);
	}
	cas_para.ca_private_data_len = prog->private_data[0];

	if (prog->service_type == IPTV_TYPE) {
	    cas_para.service_mode = SERVICE_IPTV;
	    INF("IPTV service mode:%d\n", cas_para.service_mode);
	} else {
	    cas_para.service_mode = SERVICE_DVB;
	    INF("DVB service mode:%d\n", cas_para.service_mode);
	}
        error = AM_CA_DVRStart(recorder[dev_no].cas_session, &cas_para);
        if (error) {
            ERR("CAS start DVR failed. ret = %d\r\n", error);
	    AM_CA_DestroySecmem(recorder[dev_no].cas_session, recorder[dev_no].secmem_session);
	    recorder[dev_no].secmem_session = (SecMemHandle)NULL;
	    AM_CA_CloseSession(recorder[dev_no].cas_session);
	    recorder[dev_no].cas_session = 0;
	    dvr_wrapper_close_record(recorder_session);
            return -1;
        }
    }

    pids_info = &rec_start_params.pids_info;
    pids_info->nb_pids = 2;
    pids_info->pids[0].pid = prog->i_video_pid;
    pids_info->pids[1].pid = prog->i_audio_pid;
    pids_info->pids[0].type = DVR_STREAM_TYPE_VIDEO << 24 | prog->i_vformat;
    pids_info->pids[1].type = DVR_STREAM_TYPE_AUDIO << 24 | prog->i_aformat;
    error = dvr_wrapper_start_record(recorder_session, &rec_start_params);
    if (error)
    {
      ERR( "recorder start fail = (0x%x)\n", error);
      dvr_wrapper_close_record(recorder_session);
      AM_CA_DestroySecmem(recorder[dev_no].cas_session, recorder[dev_no].secmem_session);
      recorder[dev_no].secmem_session = (SecMemHandle)NULL;
      AM_CA_CloseSession(recorder[dev_no].cas_session);
      recorder[dev_no].cas_session = 0;
      return -1;
    }

    return 0;
}

static int show_cardno(void)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_GETSCNO);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
    cJSON_Delete(input);

    input = cJSON_Parse(out_json);
    item = cJSON_GetObjectItemCaseSensitive(input, ITEM_CARDNO);
    if (!cJSON_IsString(item) || item->valuestring[0] == '\0') {
	    cJSON_Delete(input);
	    INF("Get card no failed\n");
	    return -1;
    }

    INF("cardno:%s\n", item->valuestring);
    cJSON_Delete(input);

    return 0;
}

static int check_pin(char *pin, uint8_t pinIndex, uint8_t reason)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_CHECK_PIN);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateString(pin);
    cJSON_AddItemToObject(input, ITEM_PIN, item);
    item = cJSON_CreateNumber(pinIndex);
    cJSON_AddItemToObject(input, ITEM_PIN_INDEX, item);
    item = cJSON_CreateNumber(reason);
    cJSON_AddItemToObject(input, ITEM_REASON, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (play.cas_session) {
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
	INF("out_json:\n%s\n", out_json);
    }

    return 0;
}

static int dvr_test_config(uint8_t algo)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_SET_ALGO);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(algo);
    cJSON_AddItemToObject(input, ITEM_ALGO, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    AM_CA_Ioctl(recorder[0].cas_session, in_json, out_json, MAX_JSON_LEN);
    INF("out_json:\n%s\n", out_json);

    return 0;
}

static int watermark_test_config(
	uint8_t on,
	uint8_t config,
	uint8_t strength)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_WATERMARK);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(on);
    cJSON_AddItemToObject(input, ITEM_ON, item);
    item = cJSON_CreateNumber(config);
    cJSON_AddItemToObject(input, ITEM_CONFIG, item);
    item = cJSON_CreateNumber(strength);
    cJSON_AddItemToObject(input, ITEM_STRENGTH, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (has_live(mode) && play.cas_session) {
	INF("has live\n");
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
    }
    if (recorder[0].cas_session) {
	INF("has recording\n");
	AM_CA_Ioctl(recorder[0].cas_session, in_json, out_json, MAX_JSON_LEN);
    }
    INF("out_json:\n%s\n", out_json);

    return 0;
}

static int output_control_test_config(
	uint32_t flag,
	uint8_t analog,
	uint8_t cgmsa,
	uint8_t emicci)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_OUTPUT_CONTROL);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(flag);
    cJSON_AddItemToObject(input, ITEM_FLAG, item);
    item = cJSON_CreateNumber(analog);
    cJSON_AddItemToObject(input, ITEM_ANALOG, item);
    item = cJSON_CreateNumber(cgmsa);
    cJSON_AddItemToObject(input, ITEM_CGMSA, item);
    item = cJSON_CreateNumber(emicci);
    cJSON_AddItemToObject(input, ITEM_EMICCI, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (has_live(mode) && play.cas_session) {
	INF("has live\n");
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
    }
    if (recorder[0].cas_session) {
	INF("has recording\n");
	AM_CA_Ioctl(recorder[0].cas_session, in_json, out_json, MAX_JSON_LEN);
    }
    INF("out_json:\n%s\n", out_json);

    return 0;
}

static int svp_test_config(size_t addr)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_SVP);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(addr);
    cJSON_AddItemToObject(input, ITEM_ADDR, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (has_live(mode)) {
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
	INF("out_json:\n%s\n", out_json);
    }

    return 0;
}

static int antirollback_test_config(uint8_t flag)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_ARB);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(flag);
    cJSON_AddItemToObject(input, ITEM_FLAG, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (has_live(mode)) {
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
	INF("out_json:\n%s\n", out_json);
    }

    return 0;
}

static int ta2ta_test_config(
	uint32_t clientid,
	const char *data,
	uint32_t len)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_TA2TA);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(clientid);
    cJSON_AddItemToObject(input, ITEM_CLIENTID, item);
    item = cJSON_CreateString(data);
    cJSON_AddItemToObject(input, ITEM_DATA, item);
    item = cJSON_CreateNumber(len);
    cJSON_AddItemToObject(input, ITEM_LEN, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (has_live(mode)) {
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
	INF("out_json:\n%s\n", out_json);
    }

    return 0;
}

static int hdcp_test_config(uint8_t svc_idx)
{
    cJSON *input = NULL;
    cJSON *item = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    item = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, item);
    item = cJSON_CreateString(ITEM_HDCP);
    cJSON_AddItemToObject(input, ITEM_CMD, item);
    item = cJSON_CreateNumber(svc_idx);
    cJSON_AddItemToObject(input, ITEM_SERVICE_INDEX, item);

    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF("in_json:\n%s\n", in_json);
    if (play.cas_session) {
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
    }
    INF("out_json:\n%s\n", out_json);

    return 0;
}
static int stop_recording(int dev_no)
{
    int ret;
    CasSession cas_session = recorder[dev_no].cas_session;

    if (dev_no >= MAX_REC_NUM) {
      ERR("wrong device no %d\n", dev_no);
      return -1;
    }

    ret = dvr_wrapper_stop_record((DVR_WrapperRecord_t *)recorder[dev_no].dvr_session);
    ret |= dvr_wrapper_close_record((DVR_WrapperRecord_t *)recorder[dev_no].dvr_session);
    if (ret) {
        ERR("stop/close record failed:%d\n", ret);
        return -1;
    }
    if (cas_session) {
        AM_CA_DVRStop(cas_session);
        ret = AM_CA_DestroySecmem(cas_session, recorder[dev_no].secmem_session);
        if (ret) {
            ERR("destroy secmem failed:%d", ret);
            return -1;
        }
        AM_CA_CloseSession(cas_session);
    }

    memset(&recorder[dev_no], 0, sizeof(CasTestSession));

    return 0;
}

static int get_dvr_info(char *location, int *apid, int *afmt, int *vpid, int *vfmt)
{
    uint32_t segment_nb;
    uint64_t *p_segment_ids;
    DVR_RecordSegmentInfo_t seg_info;
    int error;
    int aid = 0x1fff, vid = 0x1fff;
    int aft = 0, vft = 0;

    error = dvr_segment_get_list(location, &segment_nb, &p_segment_ids);
    if (!error && segment_nb) {
        error = dvr_segment_get_info(location, p_segment_ids[0], &seg_info);
        free(p_segment_ids);
    }
    if (!error) {
        int i;
        for (i = 0; i < seg_info.nb_pids; i++) {
            switch (DVR_STREAM_TYPE_TO_TYPE(seg_info.pids[i].type))
            {
            case DVR_STREAM_TYPE_VIDEO:
                vid = seg_info.pids[i].pid;
                vft = DVR_STREAM_TYPE_TO_FMT(seg_info.pids[i].type);
                INF("type(0x%x)[video] pid(0x%x) fmt(%d)\n",
                    DVR_STREAM_TYPE_TO_TYPE(seg_info.pids[i].type),
                    seg_info.pids[i].pid,
                    DVR_STREAM_TYPE_TO_FMT(seg_info.pids[i].type)
                    );
            break;
            case DVR_STREAM_TYPE_AUDIO:
                aid = seg_info.pids[i].pid;
                aft = DVR_STREAM_TYPE_TO_FMT(seg_info.pids[i].type);
                INF("type(0x%x)[audio] pid(0x%x) fmt(%d)\n",
                    DVR_STREAM_TYPE_TO_TYPE(seg_info.pids[i].type),
                    seg_info.pids[i].pid,
                    DVR_STREAM_TYPE_TO_FMT(seg_info.pids[i].type)
                    );
            break;
            default:
                INF("type(0x%x) pid(0x%x) fmt(%d)\n",
                    DVR_STREAM_TYPE_TO_TYPE(seg_info.pids[i].type),
                    seg_info.pids[i].pid,
                    DVR_STREAM_TYPE_TO_FMT(seg_info.pids[i].type)
                    );
            break;
            }
        }
    }

    if (apid)
        *apid = aid;
    if (afmt)
        *afmt = aft;
    if (vpid)
        *vpid = vid;
    if (vfmt)
        *vfmt = vft;

    return 0;
}

static int start_playback(void *params, int scrambled, int pause)
{
    DVR_WrapperPlayback_t player;
    DVR_PlaybackPids_t play_pids;
    DVR_WrapperPlaybackOpenParams_t play_params;
    am_tsplayer_handle tsplayer_handle;
    int vpid = 1024, apid = 1025, vfmt = 0, afmt = 0;
    int error;

    void *sec_buf;
    uint32_t sec_buf_size = INJECT_LENGTH + 4*1024;
    CA_SERVICE_TYPE_t service_type = SERVICE_PVR_PLAY;

    memset(&play_params, 0, sizeof(play_params));
    memset(&play_pids, 0, sizeof(play_pids));

    play_pids.video.type = DVR_STREAM_TYPE_VIDEO;
    play_pids.audio.type = DVR_STREAM_TYPE_AUDIO;

    if (is_timeshifting(mode)) {
        dvb_service_info_t *prog = (dvb_service_info_t *)params;
        strncpy(play_params.location, pfilename, sizeof(play_params.location));
        play_params.is_timeshift = DVR_TRUE;
        play_params.dmx_dev_id = DMX_DEV_NO_2ND;

        vpid = prog->i_video_pid;
        vfmt = prog->i_vformat;
        apid = prog->i_audio_pid;
        afmt = prog->i_aformat;
    } else {
        strncpy(play_params.location, params, sizeof(play_params.location));
        play_params.is_timeshift = DVR_FALSE;
        play_params.dmx_dev_id = DMX_DEV_NO;
        get_dvr_info(params, &apid, &afmt, &vpid, &vfmt);

    }
    INF("vpid:%#x vfmt:%d apid:%#x afmt:%d\n", vpid, vfmt, apid, afmt);

    if (scrambled) {
	error = AM_CA_OpenSession(
		g_cas_handle,
		&play.cas_session,
		service_type);
	INF("%s open cas session:%#x, start cas\n",
		__func__, play.cas_session);

	AM_CA_RegisterEventCallback(play.cas_session, cas_event_cb);

        play.secmem_session = AM_CA_CreateSecmem(
				play.cas_session,
				SERVICE_PVR_PLAY,
				&sec_buf,
				&sec_buf_size);
        if (!play.secmem_session) {
	    ERR("cas playback failed. secmem_session:%#x\n", play.secmem_session);
        }
    }

    switch (vfmt) {
        case AV_VIDEO_CODEC_MPEG1:
            vfmt = DVR_VIDEO_FORMAT_MPEG1;
            break;
        case AV_VIDEO_CODEC_MPEG2:
            vfmt = DVR_VIDEO_FORMAT_MPEG2;
            break;
        case AV_VIDEO_CODEC_H264:
            vfmt = DVR_VIDEO_FORMAT_H264;
            break;
        default:
            break;
    };

    switch (afmt) {
            case AV_AUDIO_CODEC_MP3:
                afmt = DVR_AUDIO_FORMAT_MPEG;
                break;
            case AV_AUDIO_CODEC_AAC:
                afmt = DVR_AUDIO_FORMAT_AAC;
                break;
            default:
                break;
    };
    play_pids.video.pid = vpid;
    play_pids.video.format = vfmt;
    play_pids.audio.pid = apid;
    play_pids.audio.format = afmt;

    play_params.event_fn = PlayEventHandler;
    play_params.event_userdata = "play0";

     /*open TsPlayer*/
    {
       uint32_t versionM, versionL;
       am_tsplayer_init_params init_param =
       {
          .source = TS_MEMORY,
          .dmx_dev_id = DMX_DEV_NO,
          .event_mask = 0,
               /*AM_TSPLAYER_EVENT_TYPE_PTS_MASK
             | AM_TSPLAYER_EVENT_TYPE_DTV_SUBTITLE_MASK
             | AM_TSPLAYER_EVENT_TYPE_USERDATA_AFD_MASK
             | AM_TSPLAYER_EVENT_TYPE_VIDEO_CHANGED_MASK
             | AM_TSPLAYER_EVENT_TYPE_AUDIO_CHANGED_MASK
             | AM_TSPLAYER_EVENT_TYPE_DATA_LOSS_MASK
             | AM_TSPLAYER_EVENT_TYPE_DATA_RESUME_MASK
             | AM_TSPLAYER_EVENT_TYPE_SCRAMBLING_MASK
             | AM_TSPLAYER_EVENT_TYPE_FIRST_FRAME_MASK,*/
       };
       if (is_timeshifting(mode)) {
           init_param.dmx_dev_id = DMX_DEV_NO_2ND;
       }
       if (scrambled) {
           init_param.drmmode = TS_INPUT_BUFFER_TYPE_SECURE;
       }
       am_tsplayer_result result =
          AmTsPlayer_create(init_param, &tsplayer_handle);
       INF( "open TsPlayer %s, result(%d)\n", (result)? "FAIL" : "OK", result);

       result = AmTsPlayer_getVersion(&versionM, &versionL);
       INF( "TsPlayer verison(%d.%d) %s, result(%d)\n",
          versionM, versionL,
          (result)? "FAIL" : "OK",
          result);

       result = AmTsPlayer_registerCb(tsplayer_handle,
          tsplayer_callback,
          "tsp0");

       result = AmTsPlayer_setWorkMode(tsplayer_handle, TS_PLAYER_MODE_NORMAL);
       INF( " TsPlayer set Workmode NORMAL %s, result(%d)\n", (result)? "FAIL" : "OK", result);
       //result = AmTsPlayer_setSyncMode(tsplayer_handle, TS_SYNC_NOSYNC );
       //PLAY_DBG(" TsPlayer set Syncmode FREERUN %s, result(%d)", (result)? "FAIL" : "OK", result);
       result = AmTsPlayer_setSyncMode(tsplayer_handle, TS_SYNC_VMASTER );
       INF( " TsPlayer set Syncmode PCRMASTER %s, result(%d)\n", (result)? "FAIL" : "OK", result);
       play_params.playback_handle = (Playback_DeviceHandle_t)tsplayer_handle;
       play.player_session = tsplayer_handle;
    }

    play.replayed = 0;
    if (scrambled) {
        play_params.crypto_fn = decrypt_callback;
        play_params.crypto_data = NULL;
    }
    play_params.block_size = BLOCK_SIZE;
    error = dvr_wrapper_open_playback(&player, &play_params);
    if (!error)
    {
       //DVR_PlaybackFlag_t play_flag = (is_timeshifting(mode))? DVR_PLAYBACK_STARTED_PAUSEDLIVE : 0;
       DVR_PlaybackFlag_t play_flag = (pause)? DVR_PLAYBACK_STARTED_PAUSEDLIVE : 0;
       play.dvr_session = (void *)player;

       if (scrambled) {
           INF("cas playback set secure buffer:%p, secure buffer size:%#x\n",
                        sec_buf, sec_buf_size);
           dvr_wrapper_set_playback_secure_buffer(player, sec_buf, sec_buf_size);
       }
       INF( "Starting playback\n");

       error = dvr_wrapper_start_playback(player, play_flag, &play_pids);
       if (error)
       {
          ERR( "Start play failed, error %d\n", error);
       }
     }

    return 0;
}

static int pause_playback(void)
{
    int error;

    if (play.dvr_session) {
	error = dvr_wrapper_pause_playback(play.dvr_session);
    }

    INF("pause = (%d)\n", error);
    return error;
}

static int resume_playback(void)
{
    int error;

    if (play.dvr_session) {
	error = dvr_wrapper_resume_playback(play.dvr_session);
    }

    INF("resume = (%d)\n", error);
    return error;
}

static int stop_playback(void)
{
    dvr_wrapper_stop_playback((DVR_WrapperPlayback_t *)play.dvr_session);
    if (play.cas_session) {
        AM_CA_DestroySecmem(play.cas_session, play.secmem_session);
        AM_CA_CloseSession(play.cas_session);
    }
    AmTsPlayer_stopAudioDecoding(play.player_session);
    AmTsPlayer_stopVideoDecoding(play.player_session);
    AmTsPlayer_release(play.player_session);

    return 0;
}

static void usage(int argc, char *argv[])
{
    UNUSED(argc);

    INF("Usage: live      : %s live <fend_dev_no> <input_dev_no> <prog_idx> <freqM> <isIPTV>\n", argv[0]);
    INF("Usage: local	  : %s local <tsfile> <prog_idx>\n", argv[0]);
    INF("Usage: playback  : %s dvrplay <tsfile> <scramble_flag>\n", argv[0]);
}

static int cas_test_term(void)
{
    if (has_live(mode)) {
        stop_liveplay();
    }

    if (has_live_local(mode)) {
	gInjectRunning = 0;
	pthread_join(gInjectThread, NULL);
        stop_liveplay();
    }

    if (has_recording(mode)) {
	int i;
	for (i = 0; i < MAX_REC_NUM; i++) {
	    if (rec_status & (1 << i)) {
		stop_recording(i);
	    }
	}
    }

    if (is_ext_playback(mode)) {
	ext_dvr_playback_stop();
    } else if (has_playback(mode)) {
        stop_playback();
    }

    return 0;
}

static void handle_signal(int signal)
{
    UNUSED(signal);
    cas_test_term();
    exit(0);
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
    char cmd[256];
    char tspath[256] = {0};
    int dvr_dev_no = 0;
    int fend_dev_no = 0;
    int input_dev_no = 0;
    int prog_idx = 0;
    int scrambled = 1;
    int freqM = 394;
    int isIPTV = 0;
    dvb_service_info_t *prog = NULL;

    char *secdvr = getenv("SECDVR");
    int secure_dvr = 0;

    if (secdvr) {
	secure_dvr = atoi(secdvr);
	if (secure_dvr) {
	    INF("enable secure dvr for FTA stream\n");
	}
    }

    if (argc < 3) {
        usage(argc, argv);
        exit(0);
    }

    init_signal_handler();

    memset(&play, 0, sizeof(CasTestSession));
    memset(recorder, 0, sizeof(CasTestSession)*MAX_REC_NUM);

    if (strcmp(argv[1], "live") == 0) {
        mode = LIVE;
        sscanf(argv[2], "%d", &fend_dev_no);
	if (argc > 3) {
	    sscanf(argv[3], "%d", &input_dev_no);
	}
        if (argc > 4) {
            sscanf(argv[4], "%d", &prog_idx);
        }
	if (argc > 5) {
	    sscanf(argv[5], "%d", &freqM);
	}
	if (argc > 6) {
	    sscanf(argv[6], "%d", &isIPTV);
	}
    } else if (strcmp(argv[1], "local") == 0) {
        mode = LIVE_LOCAL;
        strcpy(&tspath[0], argv[2]);
        sscanf(argv[3], "%d", &prog_idx);
    } else if (strcmp(argv[1], "dvrrecord") == 0) {
        strcpy(&tspath[0], argv[2]);
        mode = RECORDING;
    } else if (strcmp(argv[1], "dvrplay") == 0) {
	int ret;
	struct stat buf;

        strcpy(&tspath[0], argv[2]);
        if (argc > 3) {
            sscanf(argv[3], "%d", &scrambled);
        }
	ret = stat(tspath, &buf);
	if (ret == -1 && errno == ENOENT) {
		//aml dvr file path
		mode = PLAYBACK;
	} else {
		//external dvr file path
		mode = EXT_PLAYBACK;
	}
    } else {
        usage(argc, argv);
        exit(0);
    }

    INF("@@@in cas_hal_test mode = %d\n", mode);

    ret = dvb_init();
    if (!ret) {
	while (1) {
	    if (!show_cardno()) {
	        break;
	    }
	    sleep(1);
	};
    }

    if (is_live(mode) || is_live_local(mode)) {
	if (is_live(mode)) {
	    DVB_DemuxSource_t dmx_src;

            fend_lock(fend_dev_no, freqM);
	    dmx_src = DVB_DEMUX_SOURCE_TS0 + input_dev_no;
	    if (dmx_src > DVB_DEMUX_SOURCE_DMA7) {
		dmx_src = DVB_DEMUX_SOURCE_TS1;
	    }
	    dvb_set_demux_source(DMX_DEV_NO, dmx_src);
	} else {
	    dvb_service_info_t prog;

	    dvb_set_demux_source(DMX_DEV_NO, DVB_DEMUX_SOURCE_DMA0);
	    memset(&prog, 0, sizeof(prog));
#if 0
	    prog.i_video_pid = 0x22;
	    prog.i_vformat = 2;
	    prog.i_audio_pid = 0x21;
	    prog.i_aformat = 2;
#else
	    prog.i_video_pid = 0x1fff;
	    prog.i_audio_pid = 0x1fff;
#endif
	    init_tsplayer_inject(&prog);
	    gInjectRunning = 1;
	    pthread_create(&gInjectThread, NULL, inject_thread, &tspath[0]);
	}

        INF("%d programs scanned\r\n", aml_scan());

	if (is_live_local(mode)) {
	    gInjectRunning = 0;
	    pthread_join(gInjectThread, NULL);
	    stop_liveplay();
	}

	gInjectRunning = 0;
        prog = aml_get_program(prog_idx);
        INF("try to play program:%d handle:%x\r\n", prog_idx, (uint32_t)prog);
        if (prog && is_live(mode)) {
	    if (isIPTV) {
	        prog->service_type = IPTV_TYPE;
	    } else {
	        prog->service_type = DVB_TYPE;
	    }

	    if (secure_dvr) {
		prog->scrambled = 1;
	    }

	    start_descrambling(prog);
            start_liveplay(prog);
        } else if (prog && is_live_local(mode)) {
	    init_tsplayer_inject(prog);
	    start_descrambling(prog);
	    gInjectRunning = 1;
	    pthread_create(&gInjectThread, NULL, inject_thread, &tspath[0]);
	}
#if 0 //for test pattern
	else {
    	    dvb_service_info_t prog;

	    prog.i_audio_pid = 0x1fff;
	    prog.i_video_pid = 0x80;
	    prog.i_vformat = 2;
            start_liveplay(&prog);
	    start_descrambling(&prog);
            INF("invalid prog_idx:%x \r\n", prog_idx);
        }
#endif
    } else if (is_playback(mode)) {
        INF("try to play file:%s scrambled:%d pause:0\r\n",
            tspath, scrambled);

	dvb_set_demux_source(DMX_DEV_NO, DVB_DEMUX_SOURCE_DMA0);

        start_playback(tspath, scrambled, 0);
    } else if (is_ext_playback(mode)) {
        INF("try to play file:%s\r\n", tspath);
	dvb_set_demux_source(DMX_DEV_NO, DVB_DEMUX_SOURCE_DMA0);
        ext_dvr_playback(tspath, g_cas_handle);
    }

    sprintf(cmd, "echo 1 > /sys/class/graphics/fb0/osd_display_debug");
    system(cmd);
    sprintf(cmd, "echo 1 > /sys/class/graphics/fb0/blank");
    system(cmd);
    sprintf(cmd, "echo 0 2 > /sys/class/video/path_select");
    system(cmd);
    sprintf(cmd, "echo 1 > /sys/class/video/video_global_output");
    system(cmd);
    sprintf(cmd, "echo 0 > /sys/class/video/disable_video");
    system(cmd);

    while ( running ) {
        char buf[256];
        memset( buf, 0 , 256 );

        INF( "********************\n" );
        INF( "* commands:\n" );
        INF( "* dvrrecord <dvr_dev_no> <prog_idx> <tspath> <algono> <isIPTV>\n" );
        INF( "* dvrstop <dvr_dev_no>\n" );
	INF( "* oc <value> [<AnalogProtection> <Cgmsa> <Emicci>]\n");
	INF( "* pin <pin> <pinIdx> <reason>\n");
	INF( "* wm <on> <config> <strength>\n");
	INF( "* hdcp\n");
	INF( "* ta2ta <client id> <ascii input data>\n");
	INF( "* arb <0>/<1>\n");
        INF( "* quit\n" );
        INF( "********************\n" );

        if (fgets(buf, 256, stdin)) {
            if (!strncmp(buf, "quit", 4)) {
                running = 0;
            } else if (!strncmp(buf, "stop", 4)) {
		stop_liveplay();
            } else if (!strncmp(buf, "zap", 3)) {
		int prog_idx;

		ret = sscanf(buf, "zap %d", &prog_idx);
		if (ret >= 1) {
		    if (has_live(mode)) {
		        prog = aml_get_program(prog_idx);
		        if (prog) {
			    stop_liveplay();
		            start_descrambling(prog);
			    start_liveplay(prog);
		        }
		    }
		}

	    } else if (!strncmp(buf, "dvrrecord", 9)) {
                int prog_idx;
		uint8_t algo;
		DVB_DemuxSource_t dmx_src;

		isIPTV = 0;
                ret = sscanf(buf, "dvrrecord %d %d %255s %hhu %d", &dvr_dev_no,
			     &prog_idx, &tspath[0], &algo, &isIPTV);
		if (ret >= 4) {
			dvr_test_config(algo);
		}
                if (ret >= 3) {
#if 0
                    if (mode & RECORDING) {
                        ERR("DVR already start, please stop dvr first\r\n");
                        continue;
                    }
                    if (dvr_dev_no != 0) {
                        ERR("Now, must use DVR device0\r\n");
                        continue;
                    }
#endif
                    prog = aml_get_program(prog_idx);
                    INF("try to record program:%d handle:%x\r\n", prog_idx, (uint32_t)prog);
                    if (prog) {
			if (isIPTV) {
			    prog->service_type = IPTV_TYPE;
			} else {
			    prog->service_type = DVB_TYPE;
			}

			if (secure_dvr) {
				prog->scrambled = 1;
			}

			dmx_src = DVB_DEMUX_SOURCE_TS0 + input_dev_no;
			if (dmx_src > DVB_DEMUX_SOURCE_DMA7) {
				dmx_src = DVB_DEMUX_SOURCE_TS1;
			}
			dvb_set_demux_source(dvr_dev_no, dmx_src);

                        ret = start_recording(dvr_dev_no, prog, tspath);
                        if (!ret) {
                            mode |= RECORDING;
                            pfilename = tspath;
			    rec_status |= (1 << dvr_dev_no);
                            INF("recording%d started\n", dvr_dev_no);
                        } else {
                            ERR("start recording failed. ret:%d\r\n", ret);
                        }
                    } else {
                        ERR("invalid prog_idx:%x \r\n", prog_idx);
                    }
                }
	    } else if (!strncmp(buf, "dvrstop", 7)) {
                ret = sscanf(buf, "dvrstop %d", &dvr_dev_no);
                if (ret != 1)
                {
                    ERR("wrong input, cmd: dvrstop dvr_dev_no");
                    continue;
                }
                ret = stop_recording(dvr_dev_no);
                if (!ret) {
		    rec_status &= ~(1 << dvr_dev_no);
		    if (rec_status == 0) {
			mode &= ~RECORDING;
		    }
		    INF("recording%d stopped\n", dvr_dev_no);
                } else {
		    INF("recording%d stop failed:%d\n", dvr_dev_no, ret);
		}
            } else if (!strncmp(buf, "tsstart", 7)) {
                if (has_recording(mode)) {
                    ERR("DVR already start, please stop dvr first\n");
                    continue;
                }
                if (is_live(mode)) {
                    stop_liveplay();

                    mode = TIMESHIFTING;
                    strcpy(tspath, pfilename);
                    start_recording(DVR_DEV_NO, prog, tspath);

		    dvb_set_demux_source(DMX_DEV_NO_2ND, DVB_DEMUX_SOURCE_DMA1);
                    start_playback(prog, prog->scrambled, 0);

                } else {
                    ERR("Not in live only mode, cannot enter timeshift\n");
                    continue;
                }
            } else if (!strncmp(buf, "tsstop", 6)) {
                if (is_timeshifting(mode)) {
                    stop_playback();
                    stop_recording(DVR_DEV_NO);

                    mode = LIVE;
		    start_descrambling(prog);
                    start_liveplay(prog);
                } else {
                    ERR("Not in timeshifint mode\n");
                    continue;
                }
            } else if (!strncmp(buf, "pause", 5)) {
		if (is_timeshifting(mode)) {
		    pause_playback();
		}
	    } else if (!strncmp(buf, "resume", 6)) {
		if (is_timeshifting(mode)) {
		    resume_playback();
		}
	    } else if (!strncmp(buf, "cardno", 6)) {
		show_cardno();
	    } else if (!strncmp(buf, "wm", 2)) {
		uint8_t on = 0, config = 0, strength = 0;
		ret = sscanf(buf, "wm %hhu %hhu %hhu", &on, &config, &strength);
		if (ret >= 1) {
		    g_vm_config.run = 1;
		    g_vm_config.on = on;
		    g_vm_config.config = config;
		    g_vm_config.strength = strength;
		    watermark_test_config(on, config, strength);
		}
	    } else if (!strncmp(buf, "oc", 2)) {
		uint32_t flag = 0;
		uint8_t analog = 0, cgmsa = 0, emicci = 0;
		ret = sscanf(buf, "oc %u %hhu %hhu %hhu", &flag, &analog, &cgmsa, &emicci);
		if (ret >= 1) {
		    g_oc_config.run = 1;
		    g_oc_config.flag = flag;
		    g_oc_config.analog = analog;
		    g_oc_config.cgmsa = cgmsa;
		    g_oc_config.emicci = emicci;
		    output_control_test_config(flag, analog, cgmsa, emicci);
		}
	    } else if (!strncmp(buf, "pin", 3)) {
		uint8_t pinIndex, reason;
		char pin[64];

		ret = sscanf(buf, "pin %s %hhu %hhu", pin, &pinIndex, &reason);
		if (ret == 3) {
			check_pin(pin, pinIndex, reason);
		}
	    } else if (!strncmp(buf, "svp", 3)) {
		size_t addr;
		ret = sscanf(buf, "svp 0x%x", &addr);
		if (ret == 1) {
		    svp_test_config(addr);
		}
	    } else if (!strncmp(buf, "arb", 3)) {
		uint8_t flag;
		ret = sscanf(buf, "arb %hhu", &flag);
		if (ret == 1) {
		    antirollback_test_config(flag);
		}
	    } else if (!strncmp(buf, "ta2ta", 5)) {
		char *data = malloc(2048);
		uint32_t len = 0;
		uint32_t clientid;
		uint32_t i;

		if (buf[5] != '\0' && buf[6] != '\0' && buf[7] != '\0' && buf[8]!= '\0') {
		    sscanf(buf, "ta2ta %u", &clientid);
		    strncpy(data, buf + 8, 2048);
		    data[2047] = '\0';
		    len = strlen(data);
		    INF("sending len=%u data=", len);
		    for (i = 0; i < len &&  i < 256; i++) {
			INF("%02x ", data[i]);
		    }
		    INF("\n");
		    ta2ta_test_config(clientid, data, len);
		    INF("received data=");
		    for (i = 0; i < len &&  i < 256; i++) {
			INF("%02x ", data[i]);
		    }
		    INF("\n");
		}
		if (data)
		    free(data);
	    } else if (!strncmp(buf, "hdcp", 4)) {
		    uint8_t svc_idx = 0;
		    ret = sscanf(buf, "hdcp %hhu", &svc_idx);
		    hdcp_test_config(svc_idx);
	    }
        }
    };

    cas_test_term();
    exit(0);
}

