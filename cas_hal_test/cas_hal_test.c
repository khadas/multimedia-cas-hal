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
 *   cas_hal_test <fend_dev_no> <prog_index>
 * \endcode
 * For playback:
 * \code
 *   dvr_wrapper_test <tsfile> <paused>
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
#define DMX_DEV_NO_3RD (2)
#define AV_DEV_NO (0)
#define DSC_DEV_NO (0)
#define DVR_DEV_NO (0)

#define VMX_SYS_ID (0x1724)
#define VMX_CAS_STRING "Verimatrix"

#define DVR_BUFFER_SIZE (512*1024)
#define RECORD_BLOCK_SIZE (256*1024)//same to asyncfifo flush size, it's enc block size and dec block size//65424

#define DVR_STREAM_TYPE_TO_TYPE(_t) (((_t) >> 24) & 0xF)
#define DVR_STREAM_TYPE_TO_FMT(_t)  ((_t) & 0xFFFFFF)

#define has_live(_m_)        ((_m_) & LIVE)
#define has_playback(_m_)    ((_m_) & PLAYBACK)
#define has_recording(_m_)   ((_m_) & RECORDING)
#define is_live(_m_)         ((_m_) == LIVE)
#define is_playback(_m_)     ((_m_) == PLAYBACK)
#define is_timeshifting(_m_) ((_m_) == TIMESHIFTING)

typedef struct
{
    CasSession cas_session;
    SecMemHandle secmem_session;
    void *dvr_session; //'DVR_WrapperPlayback_t *' or 'DVR_WrapperRecord_t *'
    am_tsplayer_handle player_session;
} CasTestSession;

static int mode = 0;
static int duration=180000;
static int size=1024*1024*1024;
static char *pfilename = "/data/data/timeshifting.ts";

enum {
    LIVE        = 0x01,
    PLAYBACK    = 0x02,
    RECORDING   = 0x04,
    TIMESHIFTING = PLAYBACK | RECORDING | 0x10,
};

static CasHandle g_cas_handle = 0;
static CasTestSession play;
static CasTestSession recorder;

static int fend_lock(int dev_no)
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
    delivery.delivery.cable.frequency = 666000;
    delivery.delivery.cable.symbol_rate = 6875;
    delivery.delivery.cable.modulation = DMD_MOD_64QAM;
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

static int dvb_init(void)
{
    int ret;

    ret = AM_CA_Init(&g_cas_handle);
    INF("CAS init ret = %d\r\n", ret);

    return 0;
}

static AM_RESULT cas_event_cb(CasSession session, char *json)
{
    CA_DEBUG(0, "%s:\n%s", __func__, json);
    return 0;
}

static DVR_Result_t encrypt_callback(DVR_CryptoParams_t *params, void *userdata)
{
    int ret;
    UNUSED(userdata);

    AM_CA_CryptoPara_t *cryptoPara = (AM_CA_CryptoPara_t *)params;

    if (!recorder.cas_session) {
        ERR("%s invalid cas session\n", __func__);
        return -1;
    }

    ret = AM_CA_DVREncrypt(recorder.cas_session, cryptoPara);
    if (ret) {
        cryptoPara->buf_len = 0;
        cryptoPara->buf_out.size = 0;
        ERR("%s failed\n", __func__);
        return -1;
    }

    INF("%#x bytes encrypted\n", cryptoPara->buf_len);

    return 0;
}

static DVR_Result_t decrypt_callback(DVR_CryptoParams_t *params, void *userdata)
{
    int ret;
    UNUSED(userdata);

    AM_CA_CryptoPara_t *cryptoPara = (AM_CA_CryptoPara_t *)params;

    if (!play.cas_session) {
        ret = AM_CA_OpenSession(g_cas_handle, &play.cas_session);
        ret |= AM_CA_DVRReplay(play.cas_session, cryptoPara);
        INF("%s open cas session:%#x, start cas replay. ret:%d\n",
            __func__, play.cas_session, ret);
    }

    ret = AM_CA_DVRDecrypt(play.cas_session, cryptoPara);
    if (ret) {
        cryptoPara->buf_len = 0;
        cryptoPara->buf_out.size = 0;
        ERR("%s failed\n", __func__);
        return -1;
    }

    INF("%#x bytes decrypted\n", cryptoPara->buf_len);

    return 0;
}

static DVR_Result_t RecEventHandler(DVR_RecordEvent_t event, void *params, void *userdata)
{
   if (userdata != NULL)
   {
      DVR_WrapperRecordStatus_t *status = (DVR_WrapperRecordStatus_t *)params;

      switch (event)
      {
         case DVR_RECORD_EVENT_STATUS:
            INF("Record event %d\n", status->state);
            break;
         default:
            ERR("Unhandled recording event 0x%x from (%s)\n", event, (char *)userdata);
         break;
      }
   }
   return DVR_SUCCESS;
}

void video_callback(void *user_data, am_tsplayer_event *event)
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
           ERR("Unhandled event 0x%x from (%s)\n", event, (char *)userdata);
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

static int start_liveplay(dvb_service_info_t *prog)
{
    uint32_t num;
    am_tsplayer_result ret;
    am_tsplayer_video_params vparam;
    am_tsplayer_audio_params aparam;
    am_tsplayer_init_params param;
    am_tsplayer_avsync_mode avsyncmode = TS_SYNC_AMASTER;

    am_tsplayer_handle player_session;
    AM_CA_ServiceInfo_t cas_para;

    INF("vpid:%#x vfmt:%d apid:%#x afmt:%d ecmpid:%#x emmpid:%#x scramble:%d\r\n",
        prog->i_video_pid, prog->i_vformat,
        prog->i_audio_pid, prog->i_aformat,
        prog->i_ecm_pid[0], prog->i_ca_pid, prog->scrambled);

    memset(&param, 0 , sizeof(am_tsplayer_init_params));
    param.source = TS_DEMOD;
    param.dmx_dev_id = DMX_DEV_NO;
    if (prog->scrambled) {
        param.drmmode = TS_INPUT_BUFFER_TYPE_TVP;
    }

    if (param.drmmode != TS_INPUT_BUFFER_TYPE_NORMAL) {
        play.secmem_session = AM_CA_CreateSecmem(SERVICE_LIVE_PLAY, NULL, NULL);
        if (!play.secmem_session) {
            CA_DEBUG(0, "Create live secmem failed!!!!");
            return -1;
        }
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

    aparam.codectype = prog->i_aformat;
    aparam.pid = prog->i_audio_pid;
    AmTsPlayer_setAudioParams(player_session, &aparam);
    AmTsPlayer_startAudioDecoding(player_session);

    AmTsPlayer_showVideo(player_session);
    AmTsPlayer_setTrickMode(player_session, AV_VIDEO_TRICK_MODE_NONE);

    if (!prog->scrambled)
        return 0;

    ret = AM_CA_SetEmmPid(g_cas_handle, DMX_DEV_NO, prog->i_ca_pid);
    if (ret) {
        ERR("CAS set emm PID failed. ret = %d\r\n", ret);
        return -1;
    }

    ret = AM_CA_OpenSession(g_cas_handle, &play.cas_session);
    if (ret) {
        ERR("CAS open session failed. ret = %d\r\n", ret);
        return -1;
    }

    ret = AM_CA_RegisterEventCallback(play.cas_session, cas_event_cb);
    if (ret) {
        ERR("CAS RegisterEventCallback failed. ret = %d\r\n", ret);
        return -1;
    }

    memset(&cas_para, 0x0, sizeof(AM_CA_ServiceInfo_t));
    cas_para.service_id = prog->i_service_num;
    cas_para.service_type = SERVICE_LIVE_PLAY;
    cas_para.ecm_pid = prog->i_ecm_pid[0];
    cas_para.stream_pids[0] = prog->i_video_pid;
    cas_para.stream_pids[1] = prog->i_audio_pid;
    cas_para.stream_num = 2;
    cas_para.ca_private_data_len = 0;
    ret = AM_CA_StartDescrambling(play.cas_session, &cas_para);
    if (ret) {
        ERR("CAS start descrambling failed. ret = %d\r\n", ret);
        return -1;
    }

    INF("CAS started\r\n");

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

    UNUSED(dev_no);
    DVR_WrapperRecord_t recorder_session;
    //sprintf(cmd, "echo ts%d > /sys/class/stb/demux%d_source", tssrc, DMX_DEV_DVR);
    //system(cmd);

    memset(&rec_open_params, 0, sizeof(DVR_WrapperRecordOpenParams_t));

    rec_open_params.dmx_dev_id = DMX_DEV_NO;
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
        rec_open_params.crypto_data = prog;
        rec_open_params.crypto_fn = encrypt_callback;
    }

    error = dvr_wrapper_open_record(&recorder_session, &rec_open_params);
    if (error) {
      ERR( "recorder open fail = (0x%x)\n", error);
      return -1;
    }
    recorder.dvr_session = (void *)recorder_session;

    INF( "Starting %s recording %p [%ld secs/%llu bytes] [%s.ts]\n",
       (is_timeshifting(mode))? "timeshift" : "normal",
       recorder_session,
       rec_open_params.max_time,
       rec_open_params.max_size,
       rec_open_params.location);

    memset(&rec_start_params, 0, sizeof(rec_start_params));

    if (prog->scrambled) {
        void *buf = NULL;
        uint32_t secmem_size = 0;
        SecMemHandle secmem_session;

        secmem_session = AM_CA_CreateSecmem(SERVICE_PVR_RECORDING, &buf, &secmem_size);
        if (!secmem_session) {
            ERR("create dvr recording secmem failed\n");
            dvr_wrapper_close_record(recorder_session);
            return -1;
        }
        recorder.secmem_session = secmem_session;

        INF("set dvr recording secmem addr:%#x size:%#x\n", (uint32_t)buf, secmem_size);
        error = dvr_wrapper_set_record_secure_buffer(recorder_session, buf, secmem_size);
        if (error) {
            dvr_wrapper_close_record(recorder_session);
            AM_CA_DestroySecmem(secmem_session);
            recorder.secmem_session = (SecMemHandle)NULL;
            return -1;
        }

        error = AM_CA_SetEmmPid(g_cas_handle, DMX_DEV_NO, prog->i_ca_pid);
        if (error) {
            ERR("CAS set emm PID failed. ret = %d\r\n", error);
            return -1;
        }

        error = AM_CA_OpenSession(g_cas_handle, &recorder.cas_session);
        if (error) {
            ERR("CAS open session failed. ret = %d\r\n", error);
            return -1;
        }

        memset(&cas_para, 0x0, sizeof(AM_CA_ServiceInfo_t));
        if (is_timeshifting(mode)) {
            cas_para.dmx_dev = DMX_DEV_NO_3RD;
        } else {
            cas_para.dmx_dev = DMX_DEV_NO;
        }
        cas_para.service_id = prog->i_service_num;
        cas_para.service_type = SERVICE_PVR_RECORDING;
        cas_para.ecm_pid = prog->i_ecm_pid[0];
        cas_para.stream_pids[0] = prog->i_video_pid;
        cas_para.stream_pids[1] = prog->i_audio_pid;
        cas_para.stream_num = 2;
        cas_para.ca_private_data_len = 0;

        error = AM_CA_DVRStart(recorder.cas_session, &cas_para);
        if (error) {
            ERR("CAS start DVR failed. ret = %d\r\n", error);
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
      AM_CA_DestroySecmem(recorder.secmem_session);
      recorder.secmem_session = (SecMemHandle)NULL;
      return -1;
    }

    return 0;
}

static int show_cardno(void)
{
    const cJSON *input = NULL;
    const cJSON *output = NULL;
    const cJSON *cas = NULL;
    const cJSON *cmd = NULL;
    const cJSON *type = NULL;
    char in_json[MAX_JSON_LEN];
    char out_json[MAX_JSON_LEN];

    input = cJSON_CreateObject();
    cas = cJSON_CreateString(VMX_CAS_STRING);
    cJSON_AddItemToObject(input, ITEM_CAS, cas);
    cmd = cJSON_CreateString(ITEM_GETSCNO);
    cJSON_AddItemToObject(input, ITEM_CMD, cmd);
    cJSON_PrintPreallocated(input, in_json, MAX_JSON_LEN, 1);
    INF( "in_json:\n%s\n", in_json);
    if (play.cas_session) { 
	AM_CA_Ioctl(play.cas_session, in_json, out_json, MAX_JSON_LEN);
	INF( "out_json:\n%s\n", out_json);
    }

    return 0;
}

static int stop_recording(int dev_no)
{
    int ret;
    CasSession cas_session = recorder.cas_session;

    UNUSED(dev_no);

    ret = dvr_wrapper_stop_record((DVR_WrapperRecord_t *)recorder.dvr_session);
    ret |= dvr_wrapper_close_record((DVR_WrapperRecord_t *)recorder.dvr_session);
    if (ret) {
        ERR("stop/close record failed:%d\n", ret);
        return -1;
    }

    if (cas_session) {
        AM_CA_DVRStop(cas_session);
        AM_CA_CloseSession(cas_session);
        ret = AM_CA_DestroySecmem(recorder.secmem_session);
        if (ret) {
            ERR("destroy secmem failed:%d", ret);
            return -1;
        }
    }

    memset(&recorder, 0, sizeof(CasTestSession));

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
                vfmt = DVR_AUDIO_FORMAT_MPEG;
                break;
            case AV_AUDIO_CODEC_AAC:
                vfmt = DVR_AUDIO_FORMAT_AAC;
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
       result = AmTsPlayer_setSyncMode(tsplayer_handle, TS_SYNC_PCRMASTER );
       INF( " TsPlayer set Syncmode PCRMASTER %s, result(%d)\n", (result)? "FAIL" : "OK", result);
       play_params.playback_handle = (Playback_DeviceHandle_t)tsplayer_handle;
       play.player_session = tsplayer_handle;
    }

    if (scrambled) {
        play_params.crypto_fn = decrypt_callback;
        play_params.crypto_data = NULL;
    }
    play_params.block_size = RECORD_BLOCK_SIZE;
    error = dvr_wrapper_open_playback(&player, &play_params);
    if (!error)
    {
       //DVR_PlaybackFlag_t play_flag = (is_timeshifting(mode))? DVR_PLAYBACK_STARTED_PAUSEDLIVE : 0;
       DVR_PlaybackFlag_t play_flag = (pause)? DVR_PLAYBACK_STARTED_PAUSEDLIVE : 0;
       play.dvr_session = (void *)player;

       if (scrambled) {
           void *sec_buf;
           uint32_t sec_buf_size = 0;

           play.secmem_session = AM_CA_CreateSecmem(SERVICE_PVR_PLAY, &sec_buf, &sec_buf_size);
           if (!play.secmem_session) {
                ERR("cas playback failed. secmem_session:%#x\n", play.secmem_session);
           }
           INF("cas playback set secure buffer:%#x, secure buffer size:%#x\n",
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

static int stop_playback(void)
{
    dvr_wrapper_stop_playback((DVR_WrapperPlayback_t *)play.dvr_session);
    if (play.cas_session) {
        AM_CA_DestroySecmem(play.secmem_session);
        AM_CA_CloseSession(play.cas_session);
    }
    AmTsPlayer_release(play.player_session);

    return 0;
}

static void usage(int argc, char *argv[])
{
    UNUSED(argc);

    INF("Usage: live      : %s live <fend_dev_no> <prog_idx>>\n", argv[0]);
    INF("Usage: playback  : %s dvrplay <tsfile> <scramble_flag>\n", argv[0]);
}

static void handle_signal(int signal)
{
    UNUSED(signal);
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
    int running = 1;
    char cmd[256];
    char tspath[256] = {0};
    int dvr_dev_no = 0;
    int fend_dev_no = 0;
    int prog_idx = 0;
    int scrambled = 1;
    dvb_service_info_t *prog = NULL;

    if (argc < 3) {
        usage(argc, argv);
        exit(0);
    }

    init_signal_handler();

    memset(&play, 0, sizeof(CasTestSession));
    memset(&recorder, 0, sizeof(CasTestSession));

    if (strcmp(argv[1], "live") == 0) {
        mode = LIVE;
        sscanf(argv[2], "%d", &fend_dev_no);
        if (argc > 3) {
            sscanf(argv[3], "%d", &prog_idx);
        }
    } else if (strcmp(argv[1], "dvrrecord") == 0) {
        strcpy(&tspath[0], argv[2]);
        mode = RECORDING;
    } else if (strcmp(argv[1], "dvrplay") == 0) {
        strcpy(&tspath[0], argv[2]);
        if (argc > 3) {
            sscanf(argv[3], "%d", &scrambled);
        }
        mode = PLAYBACK;
    } else {
        usage(argc, argv);
        exit(0);
    }

    INF("@@@in cas_hal_test mode = %d\n", mode);

    dvb_init();

    if (is_live(mode)) {
        fend_lock(fend_dev_no);

	dvb_set_demux_source(DMX_DEV_NO, DVB_DEMUX_SOURCE_TS0);

        aml_set_ca_system_id(VMX_SYS_ID);
        INF("%d programs scanned\r\n", aml_scan());
        prog = aml_get_program(prog_idx);
        INF("try to play program:%d handle:%x\r\n", prog_idx, (uint32_t)prog);
        if (prog) {
            start_liveplay(prog);
        } else {
            INF("invalid prog_idx:%x \r\n", prog_idx);
        }
    } else if (is_playback(mode)) {
        INF("try to play file:%s scrambled:%d pause:0\r\n",
            tspath, scrambled);

	dvb_set_demux_source(DMX_DEV_NO, DVB_DEMUX_SOURCE_DMA0);

        start_playback(tspath, scrambled, 0);
    }

    sprintf(cmd, "echo 1 > /sys/class/graphics/fb0/osd_display_debug");
    system(cmd);

    sprintf(cmd, "echo 1 > /sys/class/graphics/fb0/blank");
    system(cmd);
    while ( running ) {
        char buf[256];
        memset( buf, 0 , 256 );

        INF( "********************\n" );
        INF( "* commands:\n" );
        INF( "* dvrrecord <dvr_dev_no> <prog_idx> <tspath>\n" );
        INF( "* dvrstop <dvr_dev_no>\n" );
        INF( "* quit\n" );
        INF( "********************\n" );

        if (fgets(buf, 256, stdin)) {
            if (!strncmp(buf, "quit", 4)) {
                running = 0;
            } else if (!strncmp(buf, "dvrrecord", 9)) {
                int prog_idx;

                ret = sscanf(buf, "dvrrecord %d %d %255s", &dvr_dev_no, &prog_idx, &tspath[0]);
                if (ret == 3) {
                    if (mode & RECORDING) {
                        ERR("DVR already start, please stop dvr first\r\n");
                        continue;
                    }
                    if (dvr_dev_no != 0) {
                        ERR("Now, must use DVR device0\r\n");
                        continue;
                    }
                    prog = aml_get_program(prog_idx);
                    INF("try to record program:%d handle:%x\r\n", prog_idx, (uint32_t)prog);
                    if (prog) {
                        ret = start_recording(dvr_dev_no, prog, tspath);
                        if (!ret) {
                            mode |= RECORDING;
                            pfilename = tspath;
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
                if (ret != 1 || dvr_dev_no != 0)
                {
                    ERR("wrong input, cmd: dvrstop dvr_dev_no");
                    continue;
                }
                if (mode & RECORDING) {
                    ret = stop_recording(dvr_dev_no);
                    if (!ret) {
                        mode &= ~RECORDING;
                        INF("recording%d stopped\n", dvr_dev_no);
                    } else {
                        INF("recording%d stop failed:%d\n", dvr_dev_no, ret);
                    }
                } else {
                    ERR("recording%d didn't start yet\n", dvr_dev_no);
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

		    dvb_set_demux_source(DMX_DEV_NO_2ND, DVB_DEMUX_SOURCE_DMA0);
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
                    start_liveplay(prog);
                } else {
                    ERR("Not in timeshifint mode\n");
                    continue;
                }
            } else if (!strncmp(buf, "cardno", 6)) {
		show_cardno();
	    }
        }
    };

    if (has_live(mode)) {
        stop_liveplay();
    }

    if (has_recording(mode)) {
        stop_recording(DVR_DEV_NO);
    }

    if (has_playback(mode)) {
        stop_playback();
    }

    exit(0);
}
