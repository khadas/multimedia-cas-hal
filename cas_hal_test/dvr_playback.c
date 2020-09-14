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

#ifdef UNUSED
#undef UNUSED
#endif

#include "am_cas.h"

#define INF(fmt, ...)       fprintf(stdout, fmt, ##__VA_ARGS__)

static pthread_t gInjectThread;
static am_tsplayer_handle tsplayer_handle;
static CasSession cas_session;
static SecMemHandle secmem_session;
static void *sec_buf;
static int gInjectRunning = 1;
static AM_CA_StoreRegion_t store_reg[16];

#define INJECT_LENGTH (188*1024)
static void *inject_thread(void *arg)
{
    int ret;
    int fd = -1;
    uint8_t *buf = NULL;
    uint32_t blksize = 0;
    char *tspath = (char *)arg;
    const int kRwTimeout = 30000;
    uint32_t sec_buf_size = 0;
    AM_CA_CryptoPara_t crypto_para;
    am_tsplayer_input_buffer ibuf = {TS_INPUT_BUFFER_TYPE_SECURE, NULL, 0};

    uint8_t i = 0;
    uint8_t reg_cnt = 0;
    uint8_t curr_reg_idx = 0;

    fd = open(tspath, O_RDONLY);
    INF("%s open %s, fd:%d\n", __func__, tspath, fd);
    if (fd == -1) {
	return NULL;
    }

    memset(&store_reg[0], 0, sizeof(store_reg));
    memset(&crypto_para, 0, sizeof(crypto_para));
    crypto_para.offset = 0;
    crypto_para.type = CRYPTO_TYPE_DECRYPT;
    memcpy(crypto_para.location, tspath, strlen(tspath));
    if (AM_CA_DVRReplay(cas_session, &crypto_para)) {
	    INF("replay failed\n");
	    close(fd);
	    return NULL;
    }

    ret = AM_CA_GetStoreRegion(cas_session, store_reg, &reg_cnt);
    if (ret) {
	    INF("error! must get store region first\n");
    }

    blksize = crypto_para.buf_in.size;
    INF("blksize:%#x\n", blksize);
    if (blksize == 0) {
	blksize = INJECT_LENGTH;
	sec_buf_size = INJECT_LENGTH;
    }
    secmem_session = AM_CA_CreateSecmem(
			cas_session,
			SERVICE_PVR_PLAY,
			&sec_buf,
			&sec_buf_size);
    if (!secmem_session) {
	INF("cas playback failed. secmem_session:%#x\n", secmem_session);
	close(fd);
	return NULL;
    }

    buf = malloc(blksize);
    crypto_para.buf_out.addr = (size_t)sec_buf;
    crypto_para.buf_out.size = sec_buf_size;
    crypto_para.buf_in.addr = (size_t)buf;
    ibuf.buf_data = sec_buf;
    for (i = 0; i < reg_cnt; i++) {
	INF("Region[%d] %lld ~ %lld\n",
	    i,
	    store_reg[i].start,
	    store_reg[i].end);
    }
    while (gInjectRunning) {
	int size;
        int retry = 100;
	int kRwSize = 0;
        am_tsplayer_result res;

	if (curr_reg_idx < reg_cnt - 1) {
		if (crypto_para.offset + blksize >= store_reg[curr_reg_idx +1].start) {
			blksize = store_reg[curr_reg_idx + 1].start - crypto_para.offset;
			curr_reg_idx ++;
		}
	}

	kRwSize = read(fd, buf, blksize);
	if (kRwSize <= 0) {
	    INF("%s read end of file\n", __func__);
	    while (gInjectRunning) {
		sleep(1);
	    }
	    break;
	}

	crypto_para.buf_in.size = kRwSize;
	ret = AM_CA_DVRDecrypt(cas_session, &crypto_para);
	if (ret) {
		INF("Decrypt failed:%d\n", ret);
		continue;
	}

	ibuf.buf_size = kRwSize;
	//INF("streampos: %lld, curr_reg_idx:%d\n", crypto_para.offset, curr_reg_idx);
        do {
            res = AmTsPlayer_writeData(tsplayer_handle, &ibuf, kRwTimeout);
            if (res == AM_TSPLAYER_ERROR_RETRY) {
                usleep(50000);
		INF("tsplayer write retry\n");
            } else {
		//INF("%#x Bytes injected\n", ibuf.buf_size);
                break;
	    }
        } while(res || retry-- > 0);

	crypto_para.offset += kRwSize;
    }

    free(buf);
    close(fd);
    INF("exit %s\n", __func__);
    return NULL;
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

#define VIDEO_PID 0x44
#define AUDIO_PID 0x45
int ext_dvr_playback(const char *path, CasHandle cas_handle)
{
	int vpid = VIDEO_PID, apid = AUDIO_PID;
	int vfmt = AV_VIDEO_CODEC_MPEG2, afmt = AV_AUDIO_CODEC_MP3;
	int error;

	am_tsplayer_video_params vparam;
	am_tsplayer_audio_params aparam;
	uint32_t versionM, versionL;
	am_tsplayer_init_params init_param =
	{
	  .source = TS_MEMORY,
	  .dmx_dev_id = 0,
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
	  .drmmode = TS_INPUT_BUFFER_TYPE_SECURE,
	};

    INF("external vpid:%#x vfmt:%d apid:%#x afmt:%d\n", vpid, vfmt, apid, afmt);

     /*open TsPlayer*/
    {
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

	vparam.codectype = vfmt;
	vparam.pid = vpid;
	result = AmTsPlayer_setVideoParams(tsplayer_handle, &vparam);
	INF( " TsPlayer set video params %s, result(%d)\n", (result)? "FAIL" : "OK", result);
	result = AmTsPlayer_startVideoDecoding(tsplayer_handle);
	INF( " TsPlayer start video decoding %s, result(%d)\n", (result)? "FAIL" : "OK", result);

	aparam.codectype = afmt;
	aparam.pid = apid;
	aparam.seclevel = 10;
	result = AmTsPlayer_setAudioParams(tsplayer_handle, &aparam);
	INF( " TsPlayer set audio params %s, result(%d)\n", (result)? "FAIL" : "OK", result);
	result = AmTsPlayer_startAudioDecoding(tsplayer_handle);
	INF( " TsPlayer start audio decoding %s, result(%d)\n", (result)? "FAIL" : "OK", result);

	result = AmTsPlayer_showVideo(tsplayer_handle);
	INF( " TsPlayer show video %s, result(%d)\n", (result)? "FAIL" : "OK", result);
	result = AmTsPlayer_setTrickMode(tsplayer_handle, AV_VIDEO_TRICK_MODE_NONE);
	INF( " TsPlayer show audio decoding %s, result(%d)\n", (result)? "FAIL" : "OK", result);
    }


	error = AM_CA_OpenSession(
		cas_handle,
		&cas_session,
		SERVICE_PVR_PLAY);
	INF("%s open cas session:%#x, start cas\n", __func__, cas_session);

	INF( "Starting playback\n");

	pthread_create(&gInjectThread, NULL, inject_thread, path);

    return 0;
}

int ext_dvr_playback_stop(void)
{
    gInjectRunning = 0;
    if (gInjectThread) {
	pthread_join(gInjectThread, NULL);
    }
    if (cas_session) {
        AM_CA_DestroySecmem(cas_session, secmem_session);
        AM_CA_CloseSession(cas_session);
    }
    AmTsPlayer_stopAudioDecoding(tsplayer_handle);
    AmTsPlayer_stopVideoDecoding(tsplayer_handle);
    AmTsPlayer_release(tsplayer_handle);

    return 0;
}
