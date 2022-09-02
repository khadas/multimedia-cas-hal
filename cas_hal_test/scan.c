#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <time.h>
#include <sys/time.h>
#include <linux/dvb/dmx.h>

#include "AmTsPlayer.h"
#include "am_dmx.h"
#include "am_cas.h"
#include "scan.h"

#define DMX_DEV_NO (0)

static int parse_pat_section( const uint8_t *data, int sec_len, void *user_data );
static int parse_pmt_section( const uint8_t *data, void *user_data );
static int parse_cat_section( const uint8_t *data, void *user_data );
static void section_callback( int dev_no, int fid, const uint8_t *data, int len, void *user_data );
static int parse_ca_descriptor( uint8_t *p, dvb_service_info_t **dvb_info, uint16_t len, int index, int type );

static dvb_service_info_t g_info[16];
int pat_done_flag = 0;
int pmt_done_flag = 0;
int cat_done_flag = 0;
int g_pmt_num = 0;
uint32_t g_start_time = 0;

int file_read(const char *name, char *buf, int len)
{
    FILE *fp;
    int ret;

    fp = fopen(name, "r");
    if(!fp)
    {
        CA_DEBUG(1, "cannot open file \"%s\"", name);
        return -1;
    }

    ret = fread(buf, 1, len, fp);
    if(!ret)
    {
        CA_DEBUG(1, "read the file:\"%s\" error:\"%s\" failed", name, strerror(errno));
    }

    fclose(fp);

    return ret ? 0 : -1;
}

static uint32_t time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int parse_pat_section( const uint8_t *data, int sec_len, void *user_data )
{
    dvb_service_info_t  *p_dvb_info = (dvb_service_info_t *)user_data;

    if (pat_done_flag) {
        CA_DEBUG( 1, "%s, pat receive is done ,return", __FUNCTION__ );
        return 0;
    }

    uint8_t pmt_num = 0, i = 0;
    uint16_t program_num = 0;
    uint8_t *p = NULL;
    p = ( uint8_t * )( data + 8 );
    pmt_num = ( sec_len - 12 ) / 4 + 1;
    CA_DEBUG( 2, "data 8 Byte:%#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x",
              data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7] );
    CA_DEBUG( 1, "%s, pmt_num:%d, sec_len:%d", __FUNCTION__, pmt_num, sec_len );
    if ( p_dvb_info == NULL ) {
        for ( i = 0; i < pmt_num; i++ ) {
            CA_DEBUG( 1, "@data: %#x, %#x, %#x, %#x ", p[0], p[1], p[2], p[3] );
            program_num = ( p[0] << 8 | p[1] );
            if ( program_num != 0 ) {
                g_pmt_num++;
                CA_DEBUG( 1, "%s, 111, get program:%d, g_pmt_num:%d", __FUNCTION__, program_num, g_pmt_num );
            }
            p += 4;
        }
        pat_done_flag = 1;
        return 0;
    }
    int j = 0;
    for ( i = 0; i < pmt_num; i++ ) {
        CA_DEBUG( 2, "data: %#x, %#x, %#x, %#x ", p[0], p[1], p[2], p[3] );
        program_num = ( p[0] << 8 | p[1] );
        if ( program_num != 0 ) {
            p_dvb_info[j].i_program_num = program_num;
            p_dvb_info[j].i_pmt_pid = ( ( p[2] << 8 | p[3] ) & 0x1FFF );
            CA_DEBUG( 1, "%s, 222, get program:%d, pmt_pid:%#x", __FUNCTION__, p_dvb_info[j].i_program_num, p_dvb_info[j].i_pmt_pid );
            g_pmt_num++;
            j++;
        }
        p += 4;
    }
    pat_done_flag = 1;
    return 0;
}

static int parse_pmt_section( const uint8_t *data, void *user_data )
{
    dvb_service_info_t  *p_dvb_info = ( dvb_service_info_t * )user_data;
    if ( p_dvb_info == NULL ) {
        return 0;
    }
    uint16_t program_num = 0, program_info_len = 0, ca_system_id = 0, ca_pid = 0, sec_len = 0;
    uint8_t desc_tag = 0, desc_len = 0;
    uint8_t *p = NULL;
    int i = 0, index = 0, type = TYPE_INVALID;

    p = ( uint8_t * )data;
    sec_len = ( ( p[1] << 8 | p[2] ) & 0x0FFF );
    program_num = ( p[3] << 8 | p[4] );
    program_info_len = ( ( p[10] << 8 | p[11] ) & 0x0FFF );

    for ( i = 0; i < g_pmt_num; i++ ) {
        if ( p_dvb_info[i].i_program_num == program_num ) {
            index = i;
            break;
        }
    }

    CA_DEBUG( 1, "%s, program_num:%d, program_info_len:%d, sec_len:%d",
              __FUNCTION__, program_num, program_info_len, sec_len );
    p += 12;
    sec_len -= 9;
    sec_len -= program_info_len;

    while ( program_info_len ) {
        CA_DEBUG( 2, "data: %#x, %#x, %#x, %#x, %#x, %#x ", p[0], p[1], p[2], p[3], p[4], p[5] );
        desc_tag = p[0];
        desc_len = p[1];
        ca_system_id = p[2] << 8 | p[3];
        ca_pid = ( ( p[4] << 8 | p[5] ) & 0x1FFF );
        if (desc_tag == 0x9)
        CA_DEBUG( 1, "%s, desc_tag:%d, desc_len:%d, ca_system_id:%#x, ca_pid:%#x",
                  __FUNCTION__, desc_tag, desc_len, ca_system_id, ca_pid );
        if (desc_tag == 0x65) {
		CA_DEBUG(1, "Scrambling_descriptor(0x65) is found, algo:%#x\n", p[2]);
		p_dvb_info[index].private_data[0] = 3;
		p_dvb_info[index].private_data[1] = 0;
		p_dvb_info[index].private_data[2] = p[2];
        }
        if ( AM_CA_IsSystemIdSupported(ca_system_id) ) {
            p_dvb_info[index].i_ca_system_id = ca_system_id;
            p_dvb_info[index].i_ecm_pid[0] = p_dvb_info[index].i_ecm_pid[1] = ca_pid;
            p_dvb_info[index].scrambled = 1;
        }

	if ( desc_len > 4 ) {
		CA_DEBUG( 1, "%s, @@this is ca_private_data, data:%#x",
			  __FUNCTION__, p[6]);
		p_dvb_info[index].private_data[0] = 3;
		p_dvb_info[index].private_data[1] = 1;
		p_dvb_info[index].private_data[2] = p[6];
	}
        program_info_len -= ( desc_len + 2 );
        p += ( desc_len + 2 );
    }

    uint8_t stream_type;
    uint16_t pid, es_info_len;
    CA_DEBUG( 1, "decode es_info, sec_len:%d, data: %#x, %#x, %#x, %#x, %#x",
              sec_len, p[0], p[1], p[2], p[3], p[4] );
    while ( sec_len > 4 ) {
        stream_type = p[0];
        pid = ( ( p[1] << 8 | p[2] ) & 0x1FFF );
        es_info_len = ( ( p[3] << 8 | p[4] ) & 0x0FFF );
        sec_len -= ( 5 + es_info_len );
        CA_DEBUG( 1, "es_info, stream_type:%d, pid:%#x, es_info_len:%d, sec_len:%d\n",
                  stream_type, pid, es_info_len, sec_len );
if (p_dvb_info[index].i_video_pid == 0 ||
	 p_dvb_info[index].i_audio_pid == 0) {
        switch ( stream_type ) {

        /*video pid and video format*/
        case 0x1:
        case 0x2:
            CA_DEBUG( 1, "video pid:%#x, vformat is mpeg12", pid );
            p_dvb_info[index].i_vformat = AV_VIDEO_CODEC_MPEG2;
            p_dvb_info[index].i_video_pid = pid;
            type = TYPE_VIDEO;
            break;
        case 0x10:
            CA_DEBUG( 1, "video pid:%#x, vformat is mpeg4", pid );
            p_dvb_info[index].i_vformat = AV_VIDEO_CODEC_AUTO;
            p_dvb_info[index].i_video_pid = pid;
            type = TYPE_VIDEO;
            break;
        case 0x1b:
            CA_DEBUG( 1, "video pid:%#x, vformat is h264", pid );
            p_dvb_info[index].i_vformat = AV_VIDEO_CODEC_H264;
            p_dvb_info[index].i_video_pid = pid;
            type = TYPE_VIDEO;
            break;
        case 0x24:
            CA_DEBUG( 1, "video pid:%#x, vformat is hevc", pid );
            p_dvb_info[index].i_vformat = AV_VIDEO_CODEC_H265;
            p_dvb_info[index].i_video_pid = pid;
            type = TYPE_VIDEO;
            break;
        case 0xea:
            CA_DEBUG( 1, "video pid:%#x, vformat is vc1", pid );
            p_dvb_info[index].i_vformat = AV_VIDEO_CODEC_AUTO;
            p_dvb_info[index].i_video_pid = pid;
            type = TYPE_VIDEO;
            break;
        case 0x42:
            CA_DEBUG( 1, "video pid:%#x, vformat is avs", pid );
            p_dvb_info[index].i_vformat = AV_VIDEO_CODEC_AUTO;
            p_dvb_info[index].i_video_pid = pid;
            type = TYPE_VIDEO;
            break;
        /*audio pid and audio format*/
        case 0x3:
        case 0x4:
            CA_DEBUG( 1, "audio pid:%#x, aformat is mpeg", pid );
            p_dvb_info[index].i_aformat = AV_AUDIO_CODEC_MP3;
            p_dvb_info[index].i_audio_pid = pid;
            type = TYPE_AUDIO;
            break;
        case 0x0f:
            CA_DEBUG( 1, "audio pid:%#x, aformat is aac", pid );
            p_dvb_info[index].i_aformat = AV_AUDIO_CODEC_AAC;
            p_dvb_info[index].i_audio_pid = pid;
            type = TYPE_AUDIO;
            break;
        case 0x11:
            CA_DEBUG( 1, "audio pid:%#x, aformat is aac_latm", pid );
            p_dvb_info[index].i_aformat = AV_AUDIO_CODEC_LATM;
            p_dvb_info[index].i_audio_pid = pid;
            type = TYPE_AUDIO;
            break;
        case 0x81:
            CA_DEBUG( 1, "audio pid:%#x, aformat is ac3", pid );
            p_dvb_info[index].i_aformat = AV_AUDIO_CODEC_AC3;
            p_dvb_info[index].i_audio_pid = pid;
            type = TYPE_AUDIO;
            break;
        case 0x8A:
        case 0x82:
        case 0x85:
        case 0x86:
            CA_DEBUG( 1, "audio pid:%#x, aformat is dts", pid );
            p_dvb_info[index].i_aformat = AV_AUDIO_CODEC_DTS;
            p_dvb_info[index].i_audio_pid = pid;
            type = TYPE_AUDIO;
            break;

        case 0x6:
            CA_DEBUG( 1, "!!! private pes desc, todo... !!!" );
            break;
        }
}
        parse_ca_descriptor( p+5, &p_dvb_info, es_info_len, index, type );
        p += ( 5 + es_info_len );
    }

    for ( i = 0; i < g_pmt_num; i++ ) {
        if ( p_dvb_info[i].i_video_pid == 0 ) {
            break;
        }
    }
    if ( g_start_time == 0 ) {
        g_start_time = time_ms();
    }
    if ( i >= g_pmt_num || time_ms() - g_start_time >= 5000 ) {
        // read all pmt or took more than x seconds, consider it done
        pmt_done_flag = 1;
    }
    return 0;
}

static int parse_cat_section( const uint8_t *data, void *user_data )
{
    dvb_service_info_t  *p_dvb_info = ( dvb_service_info_t * )user_data;
    if ( p_dvb_info == NULL ) {
        return 0;
    }
    uint16_t ca_system_id = 0, ca_pid = 0, sec_len = 0;
    uint8_t desc_tag = 0, desc_len = 0;
    uint8_t *p = NULL;
    int i = 0, index = 0;

    p = ( uint8_t * )data;
    sec_len = ( ( p[1] << 8 | p[2] ) & 0x0FFF );

    p += 8;
    if ( sec_len <= 5 )
        return 0;
    sec_len -= 5;
    while ( sec_len > 9 ) {
        CA_DEBUG( 2, "%s, cat data: %#x, %#x, %#x, %#x, %#x, %#x ", __FUNCTION__,
                  p[0], p[1], p[2], p[3], p[4], p[5] );
        desc_tag = p[0];
        desc_len = p[1];
        ca_system_id = ( ( p[2] << 8 ) | p[3] );
        ca_pid = ( ( p[4] << 8 ) | p[5] ) & 0x1FFF;
        if ( sec_len < ( desc_len + 2 ) )
            break;
        sec_len -= ( desc_len + 2 );
        p += ( desc_len + 2 );
        if ( AM_CA_IsSystemIdSupported(ca_system_id) ) {
            p_dvb_info[index].i_ca_system_id = ca_system_id;

            for ( i = 0; i < g_pmt_num; i++ ) {
                p_dvb_info[i].i_ca_pid = ca_pid;
            }
        }
        CA_DEBUG( 1, "%s, get cat, tag:%d, len:%d, ca_sys_id:%#x, ca_pid:%#x", __FUNCTION__, desc_tag, desc_len, ca_system_id, ca_pid );
    }

    cat_done_flag = 1;
    return 0;
}

static int parse_ca_descriptor( uint8_t *p, dvb_service_info_t **dvb_info, uint16_t len, int index, int type )
{
    uint16_t ca_system_id = 0, ca_pid = 0;
    uint8_t desc_tag = 0, desc_len = 0;
    dvb_service_info_t *p_dvb_info = *dvb_info;

    while ( len ) {
        CA_DEBUG( 2, "%s, data: %#x, %#x, %#x, %#x, %#x, %#x ", __FUNCTION__, p[0], p[1], p[2], p[3], p[4], p[5] );
        desc_tag = p[0];
        desc_len = p[1];
        ca_system_id = p[2] << 8 | p[3];
        ca_pid = ( ( p[4] << 8 | p[5] ) & 0x1FFF );
        CA_DEBUG( 1, "%s, desc_tag:%#x, desc_len:%d, ca_system_id:%#x, ca_pid:%#x",
                  __FUNCTION__, desc_tag, desc_len, ca_system_id, ca_pid);

        if( desc_tag != 0x9 ) {
            CA_DEBUG(1, "%s, this tag is not ca descriptor", __FUNCTION__);
            switch( desc_tag ) {
                case 0x6A:
                    CA_DEBUG(1, "!!Found AC3 Descriptor!!!");
                    break;
                case 0x7A:
                    CA_DEBUG(1, "!!Found Enhanced AC3 Descriptor!!!");
                    break;
                case 0x7C:
                    CA_DEBUG(1, "!!Found AAC Descriptor!!!");
                    break;
                case 0x7B:
                    CA_DEBUG(1, "!!Found DTS Descriptor!!!");
                    break;
                case 0xA0:
                    CA_DEBUG(1, "!!Found DRA Descriptor!!!");
                    break;
            }
        } else {
            CA_DEBUG(1, "%s, find a ca descriptor", __FUNCTION__);
	    if ( desc_len > 4 ) {
		CA_DEBUG( 1, "%s, @@this is ca_private_data, data:%#x",
			  __FUNCTION__, p[6]);
		p_dvb_info[index].private_data[0] = 3;
		p_dvb_info[index].private_data[1] = 1;
		p_dvb_info[index].private_data[2] = p[6];
	    }
            if ( AM_CA_IsSystemIdSupported(ca_system_id) ) {
                p_dvb_info[index].i_ca_system_id = ca_system_id;
                if ( type == TYPE_AUDIO ) {
                    p_dvb_info[index].i_ecm_pid[0] = ca_pid;
                } else if ( type == TYPE_VIDEO ){
                    p_dvb_info[index].i_ecm_pid[1] = ca_pid;
                } else if ( type == TYPE_SUBTITLE ) {
                    p_dvb_info[index].i_ecm_pid[2] = ca_pid;
                } else if ( type == TYPE_INVALID ) {
                    p_dvb_info[index].i_ecm_pid[0] = p_dvb_info[index].i_ecm_pid[1] = p_dvb_info[index].i_ecm_pid[2] = ca_pid;
                }

            }
        }

        len -= ( desc_len + 2 );
        p += ( desc_len + 2 );
    }
    return 0;
}

static void section_callback(int dev_no, int fid, const uint8_t *data, int len, void *user_data)
{
    uint8_t tid = 0;
    uint16_t sec_len = 0;

    UNUSED(dev_no);
    UNUSED(fid);
    UNUSED(len);
    if (data == NULL) {
        CA_DEBUG(0, "%s, param error", __FUNCTION__);
        return;
    }
    tid = data[0];
    sec_len = (((data[1] & 0x0f) << 4) | data[2]);
    switch (tid) {
    case 0: //PAT
        CA_DEBUG(1,"%s, get a pat section\n", __FUNCTION__);
        parse_pat_section( data, sec_len, user_data );
        break;

    case 2: //PMT
        CA_DEBUG(1,"%s, get a pmt section\n", __FUNCTION__);
        parse_pmt_section( data, user_data );
        break;

    case 1: //CAT
        CA_DEBUG(1,"%s, get a cat section\n", __FUNCTION__);
        parse_cat_section( data, user_data );
        break;

        default:
        CA_DEBUG(1, "%s, unknown section\n", __FUNCTION__);
    }

    return;
}

int aml_scan(void)
{
    int i;
    int filter_handle = -1;
    struct dmx_sct_filter_params filter_param;

    memset(g_info, 0, sizeof(g_info));
    am_dmx_init();

    g_start_time = 0;
    am_dmx_alloc_filter(DMX_DEV_NO, &filter_handle);
    if (filter_handle < 0) {
        CA_DEBUG(1,"alloc dmx pat filter handle FAILED! %d\n", filter_handle);
        return 0;
    }
    CA_DEBUG(1,"alloc dmx pat filter handle = %d\n", filter_handle);
    am_dmx_set_callback(DMX_DEV_NO, filter_handle, section_callback, g_info);
    memset(&filter_param, 0, sizeof(filter_param));
    filter_param.pid = 0;
    filter_param.filter.filter[0] = 0;
    filter_param.filter.mask[0] = 0xff;
    filter_param.flags = 1;

    am_dmx_set_sec_filter(DMX_DEV_NO, filter_handle, &filter_param );
    am_dmx_set_buffer_size(DMX_DEV_NO, filter_handle, 32 * 1024);
    am_dmx_start_filter( DMX_DEV_NO, filter_handle);

    CA_DEBUG(1,"start PAT filter");
    while (!pat_done_flag) {
        usleep(100 * 1000);
    }

    CA_DEBUG(1,"@@ %s, pat is receive done. pmt_num: %d \n", __FUNCTION__, g_pmt_num);
    am_dmx_stop_filter(DMX_DEV_NO, filter_handle);
    am_dmx_free_filter(DMX_DEV_NO, filter_handle);

    CA_DEBUG(1,"start PMT filter");
    int pmt_filter_handles[g_pmt_num];
    for (i = 0; i < g_pmt_num; i++) {
        am_dmx_alloc_filter(DMX_DEV_NO, &pmt_filter_handles[i]);
        am_dmx_set_callback(DMX_DEV_NO, pmt_filter_handles[i], section_callback, g_info);
        memset(&filter_param, 0x0, sizeof(filter_param));
        filter_param.pid = g_info[i].i_pmt_pid;
        filter_param.filter.filter[0] = 2;
        filter_param.filter.mask[0] = 0xff;
        filter_param.flags = 1;

        am_dmx_set_sec_filter(DMX_DEV_NO, pmt_filter_handles[i], &filter_param);
        am_dmx_set_buffer_size(DMX_DEV_NO, pmt_filter_handles[i], 32 * 1024);
        am_dmx_start_filter(DMX_DEV_NO, pmt_filter_handles[i]);
    }

    while (!pmt_done_flag) {
        usleep(10*1000);
    }

    CA_DEBUG(1,"@@ %s, pmt is receive done.\n", __FUNCTION__);

    for(i = 0; i < g_pmt_num; i++) {
        am_dmx_stop_filter(DMX_DEV_NO, pmt_filter_handles[i]);
        am_dmx_free_filter(DMX_DEV_NO, pmt_filter_handles[i]);
    }
#if 1
    am_dmx_alloc_filter(DMX_DEV_NO, &filter_handle);
    am_dmx_set_callback(DMX_DEV_NO, filter_handle, section_callback, g_info);
    memset(&filter_param, 0x0, sizeof(filter_param));
    filter_param.pid = 1;
    filter_param.filter.filter[0] = 1;
    filter_param.filter.mask[0] = 0xff;
    filter_param.flags = 1;

    am_dmx_set_sec_filter(DMX_DEV_NO, filter_handle, &filter_param);
    am_dmx_set_buffer_size(DMX_DEV_NO, filter_handle, 32 * 1024);
    am_dmx_start_filter(DMX_DEV_NO, filter_handle);

    while (!cat_done_flag) {
		static int timeout = 0;
        sleep(1);
		if (++timeout >= 5) {
			break;
		}
    }

    CA_DEBUG(1,"@@ %s, cat is receive done.\n", __FUNCTION__);

    am_dmx_stop_filter(DMX_DEV_NO, filter_handle);
    am_dmx_free_filter(DMX_DEV_NO, filter_handle);
#endif
    return g_pmt_num;
}

dvb_service_info_t* aml_get_program(uint32_t prog_index)
{
    int i;

    for (i = 0; i < g_pmt_num; i++) {
        printf("program_num:%d vpid:%d, apid:%d\r\n",
		g_info[i].i_program_num,
		g_info[i].i_video_pid,
		g_info[i].i_audio_pid);
	if (prog_index == g_info[i].i_program_num) {
	    return &g_info[i];
	}
    }
    printf("\r\n");
    if (prog_index+1 > g_pmt_num) {
	return &g_info[prog_index%g_pmt_num];
    }

    return &g_info[prog_index];
}
