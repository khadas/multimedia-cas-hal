#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <linux/dvb/dmx.h>

#include "am_dmx.h"
#include "bc_main.h"
#include "bc_consts.h"
#include "caclientapi.h"
#include "vmx_porting.h"
#include "am_cas.h"
#include "am_cas_internal.h"

#define SMC_DEV_NO (0)

#define MAX_FILTER_NUM 			16
#define MAX_ECM_BUF_SIZE		2048
#define MAX_EMM_INDEX			32
#define EMM_ADDR_LENGTH			4
#define MAX_EMM_BUF_SIZE		(512*1024)
#define MAX_EMM_SECTION_SIZE 	256
#define MAX_NVM_BLOCK_NUM		10

static int am_emm_buf_init();
static int16_t  AM_FlushECM_Buffer( uint8_t bFilterId );
extern int get_dmx_dev(int svc_idx);
extern int find_dmx_dev(int16_t emmpid);

ecm_filter_t 		g_ecm_filter[MAX_FILTER_NUM];
emm_filter_t 		g_emm_filter = {
    .i_fid = -1,
    .i_emm_pid = 0,
    .b_init = 0,
};
uint32_t g_start_time = 0;
uint16_t g_ca_system_id = 0xFFFF;
static uint8_t g_boxid[8] = {0};

#if 1 //only for vmx_indiv
void reset_indiv()
{
    int i;
    unlink(AM_NVM_FILE);
    for ( i = 0; i < MAX_NVM_BLOCK_NUM; i++ ) {
        char fname[64];
        memset( fname, 0, sizeof( fname ) );
        sprintf( fname, "%s%d", AM_NVM_FILE, i );
        unlink(fname);
    }
    printf("individualization cleared\n");
}
#endif //1

static void get_boxid() {
    uint8_t zero[8] = {0};
    if (memcmp(zero, g_boxid, 8) == 0) {
        CA_GetChipID(g_boxid);
    }
}

int vmx_port_init()
{
    int i;

    memset( g_ecm_filter, 0, sizeof( g_ecm_filter ) );
    for ( i = 0; i < MAX_FILTER_NUM; i++ ) {
        g_ecm_filter[i].i_index = -1;
        g_ecm_filter[i].b_initialized = -1;
        g_ecm_filter[i].i_version = 0xFF;
        g_ecm_filter[i].i_page = 0xFF;
        g_ecm_filter[i].i_last_page = 0xFF;
        g_ecm_filter[i].i_read_page = 0;
        g_ecm_filter[i].i_read_len = 0;
        g_ecm_filter[i].b_delivered = -1;
        g_ecm_filter[i].i_len = 0;
        g_ecm_filter[i].p_buf = NULL;
        pthread_mutex_init( &g_ecm_filter[i].lock, NULL );
    }

    am_emm_buf_init();
    g_emm_filter.i_dmx_dev = -1;
    g_emm_filter.i_emm_pid = 0x0000;
    g_emm_filter.i_fid = -1;
    for ( i = 0; i < MAX_EMM_INDEX; i++ ) {
        g_emm_filter.i_emm_addr[i][0] = 0xFF;
        g_emm_filter.i_emm_len[i] = 1;
    }
    pthread_mutex_init( &g_emm_filter.lock, NULL );
    g_emm_filter.b_init = 1;

    am_dmx_init();

    get_boxid();
    return 0;
}

int vmx_port_deinit()
{
    int i;

    for ( i = 0; i < MAX_FILTER_NUM; i++ ) {
        if ( g_ecm_filter[i].p_buf ) {
            CA_DEBUG(1, "%s, free %d ecm buffer:%p", __FUNCTION__, i, g_ecm_filter[i].p_buf);
            free( g_ecm_filter[i].p_buf );
            g_ecm_filter[i].p_buf = NULL;
        }
        pthread_mutex_destroy( &g_ecm_filter[i].lock );
    }
    pthread_mutex_destroy( &g_emm_filter.lock );

    return 0;
}

static int am_emm_buf_init()
{
    g_emm_filter.p_buf = ( uint8_t * )malloc( MAX_EMM_BUF_SIZE );
    memset( g_emm_filter.p_buf, 0, MAX_EMM_BUF_SIZE );
    g_emm_filter.i_buf_len = 0;
    g_emm_filter.p_read = g_emm_filter.p_write = g_emm_filter.p_buf;
    return 0;
}

static int am_emm_buf_write( const uint8_t *buf, int len )
{
    if ( g_emm_filter.i_buf_len + len < MAX_EMM_BUF_SIZE ) {
        memcpy( g_emm_filter.p_buf + g_emm_filter.i_buf_len, buf, len );
        CA_DEBUG( 1, "%s", __FUNCTION__ );
        g_emm_filter.i_buf_len += len;
        return len;
    } else {
        CA_DEBUG( 1, "%s, error", __FUNCTION__ );
        return 0;
    }
}

static int am_emm_buf_read( uint8_t *buf, int len )
{
    int read_len = 0;
    UNUSED(len);
    if ( g_emm_filter.i_buf_len > 0 ) {
        read_len = (g_emm_filter.p_buf[0] << 8) | g_emm_filter.p_buf[1];
        memcpy( buf, g_emm_filter.p_buf + 2, read_len ); //only copy one emm packet
        g_emm_filter.i_buf_len -= ( read_len + 2 );
        if ( g_emm_filter.i_buf_len > 0 ) {
            memmove( g_emm_filter.p_buf, g_emm_filter.p_buf + 2 + read_len, g_emm_filter.i_buf_len );
        }
        CA_DEBUG( 1, "%s, %d, copy %d data", __FUNCTION__, __LINE__, read_len );
        return read_len;
    } else {
        return 0;
    }

}

static void am_emm_callback( int dev_no, int fid, const uint8_t *data, int len, void *user_data )
{
    emm_filter_t *p_emm_filter = ( emm_filter_t * )user_data;
    unsigned int cur_len = 0, cur_tid = 0, cur_index = 0, cur_addr_len = 0;
    UNUSED(dev_no);
    UNUSED(fid);
    UNUSED(len);
    if ( p_emm_filter == NULL || data == NULL ) {
        CA_DEBUG( 1, "%s, param error", __FUNCTION__ );
        return;
    }
    pthread_mutex_lock( &g_emm_filter.lock );
    cur_len = AM_GET_SECTION_LENGTH( data ) + 3;
    cur_tid = AM_GET_TABLE_ID( data );
    cur_index = EMM_GET_INDEX( data );
    cur_addr_len = EMM_GET_ADDR_LEN( data );

    //CA_DEBUG(0, "%s, len:%d, sec_len:%d, cur_tid:%#x, cur_index:%d, cur_addr_len:%d",
     //__FUNCTION__, len, cur_len, cur_tid, cur_index, cur_addr_len);

    if ( cur_index < MAX_EMM_INDEX && cur_addr_len > 0 ) {
        if ( cur_len > MAX_EMM_SECTION_SIZE ) {
            CA_DEBUG( 1, "%s, cur_len is too large", __FUNCTION__ );
        }
        if ( !memcmp( data + 5, p_emm_filter->i_emm_addr[cur_index], cur_addr_len ) ) {
            uint8_t len_1 = cur_len >> 8;
            uint8_t len_2 = cur_len & 0xff;
            am_emm_buf_write( ( const uint8_t * )&len_1, 1 );
            am_emm_buf_write( ( const uint8_t * )&len_2, 1 );
            am_emm_buf_write( data, cur_len );
        } else {
             //CA_DEBUG( 0, "%s, not match, data:%#x, %#x, %#x, cur_index:%d, cur_addr_len:%d",
             // __FUNCTION__, data[5], data[6], data[7], cur_index, cur_addr_len );
        }
    }
    pthread_mutex_unlock( &g_emm_filter.lock );
}

static int am_ecm_reorder( ecm_filter_t *p_ecm_filter, const uint8_t *buf, int len )
{
    //reorder data from page0 to lastpage
    uint8_t cur_tid = 0, cur_ver = 0, cur_page = 0, cur_last_page = 0;
    uint16_t ca_section_length = 0;

    UNUSED(len);

    cur_tid = AM_GET_TABLE_ID( buf );

    //ecm
    cur_ver = ECM_GET_VERSION( buf );
    cur_page = ECM_GET_PAGE_NUMBER( buf );
    cur_last_page = ECM_GET_LAST_PAGE_NUMBER( buf );
    ca_section_length = AM_GET_SECTION_LENGTH( buf ) + 3;

    CA_DEBUG( 1, "$$$ %s, table_id:%#02x, recv_version:%#x, page:%#x, last_page:%#x, sec_len:%d, cur_version:%#x",
              __FUNCTION__, cur_tid, cur_ver, cur_page, cur_last_page, ca_section_length, p_ecm_filter->i_version );
    if ( p_ecm_filter->i_page == 0xFF && cur_page != 0 ) {
        CA_DEBUG( 1, "%s, cur_page is not zero", __FUNCTION__ );
        return -1;
    }
    if ( cur_page == 0 && p_ecm_filter->i_version == 0xFF ) {
        if ( p_ecm_filter->p_buf == NULL ) {
            p_ecm_filter->p_buf = ( uint8_t * )malloc( MAX_ECM_BUF_SIZE );
            memset(p_ecm_filter->p_buf, 0, MAX_ECM_BUF_SIZE);
            CA_DEBUG(1, "%s, malloc ecm buf:%p", __FUNCTION__, p_ecm_filter->p_buf);
        }
        CA_DEBUG( 1, "%s, recive the first page 0", __FUNCTION__ );
        p_ecm_filter->p_buf[0] = ca_section_length;
        memcpy( p_ecm_filter->p_buf + 1, buf, ca_section_length );
        p_ecm_filter->i_len += ( ca_section_length + 1 );
        p_ecm_filter->i_page = cur_page;
        p_ecm_filter->i_last_page = cur_last_page;
        p_ecm_filter->i_version = cur_ver;
        p_ecm_filter->i_table_id = cur_tid;
        if ( cur_page == cur_last_page ) {
            CA_DEBUG( 1, "%s, recive the last page 0, can be delivered ", __FUNCTION__ );
            p_ecm_filter->b_delivered = 1;
        }
    }
    if ( cur_ver != p_ecm_filter->i_version && p_ecm_filter->i_version != 0xFF ) {
        CA_DEBUG( 1, "%s, version is changed, drop", __FUNCTION__ );
        AM_FlushECM_Buffer( p_ecm_filter->i_index );
        p_ecm_filter->i_version = 0xFF;
        p_ecm_filter->i_table_id = 0xFF;
        p_ecm_filter->i_last_page = 0xFF;
        return -1;
    } else if ( cur_tid != p_ecm_filter->i_table_id && p_ecm_filter->i_table_id != 0xFF ) {
        CA_DEBUG( 1, "%s, tid is changed, drop", __FUNCTION__ );
        AM_FlushECM_Buffer( p_ecm_filter->i_index );
        p_ecm_filter->i_version = 0xFF;
        p_ecm_filter->i_table_id = 0xFF;
        p_ecm_filter->i_last_page = 0xFF;
        return -1;
    } else if ( cur_last_page != p_ecm_filter->i_last_page && p_ecm_filter->i_last_page != 0xFF ) {
        CA_DEBUG( 1, "%s, last page is changed, drop", __FUNCTION__ );
        AM_FlushECM_Buffer( p_ecm_filter->i_index );
        p_ecm_filter->i_version = 0xFF;
        p_ecm_filter->i_table_id = 0xFF;
        p_ecm_filter->i_last_page = 0xFF;
        return -1;
    } else if ( cur_ver == p_ecm_filter->i_version && p_ecm_filter->i_version != 0xFF ) {
        //CA_DEBUG( 0, "%s, the same version, cur_page:%d, old_page:%d, last_page:%d ",
        //__FUNCTION__, cur_page, p_ecm_filter->i_page, cur_last_page );
        uint8_t check_page = p_ecm_filter->i_page + 1;
        if ( cur_page == check_page ) {
            if ( p_ecm_filter->i_len + ca_section_length < MAX_ECM_BUF_SIZE && p_ecm_filter->p_buf ) {
                p_ecm_filter->p_buf[p_ecm_filter->i_len] = ca_section_length;
                memcpy( p_ecm_filter->p_buf + p_ecm_filter->i_len + 1, buf, ca_section_length );
                p_ecm_filter->i_len += ( ca_section_length + 1 );
                p_ecm_filter->i_page = cur_page;
                p_ecm_filter->i_version = cur_ver;
                if ( cur_page == cur_last_page ) {
                    CA_DEBUG( 1, "%s, recive the last page, can be delivered ", __FUNCTION__ );
                    p_ecm_filter->b_delivered = 1;
                }
            } else {
                CA_DEBUG( 1, "%s, ecm buffer is has some error ", __FUNCTION__ );
                AM_FlushECM_Buffer( p_ecm_filter->i_index );
                return -1;
            }
        }
    }
    return 0;
}

/**
 * calculates a sequential filter index for the bFilterId values
 * bFilterId is same as bServiceIdx, eg 0x40 is given for IPTV
 * 0xff is returned if bFilterId is out of range
*/
static uint8_t getSequentialFilterIdx( uint8_t bFilterId )
{
    if ( ( bFilterId >= 0xc0 ) && ( bFilterId < (0xc0+4) ) ) /* OTT -> filters 12-15 */
        return (bFilterId - 0xc0) + 12;
    else if ( ( bFilterId >= 0x80 ) && ( bFilterId < (0x80+4) ) )/* DVR -> filters 8-11 */
        return (bFilterId - 0x80) + 8;
    else if ( ( bFilterId >= 0x40 ) && ( bFilterId < (0x40+4) ) ) /* IPTV -> filters 4-7 */
        return (bFilterId - 0x40) + 4;
    else if ( bFilterId < MAX_FILTER_NUM ) {
        /* DVB -> filters 0-3 or already converted indexes */
        /* if there are more than 4 DVB services, this will be a problem */
        return bFilterId;
    }
    return 0xff;
}

static void am_ecm_callback( int dev_no, int fid, const uint8_t *data, int len, void *user_data )
{
    uint8_t cur_tid = 0, cur_ver = 0, cur_page = 0, cur_last_page = 0;
    uint16_t ca_section_length = 0;
    ecm_filter_t *p_ecm_filter = ( ecm_filter_t * )user_data;

    UNUSED(dev_no);
    UNUSED(fid);
    if ( p_ecm_filter == NULL || data == NULL ) {
        CA_DEBUG( 1, "%s, param error", __FUNCTION__ );
        return;
    }

    pthread_mutex_lock( &p_ecm_filter->lock );
    cur_tid = AM_GET_TABLE_ID( data );
    cur_ver = ECM_GET_VERSION( data );
    cur_page = ECM_GET_PAGE_NUMBER( data );
    cur_last_page = ECM_GET_LAST_PAGE_NUMBER( data );
    ca_section_length = AM_GET_SECTION_LENGTH( data ) + 3;
    //CA_DEBUG(0, "%s, cur_tid:%#x, cur_ver:%#x, cur_page:%#x, len:%d",  __FUNCTION__, cur_tid, cur_ver, cur_page, ca_section_length);
    if ( p_ecm_filter->e_filter_mode == k_PageSearch ) {
        am_ecm_reorder( p_ecm_filter, data, len );
    } else if ( p_ecm_filter->e_filter_mode == k_PageLocked ) {
        //CA_DEBUG(0, "%s, cur_tid:%#x, cur_ver:%#x, cur_page:%#x, len:%d", __FUNCTION__, cur_tid, cur_ver, cur_page, ca_section_length);
        //CA_DEBUG(0, "%s, p_ecm_filter, tid:%#x, version:%#x, page:%#x", __FUNCTION__, p_ecm_filter->i_table_id, p_ecm_filter->i_version, p_ecm_filter->i_page);
        if (( cur_tid == p_ecm_filter->i_table_id &&
             cur_ver == p_ecm_filter->i_version && cur_page == p_ecm_filter->i_page ) ||
                (cur_ver != p_ecm_filter->i_version)
            ) {
            if ( p_ecm_filter->p_buf == NULL )
                p_ecm_filter->p_buf = ( uint8_t * )malloc( MAX_ECM_BUF_SIZE );
            memcpy( p_ecm_filter->p_buf, data, ca_section_length );
            //p_ecm_filter->i_len += ca_section_length;
            p_ecm_filter->i_len = ca_section_length;
            p_ecm_filter->b_delivered = 1;
            CA_DEBUG( 1, "%s, k_PageLocked Mode can be delevered data, len:%d", __FUNCTION__, p_ecm_filter->i_len );
        }

    }
    pthread_mutex_unlock( &p_ecm_filter->lock );
}

int16_t  FS_SetECMFilter( uint8_t bFilterId, enFilterMode_t mode, uint16_t wEcmPid,
                          uint8_t bTableId, uint8_t bVersion, uint8_t bPage )
{
    int dmx_dev;
    //CA_DEBUG( 0, "@@call %s @@, id:%d, mode:%d, ecmPid:%#x, table_id:%#x, ver:%#x, page:%d",
    // __FUNCTION__, bFilterId, mode, wEcmPid, bTableId, bVersion, bPage );
    bFilterId = getSequentialFilterIdx( bFilterId );
    if ( bFilterId >= MAX_FILTER_NUM ) {
        return k_BcError;
    }
    dmx_dev = get_dmx_dev(bFilterId);
    if (dmx_dev == -1 && mode != k_DisableFilter) {
        dmx_dev = 0;
        CA_DEBUG( 1, "%s find demux device faild, default use dmx%d",
            __func__, dmx_dev);
    }

    pthread_mutex_lock( &g_ecm_filter[bFilterId].lock );
    struct dmx_sct_filter_params param;
    g_ecm_filter[bFilterId].i_index = bFilterId;
    //g_ecm_filter[bFilterId].e_filter_mode = mode;
    g_ecm_filter[bFilterId].i_ecm_pid = wEcmPid;
    //g_ecm_filter[bFilterId].i_table_id = bTableId;
    //g_ecm_filter[bFilterId].i_version = ( bVersion & 0x3e ) >> 1;
    g_ecm_filter[bFilterId].i_page = bPage;

    if ( mode == k_DisableFilter ) {
        CA_DEBUG( 1, "%s , disable %d filter", __FUNCTION__, bFilterId );
        if ( g_ecm_filter[bFilterId].b_initialized == -1 ) {
            CA_DEBUG( 1, "%s uninit filter", __FUNCTION__ );
            pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
            return k_BcError;
        }

        AM_FlushECM_Buffer( bFilterId );
        am_dmx_stop_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
        am_dmx_free_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
        g_ecm_filter[bFilterId].b_initialized = -1;
        pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
        return k_BcSuccess;

    } else if ( mode == k_PageSearch ) {
        CA_DEBUG( 1, "%s mode:k_PageSearch, bFilterId:%d, init:%d, pid:%#x, table_id:%#x",
                  __FUNCTION__, bFilterId, g_ecm_filter[bFilterId].b_initialized, wEcmPid, bTableId );
        if ( g_ecm_filter[bFilterId].b_initialized == 1 ) {
            CA_DEBUG( 1, "%s this filter already set, disable it first", __FUNCTION__ );
            AM_FlushECM_Buffer( bFilterId );
            am_dmx_stop_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
            am_dmx_free_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
        }
        am_dmx_alloc_filter( dmx_dev, &g_ecm_filter[bFilterId].i_fid );
        CA_DEBUG(1, "pageSearch alloc filterID:%d\n", g_ecm_filter[bFilterId].i_fid);
        am_dmx_set_callback( dmx_dev, g_ecm_filter[bFilterId].i_fid, am_ecm_callback, &g_ecm_filter[bFilterId] );
        memset( &param, 0, sizeof( param ) );
        param.pid = wEcmPid;

        //ecm
        param.filter.filter[0] = 0x80;
        param.filter.mask[0] = 0xfe;

        //param.flags = DMX_CHECK_CRC;

        am_dmx_set_sec_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid, &param );
        am_dmx_set_buffer_size( dmx_dev, g_ecm_filter[bFilterId].i_fid, 32 * 1024 );
        am_dmx_start_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
        g_ecm_filter[bFilterId].i_version = 0xFF;
        g_ecm_filter[bFilterId].e_filter_mode = k_PageSearch;
        g_ecm_filter[bFilterId].b_initialized = 1;
    } else if ( mode == k_PageLocked ) {
        //g_ecm_filter[bFilterId].i_version = bVersion;
        CA_DEBUG( 1, "%s mode:k_PageLocked, bFilterId:%d, init:%d, pid:%#x, table_id:%#x, version:%#x, page:%#x, old_mode:%d",
                  __FUNCTION__, bFilterId, g_ecm_filter[bFilterId].b_initialized, wEcmPid, bTableId, bVersion, bPage & 0xff, g_ecm_filter[bFilterId].e_filter_mode );
        if ( g_ecm_filter[bFilterId].b_initialized == 1 ) {
            CA_DEBUG( 0, "%s filter already initialized, disable it first", __FUNCTION__ );
            AM_FlushECM_Buffer( bFilterId );
            am_dmx_stop_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
            am_dmx_free_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
        }
        am_dmx_alloc_filter( dmx_dev, &g_ecm_filter[bFilterId].i_fid );
        CA_DEBUG(1, "pageLock alloc filterID:%d\n", g_ecm_filter[bFilterId].i_fid);
        am_dmx_set_callback( dmx_dev, g_ecm_filter[bFilterId].i_fid, am_ecm_callback, &g_ecm_filter[bFilterId] );
        memset( &param, 0, sizeof( param ) );
        param.pid = wEcmPid;

        param.filter.filter[0] = bTableId;
        param.filter.mask[0] = 0xfe;


        am_dmx_set_sec_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid, &param );
        am_dmx_set_buffer_size( dmx_dev, g_ecm_filter[bFilterId].i_fid, 32 * 1024 );
        am_dmx_start_filter( dmx_dev, g_ecm_filter[bFilterId].i_fid );
        g_ecm_filter[bFilterId].e_filter_mode = k_PageLocked;
        g_ecm_filter[bFilterId].i_table_id = bTableId;
        g_ecm_filter[bFilterId].i_version = bVersion;
        g_ecm_filter[bFilterId].i_page = bPage;
        g_ecm_filter[bFilterId].b_initialized = 1;
    } else {
        CA_DEBUG( 0, "%s unsupport mode", __FUNCTION__ );
        pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
        return k_BcError;
    }
    pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
    return k_BcSuccess;
}

int16_t  FS_ReadECM( uint8_t bFilterId, uint8_t *pabBuffer, uint16_t *pwLen )
{
    //CA_DEBUG( 0, "@@call %s bFilterId = %d @@", __FUNCTION__, bFilterId);
    bFilterId = getSequentialFilterIdx( bFilterId );
    if ( bFilterId >= MAX_FILTER_NUM ) {
        return k_BcError;
    }
    pthread_mutex_lock( &g_ecm_filter[bFilterId].lock );
    if ( g_ecm_filter[bFilterId].b_delivered == -1 || g_ecm_filter[bFilterId].i_len == 0 ) {
        *pwLen = 0;
        //CA_DEBUG( 0, "%s ecm is not ready, delivered:%d, len:%d ", __FUNCTION__, g_ecm_filter[bFilterId].b_delivered == -1, g_ecm_filter[bFilterId].i_len );
        pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
        return k_BcSuccess; //Error;
    }
    if ( g_ecm_filter[bFilterId].e_filter_mode == k_PageSearch ) {
        int read_index = g_ecm_filter[bFilterId].i_read_len + 1;
        int cur_len = g_ecm_filter[bFilterId].p_buf[g_ecm_filter[bFilterId].i_read_len];
        CA_DEBUG( 1, "%s k_PageSearch, copy data, read_index:%d, read_len:%d, sub_len:%d, cur_read_page:%d, last_page:%d, ecm_pid:%#x, bFilterId:%d",
                  __FUNCTION__, read_index, cur_len, g_ecm_filter[bFilterId].i_len,
                  g_ecm_filter[bFilterId].i_read_page, g_ecm_filter[bFilterId].i_last_page,
                  g_ecm_filter[bFilterId].i_ecm_pid, g_ecm_filter[bFilterId].i_index);
        memcpy( pabBuffer, g_ecm_filter[bFilterId].p_buf + read_index, cur_len );
        *pwLen = cur_len;
        g_ecm_filter[bFilterId].i_read_len += ( cur_len + 1 );

        if ( g_ecm_filter[bFilterId].i_read_page == g_ecm_filter[bFilterId].i_last_page ) {
            AM_FlushECM_Buffer( bFilterId );
        } else {
            g_ecm_filter[bFilterId].i_read_page++;
        }
    } else if ( g_ecm_filter[bFilterId].e_filter_mode == k_PageLocked ) {
        CA_DEBUG( 1, "%s k_PageLocked, copy data, len:%d, ecm_pid:%#x, index:%d",
            __FUNCTION__, g_ecm_filter[bFilterId].i_len,  g_ecm_filter[bFilterId].i_ecm_pid, g_ecm_filter[bFilterId].i_index);
        memcpy( pabBuffer, g_ecm_filter[bFilterId].p_buf, g_ecm_filter[bFilterId].i_len );
        *pwLen = g_ecm_filter[bFilterId].i_len;
        uint8_t ver = g_ecm_filter[bFilterId].i_version;
        AM_FlushECM_Buffer( bFilterId );
        g_ecm_filter[bFilterId].i_version = ver;
    }

    pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
    return k_BcSuccess;
}

int16_t  AM_FlushECM_Buffer( uint8_t bFilterId )
{
    uint8_t tmpId = getSequentialFilterIdx( bFilterId );
    CA_DEBUG( 1, "@@call %s bfilterID: %d, %d, %d", __FUNCTION__, bFilterId, tmpId, g_ecm_filter[tmpId].i_index );

    bFilterId = getSequentialFilterIdx( bFilterId );
    if ( bFilterId >= MAX_FILTER_NUM ) {
        return k_BcError;
    }
    if ( g_ecm_filter[bFilterId].b_initialized == -1 ) {
        CA_DEBUG( 1, "%s uninit filter", __FUNCTION__ );
        return k_BcError;
    }
    if ( g_ecm_filter[bFilterId].p_buf ) {
        CA_DEBUG(1, "%s, init ecm buffer:%p", __FUNCTION__, g_ecm_filter[bFilterId].p_buf);
        memset(g_ecm_filter[bFilterId].p_buf, 0, MAX_ECM_BUF_SIZE);
        g_ecm_filter[bFilterId].i_len = 0;
        g_ecm_filter[bFilterId].i_version = 0xFF;
        g_ecm_filter[bFilterId].i_read_page = 0;
        g_ecm_filter[bFilterId].i_read_len = 0;
        g_ecm_filter[bFilterId].b_delivered = -1;
    }

    return k_BcSuccess;
}

int16_t  FS_FlushECM_Buffer( uint8_t bFilterId )
{
    uint8_t tmpId = getSequentialFilterIdx( bFilterId );
    CA_DEBUG( 1, "@@call %s bfilterID: %d, %d, %d", __FUNCTION__, bFilterId, tmpId, g_ecm_filter[tmpId].i_index );

    bFilterId = getSequentialFilterIdx( bFilterId );
    if ( bFilterId >= MAX_FILTER_NUM ) {
        return k_BcError;
    }
    pthread_mutex_lock( &g_ecm_filter[bFilterId].lock );
    if ( g_ecm_filter[bFilterId].b_initialized == -1 ) {
        CA_DEBUG( 1, "%s uninit filter", __FUNCTION__ );
        pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
        return k_BcError;
    }
    if ( g_ecm_filter[bFilterId].p_buf ) {
        CA_DEBUG(1, "%s, init ecm buffer:%p", __FUNCTION__, g_ecm_filter[bFilterId].p_buf);
        memset(g_ecm_filter[bFilterId].p_buf, 0, MAX_ECM_BUF_SIZE);
        g_ecm_filter[bFilterId].i_len = 0;
        g_ecm_filter[bFilterId].i_version = 0xFF;
        g_ecm_filter[bFilterId].i_read_page = 0;
        g_ecm_filter[bFilterId].i_read_len = 0;
        g_ecm_filter[bFilterId].b_delivered = -1;
    }
    pthread_mutex_unlock( &g_ecm_filter[bFilterId].lock );
    return k_BcSuccess;
}

int16_t  FS_SetEMMFilter( uint8_t bFilterIndex, uint8_t bAddressLength,
                          uint8_t *pabAddress )
{
    int i = 0;
    uint8_t addr[4];
    memset( addr, 0, sizeof( addr ) );
    if ( bAddressLength < 5 ) {
        memcpy( addr, pabAddress, bAddressLength );
    }
    CA_DEBUG( 1, "%s, index:%d, len:%d, addr:%#x,%#x,%#x,%#x, pid:%#x",
              __FUNCTION__, bFilterIndex, bAddressLength, addr[0], addr[1], addr[2], addr[3], g_emm_filter.i_emm_pid );
    if ( pabAddress[0] == 0xFF ) {
        g_emm_filter.i_emm_addr[bFilterIndex][0] = 0xFF;
        g_emm_filter.i_emm_len[bFilterIndex] = 1;
        return	k_BcSuccess;
    }
    if ( g_emm_filter.i_emm_addr[bFilterIndex][0] == 0xFF ) {
        for ( i = 0; i < bAddressLength; i++ )
            g_emm_filter.i_emm_addr[bFilterIndex][i] = *( pabAddress + i );

        g_emm_filter.i_emm_len[bFilterIndex] = bAddressLength;
        return	k_BcSuccess;
    } else {
        CA_DEBUG( 1, "%s, overwrite addr ?", __FUNCTION__ );
        return k_BcError;
    }
    return 0;
}

int16_t  FS_SetEMM_Pid( uint16_t wEmmPid )
{
    int dmx_dev;

    CA_DEBUG( 1, "%s, pid is %#x", __FUNCTION__, wEmmPid );
    dmx_dev = find_dmx_dev(wEmmPid);
    if ( wEmmPid == g_emm_filter.i_emm_pid && dmx_dev == g_emm_filter.i_dmx_dev) {
        CA_DEBUG( 1, "%s, pid has already set", __FUNCTION__ );
        return k_BcSuccess;
    }

    if (g_emm_filter.i_fid != -1) {
	am_dmx_stop_filter( dmx_dev, g_emm_filter.i_fid );
	am_dmx_free_filter( dmx_dev, g_emm_filter.i_fid );
        CA_DEBUG( 1, "%s, stop ; fid/cur %d %d", __FUNCTION__, g_emm_filter.i_fid, g_emm_filter.i_emm_pid );
    }

    g_emm_filter.i_emm_pid = wEmmPid;
    g_emm_filter.i_dmx_dev = dmx_dev;

    if ( wEmmPid == 0x1FFF ) {
        CA_DEBUG( 1, "%s, invalid pid, return", __FUNCTION__ );
        return k_BcSuccess;
    }

    struct dmx_sct_filter_params param;
    am_dmx_alloc_filter( dmx_dev, &g_emm_filter.i_fid );
    am_dmx_set_callback( dmx_dev, g_emm_filter.i_fid, am_emm_callback, &g_emm_filter );
    CA_DEBUG(1, "%s alloc emm filter fid=%d on dmx%d\n", __FUNCTION__, g_emm_filter.i_fid, dmx_dev);
    memset( &param, 0, sizeof( param ) );
    param.pid = wEmmPid;
    param.filter.filter[0] = 0x80;
    param.filter.mask[0] = 0xf0;

    //param.flags = DMX_CHECK_CRC;

    am_dmx_set_sec_filter( dmx_dev, g_emm_filter.i_fid, &param );
    am_dmx_set_buffer_size( dmx_dev, g_emm_filter.i_fid, 512 * 1024 );
    am_dmx_start_filter( dmx_dev, g_emm_filter.i_fid );
    return k_BcSuccess;
}

int16_t  FS_ReadEMM( uint8_t *pabBuffer, uint16_t *pwLen )
{
    pthread_mutex_lock( &g_emm_filter.lock );
    //return k_BcError; //disable emm filtering, should still be able to play 1061, can't play 1059
    int len = *pwLen;
    //CA_DEBUG( 0, "@@call FS_ReadEMM, len:%d", len );
    int ret = am_emm_buf_read( pabBuffer, len );
    if ( ret > 0 ) {
        if (ret >= 16) {
            CA_DEBUG( 1, "%s, read success, len:%d, data:%#x %#x %#x %#x...%#x %#x %#x %#x",
                      __FUNCTION__, ret, pabBuffer[0], pabBuffer[1], pabBuffer[2], pabBuffer[3],
                     pabBuffer[ ret - 4], pabBuffer[ret - 3], pabBuffer[ret - 2], pabBuffer[ret - 1]);
        } else {
            CA_DEBUG( 1, "%s, read success, len:%d, data:%#x %#x %#x %#x",
                      __FUNCTION__, ret, pabBuffer[0], pabBuffer[1], pabBuffer[2], pabBuffer[3] );
        }
        *pwLen = ret;
        pthread_mutex_unlock( &g_emm_filter.lock );
        return k_BcSuccess;
    } else if ( ret == 0 ) {
        *pwLen = ret;
        pthread_mutex_unlock( &g_emm_filter.lock );
        return k_BcSuccess;
    } else {
        //CA_DEBUG( 0, "%s, read error, len:%d", __FUNCTION__, len );
        pthread_mutex_unlock( &g_emm_filter.lock );
        return k_BcError;
    }
    pthread_mutex_unlock( &g_emm_filter.lock );
}

int16_t  FS_FlushEMM_Buffer( void_t )
{
    //CA_DEBUG( 0, "@@call %s @@", __FUNCTION__ );
    pthread_mutex_lock( &g_emm_filter.lock );
    memset( g_emm_filter.p_buf, 0, MAX_EMM_BUF_SIZE );
    g_emm_filter.i_buf_len = 0;
    g_emm_filter.p_read = g_emm_filter.p_write = g_emm_filter.p_buf;
    pthread_mutex_unlock( &g_emm_filter.lock );
    return k_BcSuccess;
}

//// DESCR
int16_t  FS_StartDescrambling( uint16_t wIndex, uint16_t *pawStreamPid, uint8_t bServiceIdx )
{
    UNUSED(wIndex);
    UNUSED(pawStreamPid);
    UNUSED(bServiceIdx);
    CA_DEBUG( 1, "@@call %s @@", __FUNCTION__ );
    return 0;
}
int16_t  FS_StopDescrambling( uint8_t bServiceIdx )
{
    UNUSED(bServiceIdx);
    CA_DEBUG( 1, "@@call %s @@", __FUNCTION__ );
    return 0;
}

// --- System calls ---
int32_t  SYS_GetTickCount( void_t )
{
    //CA_DEBUG( 0, "@@call %s @@", __FUNCTION__ );
    int rc;
    struct timespec now;

    rc = clock_gettime( CLOCK_MONOTONIC, &now );
    if ( rc ) {
        CA_DEBUG( 1, "%s, get clock time error", __FUNCTION__ );
        return k_BcError;
    }

    return ( int32_t )( now.tv_nsec / 1000000 + now.tv_sec * 1000 );
}

int16_t  SYS_ReadNvmBlock( uint8_t *pabDest, uint16_t wLength )
{
    CA_DEBUG( 0, "@@call %s @@[%#x]", __FUNCTION__, wLength);
    FILE *fp;
    int ret;

    //assert( AM_NVM_FILE && pabDest );
    memset(pabDest, 0xff, wLength);
    fp = fopen( AM_NVM_FILE, "rb" );
    if ( !fp ) {
        CA_DEBUG( 2, "cannot open %d" , __LINE__);
        return k_BcSuccess;
    }

    ret = fread( pabDest, 1, wLength, fp );
    fclose( fp );
    if ( !ret ) {
        CA_DEBUG( 2, "%s, read error:\"%s\"", __FUNCTION__, strerror( errno ) );
        return k_BcError;
    }
    if ( ret == wLength ) {
        return k_BcSuccess;
    } else {
        CA_DEBUG( 2, "%s, error, read data:%d, wLen:%d", __FUNCTION__, ret, wLength );
        return k_BcError;
    }
}

int16_t  SYS_WriteNvmBlock( uint8_t *pabSrc, uint16_t wLength )
{
    CA_DEBUG( 0, "@@call %s @@", __FUNCTION__ );
    FILE *fp;
    int ret;

    //assert( AM_NVM_FILE && pabSrc );
    if ( access( AM_NVM_FILE, 0 ) == -1 ) {
        CA_DEBUG( 1, "%s", __FUNCTION__ );
    }
    fp = fopen( AM_NVM_FILE, "wb" );
    if ( !fp ) {
        CA_DEBUG( 2, "cannot open %d" , __LINE__);
        return k_BcError;
    }
    ret = fwrite( pabSrc, 1, wLength, fp );
    fclose( fp );
    if ( !ret ) {
        CA_DEBUG( 2, "%s, write error:\"%s\"", __FUNCTION__, strerror( errno ) );
        return k_BcError;
    }
    if ( ret == wLength ) {
        return k_BcSuccess;
    } else {
        CA_DEBUG( 2, "%s, error, write data:%d, wLen:%d", __FUNCTION__, ret, wLength );
        return k_BcError;
    }
}

int16_t  SYS_ReadNvmData( uint8_t bBlockId, uint8_t *pabDest, uint16_t wLength )
{
    CA_DEBUG( 0, "@@call %s @@[%d][%#x]", __FUNCTION__ , bBlockId, wLength);
    char fname[128];
    FILE *fp;
    int ret;
    if ( bBlockId > MAX_NVM_BLOCK_NUM ) {
        CA_DEBUG( 2, "%s, blockID:%d is too max", __FUNCTION__, bBlockId );
        return k_BcError;
    }
    memset(pabDest, 0xff, wLength);
    memset( fname, 0, sizeof( fname ) );
    sprintf( fname, "%s%d", AM_NVM_FILE, bBlockId );

    fp = fopen( fname, "rb" );
    if ( !fp ) {
        CA_DEBUG( 2, "cannot open %s, l%d" , fname, __LINE__);
        return k_BcSuccess;
    }

    ret = fread( pabDest, 1, wLength, fp );
    fclose( fp );
    if ( !ret ) {
        CA_DEBUG( 2, "%s, read error:\"%s\"", __FUNCTION__, strerror( errno ) );
        return k_BcError;
    }
    if ( ret == wLength ) {
        return k_BcSuccess;
    } else {
        CA_DEBUG( 2, "%s, error, read data:%d, wLen:%d", __FUNCTION__, ret, wLength );
        return k_BcError;
    }
}

int16_t  SYS_WriteNvmData( uint8_t bBlockId, uint8_t *pabSrc, uint16_t wLength )
{
    CA_DEBUG( 0, "@@call %s @@", __FUNCTION__ );
    char fname[128];
    FILE *fp;
    int ret;
    if ( bBlockId > MAX_NVM_BLOCK_NUM ) {
        CA_DEBUG( 1, "%s, blockID:%d is too max", __FUNCTION__, bBlockId );
        return k_BcError;
    }
    memset( fname, 0, sizeof( fname ) );
    sprintf( fname, "%s%d", AM_NVM_FILE, bBlockId );

    fp = fopen( fname, "wb" );
    if ( !fp ) {
        CA_DEBUG( 2, "cannot open %d" , __LINE__);
        return k_BcError;
    }
    ret = fwrite( pabSrc, 1, wLength, fp );
    fclose( fp );
    if ( !ret ) {
        CA_DEBUG( 1, "%s, write error:\"%s\" failed", __FUNCTION__, strerror( errno ) );
        return k_BcError;
    }
    if ( ret == wLength ) {
        return k_BcSuccess;
    } else {
        CA_DEBUG( 1, "%s, error, write data:%d, wLen:%d", __FUNCTION__, ret, wLength );
        return k_BcError;
    }
}

int32_t  SYS_Random( void_t )
{
    //CA_DEBUG( 0, "@@call %s @@", __FUNCTION__ );
    struct timeval tpstart;
    gettimeofday( &tpstart, NULL );
    srand( tpstart.tv_usec );
    int32_t r = rand() % RAND_MAX;
    //CA_DEBUG( 0, "%s, %d", __FUNCTION__, r );
    return r;
}

int16_t  SYS_SetDialogue( uint16_t wDialogLength, uint8_t *pabDialogue )
{
    UNUSED(wDialogLength);
    UNUSED(pabDialogue);
    CA_DEBUG( 0, "@@call %s @@", __FUNCTION__ );
    return 0;
}

void_t SYS_GetBoxId( uint8_t *pabBoxId )
{
    CA_DEBUG( 1, "@@call %s @@", __FUNCTION__ );
    if (pabBoxId) {
        memcpy(pabBoxId, g_boxid, 8);
    }
    return;
}

int16_t IO_Printf( const char *format, /* args*/ ... )
{
    int ret;
    va_list ap;

    va_start( ap, format );
    ret = vfprintf( stdout, format, ap );
    va_end( ap );
    return ( ret );
}

void_t *LIBC_malloc( int32_t sz )
{
    return malloc( sz );
}

void_t DVR_OK( uint8_t bChannelId, uint8_t bMode )
{
    CA_DEBUG( 1, "@@call %s channel=%#x mode=%d @@", __FUNCTION__, bChannelId, bMode );
    return;
}

void_t DVR_UsedKey( uint8_t bChannelId, uint8_t bMode )
{
    CA_DEBUG( 1, "@@call %s channel=%#x mode=%d @@", __FUNCTION__, bChannelId, bMode );
    return;
}

typedef short (*TestCB_t)( unsigned char bMode,
        unsigned char bInfo,
        unsigned char *pabData,
        unsigned int lLen );

TestCB_t g_testcb = NULL;
void_t SYS_InstallTestCallback ( TestCB_t cb )
{
    CA_DEBUG(1, "%s %p", __func__, cb);

    if (cb) {
        g_testcb = cb;
    }
}
