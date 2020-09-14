#ifndef _VMX_PORT_H_
#define _VMX_PORT_H_
#define MAX_EMM_INDEX                   32
#define EMM_ADDR_LENGTH                 4
#define AM_SMC_MAX_BUF                  512

#define AM_GET_SECTION_LENGTH( BUF )    (uint16_t)(ECM_READ_16( &(BUF)[1] ) & 0x0FFF)
#define AM_GET_TABLE_ID( BUF )    (uint8_t)((BUF)[0] & 0xFF)
#define AM_GET_PROGRAM_NUM( BUF ) ((uint16_t)((BUF)[0]<<8|(BUF)[1]))
#define AM_GET_PMT_PID( BUF )    (uint16_t)(ECM_READ_16( &(BUF)[1] ) & 0x1FFF)

#define ECM_READ_16( BUF ) ((uint16_t)((BUF)[0]<<8|(BUF)[1]))
#define ECM_GET_VERSION( BUF )    (uint8_t)(((BUF)[3]  & 0x3E)>>1)
#define ECM_GET_CURR_NXT( BUF )    (uint8_t)((BUF)[3] & 0x01)
#define ECM_GET_PAGE_NUMBER( BUF )    (uint8_t)((BUF)[4] & 0xFF)
#define ECM_GET_LAST_PAGE_NUMBER( BUF )    (uint8_t)((BUF)[5] & 0xFF)

#define EMM_GET_INDEX( BUF )    (uint8_t)(((BUF)[3]  & 0x1F))
#define EMM_GET_ADDR_LEN( BUF )    (uint8_t)((BUF)[4] & 0x07)

typedef struct ecm_filter_s {
    int                                 i_index;
    int                                 i_fid;
    uint16_t                    i_ecm_pid;
    int                                 b_initialized;
    enFilterMode_t              e_filter_mode;

    uint8_t                     i_table_id;
    uint8_t                     i_version;
    uint8_t                     i_page;
    uint8_t                     i_last_page;
    uint8_t                     i_read_page;
    uint8_t                     i_read_len;
    pthread_mutex_t     lock;
    int                                 b_delivered;
    int                                 i_len;
    uint8_t                     *p_buf;
} ecm_filter_t;

typedef struct emm_filter_s {
    int 		i_dmx_dev;
    int                                 i_fid;
    pthread_mutex_t     lock;
    uint16_t                    i_emm_pid;
    int                                 b_init;
    uint8_t                     i_emm_addr[MAX_EMM_INDEX][EMM_ADDR_LENGTH];
    uint32_t                    i_emm_len[MAX_EMM_INDEX];
    uint8_t                     *p_buf;
    uint32_t                    i_buf_len;
    uint8_t                             *p_read;
    uint8_t                             *p_write;
} emm_filter_t;

#endif
