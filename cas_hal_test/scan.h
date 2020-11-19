#ifndef _AML_SCAN_H_
#define _AML_SCAN_H_

typedef enum {
    TYPE_AUDIO,
    TYPE_VIDEO,
    TYPE_SUBTITLE,
    TYPE_INVALID
} STREAM_TYPE_t;

#define DVB_TYPE 0
#define IPTV_TYPE 1

typedef struct dvb_service_info_s {

    uint16_t                    i_program_num;
    uint16_t                    i_pmt_pid;
    uint16_t                    i_ca_desc_len;
    uint16_t                    i_ca_system_id;
    uint16_t                    i_ca_pid;
    uint8_t			private_data[16];

    uint8_t                     i_service_index;
    uint16_t                    i_service_num;
    uint16_t                    i_desc_num;
    uint16_t                    i_ecm_pid[3];
    uint8_t                     i_aformat;
    uint8_t                     i_vformat;
    uint16_t                    i_audio_pid;
    uint16_t                    i_video_pid;
    int                         i_audio_channel;
    int                         i_video_channel;

    int                         scrambled;
    int				service_type;
} dvb_service_info_t;

int aml_scan(void);
dvb_service_info_t* aml_get_program(uint32_t prog_index);
int aml_set_ca_system_id(int ca_sys_id);
int file_read(const char *name, char *buf, int len);
#endif
