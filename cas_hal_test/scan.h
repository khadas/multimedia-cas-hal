#ifndef _AML_SCAN_H_
#define _AML_SCAN_H_

typedef enum {
    SCRAMBLE_ALGO_CSA,
    SCRAMBLE_ALGO_AES,
    SCRAMBLE_ALGO_INVALID,
    SCRAMBLE_ALGO_NONE
} SCRAMBLE_ALGO_t;

typedef enum {
    SCRAMBLE_MODE_ECB,
    SCRAMBLE_MODE_CBC,
    SCRAMBLE_MODE_INVALID
} SCRAMBLE_MODE_t;

typedef enum {
    SCRAMBLE_ALIGNMENT_LEFT,
    SCRAMBLE_ALIGNMENT_RIGHT,
    SCRAMBLE_ALIGNMENT_INVALID
} SCRAMBLE_ALIGNMENT_t;

typedef enum {
    TYPE_AUDIO,
    TYPE_VIDEO,
    TYPE_SUBTITLE,
    TYPE_INVALID
} STREAM_TYPE_t;

typedef struct SCRAMBLE_INFO_s {
    SCRAMBLE_ALGO_t             algo;
    SCRAMBLE_MODE_t             mode;
    SCRAMBLE_ALIGNMENT_t        alignment;
    uint8_t                                     has_iv_value;
    uint8_t                                     iv_value_data[16];
} SCRAMBLE_INFO_t;

typedef struct dvb_service_info_s {

    uint16_t                    i_program_num;
    uint16_t                    i_pmt_pid;
    uint16_t                    i_ca_desc_len;
    uint16_t                    i_ca_system_id;
    uint16_t                    i_ca_pid;
    SCRAMBLE_INFO_t             t_scramble_info;

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
} dvb_service_info_t;

int aml_scan(void);
dvb_service_info_t* aml_get_program(uint32_t prog_index);
int aml_set_ca_system_id(int ca_sys_id);
int file_read(const char *name, char *buf, int len);
#endif
