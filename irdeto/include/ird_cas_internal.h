/*
 * Copyright (C) 2015 Amlogic, Inc.
 *
 *
 */
#ifndef IRD_CAS_INTERNAL_H
#define IRD_CAS_INTERNAL_H

/****zyl***/
#include "UniversalClient_Common_API.h"
#include "am_cas.h"
#include "ird_cas.h"

#define ird_true 	(1)
#define ird_false	(0)
typedef struct
{
    char        location[MAX_LOCATION_SIZE];     /**< Location of the record file.*/
    int         segment_id;                      /**< Current segment's index.*/
    loff_t      offset;                          /**< Current offset in the segment file.*/
}IRD_Metadata_PVRCryptoPara_t;
/****zyl***/

typedef enum
{
	IRD_PLAY_NONE = 0,
	IRD_PLAY_EMM = 1,
	IRD_PLAY_LIVE = 2,
	IRD_PLAY_RECORD  = 3,
	IRD_PLAY_TIMESHIFT  = 4,
	IRD_PLAY_PLAYBACK  = 5,
} IRD_SERVICE_TYPE;

typedef struct _service_monitor
{
    struct _service_monitor	*next;
    char	*monitorStr;
} service_monitor_st;


int ird_client_init(void);
void ird_client_start(void);
int ird_open_service(int dmx_dev, IRD_SERVICE_TYPE type);
void ird_close_service(int index);
int ird_get_dmx_dev(void* pServiceContext);
int ird_process_pmt(int handleId, uint8_t *pdata, uint16_t len);
int ird_process_cat(int handleId, uint8_t *pdata, uint16_t len);
int ird_start_record(int handleId);
int ird_stop_record(int handleId);
int ird_submit_metadata(int handleId, uint8_t *pdata, uint16_t len);
uint32_t ird_get_cssn(void);

/****zyl***/
Ird_status_t ird_metadata_GetServiceHandle(unsigned int index, uc_service_handle *phServiceHandle);

Ird_status_t ird_metadata_ResetPVRStoreInfo(uc_service_handle hServiceHandle);
Ird_status_t ird_metadata_SaveStoreInfoToFile(uc_service_handle	hServiceHandle, uc_uint32 u32Len, uc_byte *pData);
Ird_status_t ird_metadata_SetRecordCryptoPara(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara);
Ird_status_t ird_metadata_SubmitPVRCryptoInfo(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara);
Ird_status_t ird_metadata_SubmitFirstPVRCryptoInfo(uc_service_handle hServiceHandle, IRD_Metadata_PVRCryptoPara_t *pstRecordCryptoPara);
/****zyl***/

int ird_test(void);

#endif // IRD_CAS_INTERNAL_H

