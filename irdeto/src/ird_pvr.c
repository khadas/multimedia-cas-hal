#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#include "UniversalClient_API.h"
#include "UniversalClient_Common_SPI.h"
#include "UniversalClient_IPTV_API.h"
#include "UniversalClient_Stdlib.h"
#include "UniversalClient_Common_API.h"
#include "UniversalClient_DVB_API.h"
#include "UniversalClient_SPI.h"
#include "UniversalClient_Types.h"

//#undef ANDROID

#include "am_cas.h"
#include "caclientapi.h"
#include "ird_cas.h"

uc_result PVRRecord(uc_service_handle serviceHandle)
{
    uc_result ret = UC_ERROR_SUCCESS;
    /* Make up a TLV for PVR record
    */
    uc_byte tlv[3] = {0};
    tlv[0] = UC_TLV_TAG_FOR_PVR_RECORD;
    tlv[1] = 0;
    tlv[2] = 0;
    /* Trigger the PVR record.
    */
    ret = UniversalClient_ConfigService(serviceHandle, sizeof(tlv), tlv);
    /* If the content can be recorded, some time later the SPI: UniversalClientSPI_PVR_SetSessionKey or UniversalClientSPI_PVR_SetExtendedSessionKey
     * will be called and at least one service message of type UC_SERVICE_PVR_SESSION_METADATA_REPLY will be sent to application. service message of type
     * UC_SERVICE_PVR_RECORD_STATUS_REPLY will also be sent.
    */
    return ret;
}
/* Call this method to stop the PVR recording.
*/
uc_result PVRStopRecord(uc_service_handle serviceHandle)
{
    uc_result ret = UC_ERROR_SUCCESS;
    /* Make up a TLV for Stop PVR record
    */
    uc_byte tlv[3] = {0};
    tlv[0] = UC_TLV_TAG_FOR_STOP_PVR_RECORD;
    tlv[1] = 0;
    tlv[2] = 0;
    /* Trigger the PVR record.
    */
    ret = UniversalClient_ConfigService(serviceHandle, sizeof(tlv), tlv);
    return ret;
}