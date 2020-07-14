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

#define  LOADER_MANUFACTURER_ID (24)
#define  LOADER_HARDWARE_VERSION (1)
#define  LOADER_VARIANT (24)
#define  LOADER_SYSTEM_ID (0xFFFF)
#define  LOADER_KEY_VERSION (0)
#define  LOADER_SIGNATURE_VERSION (1)
#define  LOADER_LOAD_VERSION (1)
#define  LOADER_LOADER_VERSION (3 << 8 | 1)

static uint32_t CSSN = 0;

static void str_to_hex(char *str, uint8_t *hex)
{
	int i;
	uint8_t val[2];
	*hex = 0;
	for (i = 0; i < 2; i++)
	{
		if (str[i] >= '0' && str[i] <= '9')
		    val[i] = str[i] - '0';
		else if (str[i] >= 'a' && str[i] <= 'f')
		    val[i] = str[i] - 'a' + 10;
		else if (str[i] >= 'A' && str[i] <= 'F')
		    val[i] = str[i] - 'A' + 10;
	}

	*hex = (val[0] << 4) | val[1];
}

uint32_t ird_get_cssn(void)
{
	return CSSN;
}

Ird_status_t ird_get_loader_status(loader_status_st *pLoaderStatus)
{
	pLoaderStatus->hardwareVersion = LOADER_HARDWARE_VERSION;
	pLoaderStatus->manufacturerId = LOADER_MANUFACTURER_ID;
	pLoaderStatus->keyVersion = LOADER_KEY_VERSION;
	pLoaderStatus->loaderVersion = LOADER_LOADER_VERSION;
	pLoaderStatus->loadVersion = LOADER_LOAD_VERSION;
	pLoaderStatus->signatureVersion = LOADER_SIGNATURE_VERSION;
	pLoaderStatus->systemId = LOADER_SYSTEM_ID;
	pLoaderStatus->variant = LOADER_VARIANT;

	return IRD_NO_ERROR;
}

uc_result UniversalClientSPI_Device_GetDeviceID(uc_buffer_st * pData)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetCSSN(uc_buffer_st * pData)
{
	int32_t result = 0;
	uint8_t cssn[8] = {0};

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	result = MSR_GetChipID(cssn);
	if (result != 0)
	{
		CA_DEBUG(0, "%s get chip id fail: %d", __FUNCTION__, result);
		return UC_ERROR_NULL_PARAM;
	}

	CSSN = (cssn[4] << 24) | (cssn[5] << 16) | (cssn[6] << 8) | cssn[7];

	pData->bytes[0] = cssn[4];
	pData->bytes[1] = cssn[5];
	pData->bytes[2] = cssn[6];
	pData->bytes[3] = cssn[7];
	pData->length = 4;

	CA_DEBUG(0, "cssn = 0x%08x \n", CSSN);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetPrivateData(uc_buffer_st * pData)
{
	uint32_t i;
	FILE *fd = NULL;
	char buf[40], message[64];
	char value[256];

	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	if (AML_NULL == pData)
	{
		CA_DEBUG(0, "[%s]: NULL input pointer\n", __FUNCTION__);
		return UC_ERROR_NULL_PARAM;
	}

	/**private data: md5sum(CCA_PRIVATE_DATA_PREFIX + CSSN) */
    snprintf(message, 64, "echo %s%08x | md5sum", CCA_PRIVATE_DATA_PREFIX, CSSN);
	fd = popen(message, "r");
	if (fd == NULL)
	{
		CA_DEBUG(0, "get private data failed\n");
		memset(message, 0, sizeof(message));
		return UC_ERROR_OUT_OF_MEMORY;
	}
	memset(message, 0, sizeof(message));
	memset(buf, 0, sizeof(buf));
	fgets(buf, 40, fd);
	pclose(fd);

	for (i = 0; i < CCA_PRIVATE_DATA_LEN; i++)
	{
		str_to_hex(buf + 2 * i, &(pData->bytes[i]));
	}

	pData->length = CCA_PRIVATE_DATA_LEN;

#ifdef DUMP_DEBUG
		CA_DEBUG(0, "private data length: %d\n", CCA_PRIVATE_DATA_LEN);
		CA_DEBUG(0, "[%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x][%02x]\n", \
												buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], \
												buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
#endif

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

	return UC_ERROR_SUCCESS;
}


uc_result UniversalClientSPI_Device_SetCSSK(const uc_buffer_st * pKeyMaterial)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_SetExtendedCSSK(const uc_cssk_info * pCSSKInfo)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	CA_DEBUG(0, "[%s]: StreamHandle: %d, isValid: %d, KeyProtection:%d, keyLadder:%d\n", __FUNCTION__, \
									pCSSKInfo->streamHandle, pCSSKInfo->isStreamHandleValid, \
									pCSSKInfo->KeyProtection, pCSSKInfo->keyLadder);

	Spi_Stream_SetCSSK(pCSSKInfo);

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetSecurityState(uc_device_security_state * pDeviceSecurityState)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	pDeviceSecurityState->crypto = SD_CRYPTO_CW_AES_SUPPORTED;
	pDeviceSecurityState->cwMode = 0;
	pDeviceSecurityState->jtag = SD_JTAG_OPENED;
	pDeviceSecurityState->modeIFCP = SD_IFCP_MODE_SUPPORTED;
	pDeviceSecurityState->rsaMode = 0;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetPVRSecurityState(uc_pvr_security_state * pPVRSecurityState)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	pPVRSecurityState->valid = UC_FALSE;
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetChipConfigurationCheck(
                    uc_chip_configuration_request chipConfigurationRequest,
                    uc_chip_configuration_response *pChipConfigurationResponse)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetPlatformIdentifiers(uc_device_platform_identifiers * pDevicePlatformIdentifiers)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	pDevicePlatformIdentifiers->hardwareVersion = LOADER_HARDWARE_VERSION;
	pDevicePlatformIdentifiers->manufacturerId = LOADER_MANUFACTURER_ID;
	pDevicePlatformIdentifiers->keyVersion = LOADER_KEY_VERSION;
	pDevicePlatformIdentifiers->loaderVersion = LOADER_LOADER_VERSION;
	pDevicePlatformIdentifiers->loadVersion = LOADER_LOAD_VERSION;
	pDevicePlatformIdentifiers->signatureVersion = LOADER_SIGNATURE_VERSION;
	pDevicePlatformIdentifiers->systemId = LOADER_SYSTEM_ID;
	pDevicePlatformIdentifiers->variant = LOADER_VARIANT;

	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetPersonalizedData(uc_buffer_st* pData)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_SetCSSN(const uc_buffer_st * pData)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_SetMulti2Parameter(uc_stream_handle streamHandle, uc_device_multi2_parameter *pMulti2Parameter)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetPINCode(uc_buffer_st * pData)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Device_GetIPAddress(uc_buffer_st * pData)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_PVR_SetSessionKey(uc_stream_handle streamHandle, const uc_buffer_st *pPVRSessionKey)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_PVR_SetExtendedSessionKey(uc_stream_handle streamHandle, const uc_pvrsk_info * pPVRSKInfo)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result  UniversalClientSPI_CopyControl_Macrovision_SetConfig(uc_macrovision_config mac_config_data)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result  UniversalClientSPI_CopyControl_Macrovision_SetMode(uc_stream_handle streamHandle, uc_macrovision_mode mac_mode)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result  UniversalClientSPI_CopyControl_SetCCI(uc_stream_handle streamHandle, uc_copy_control_info* pCopyControlInfo)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Smartcard_Open(uc_uint32 *pSmartcardID, uc_sc_open_parameter *pSCOpenData)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Smartcard_Close(uc_uint32 smartcardID)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Smartcard_Reset(uc_uint32 smartcardID)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Smartcard_Communicate(uc_uint32 smartcardID, uc_uint32 headerLen, uc_uint32 payloadLen,uc_byte *pSendBuffer, uc_uint32 *pRecvDataLen, uc_byte *pRecvBuffer )
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_DateTime_GetTimeOfDay(uc_time *pCurrentTime)
{
    struct timeval tv;

	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

    gettimeofday(&tv, NULL);
	pCurrentTime->millisecond = tv.tv_usec / 1000;
	pCurrentTime->second = tv.tv_sec;

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Crypto_Verify(uc_crypto_info *pCryptoInfo)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Timer_Open(uc_uint32* pTimerId,uc_timer_info* pTimerInfo)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Timer_Close(uc_uint32 timerId)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Timer_Stop(uc_uint32 timerId)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Timer_Start(uc_uint32 timerId)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_SetExtraTrickModeControl(uc_stream_handle streamHandle,uc_extra_trick_mode_control *pExtraTrickModeControl)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_HGPC_SendHNAMessage(uc_byte* pHNAMessage)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}

uc_result UniversalClientSPI_Message_CallBack(uc_message_callback messageCallback)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);
	CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);
	return UC_ERROR_SUCCESS;
}


uc_uint32 UniversalClient_Stdlib_strlen(const uc_char *pString)
{
	return strlen(pString);
}

uc_char* UniversalClient_Stdlib_strcpy(uc_char *pDest, const uc_char *pSource)
{
	return strcpy(pDest, pSource);
}

void* UniversalClient_Stdlib_memcpy(void *pDest, const void *pSource, uc_uint32 count)
{
	return memcpy(pDest, pSource, count);
}

void *UniversalClient_Stdlib_memset(void *dest, uc_uint8 c, uc_uint32 count)
{
	return memset(dest, c, count);
}

uc_sint32 UniversalClient_Stdlib_memcmp(const uc_uint8 *pBuf1, const uc_uint8 *pBuf2, uc_uint32 len)
{
	return memcmp(pBuf1, pBuf2, len);
}

void UniversalClient_Stdlib_srand(uc_uint32 seed)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	srand(seed);
	return;
}

uc_uint32 UniversalClient_Stdlib_rand(void)
{
	CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

	return rand();
}

uc_sint32 UniversalClient_Stdlib_printf(const uc_char *pFormat, ...)
{
    int retVal;
    va_list args;

	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

#if 0
    va_start(args, pFormat);
    retVal = vfprintf(stdout, pFormat, args);
    va_end(args);
#endif

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

    return retVal;
}

uc_uint32 UniversalClient_Stdlib_sprintf(uc_char *buffer, const uc_char *format, ...)
{
    int retVal;
    va_list args;

	//CA_DEBUG(0, "[%s]: step in\n", __FUNCTION__);

    va_start(args, format);
    retVal = vsprintf(buffer, format, args);
    va_end(args);

	//CA_DEBUG(0, "[%s]: step out\n", __FUNCTION__);

    return retVal;
}

