#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

#include "UniversalClient_API.h"
#include "UniversalClient_Common_SPI.h"
#include "UniversalClient_IPTV_API.h"
#include "UniversalClient_Stdlib.h"
#include "UniversalClient_Common_API.h"
#include "UniversalClient_DVB_API.h"
#include "UniversalClient_SPI.h"
#include "UniversalClient_Types.h"

uc_uint32 UniversalClientSPI_GetVersion(void)
{
	return UNIVERSALCLIENTSPI_VERSION;
}

void UniversalClientSPI_GetImplementation(uc_spi_implementation_st *pImpl)
{
	pImpl->Memory_Malloc = UniversalClientSPI_Memory_Malloc;
	pImpl->Memory_Free = UniversalClientSPI_Memory_Free;

	pImpl->Semaphore_Open = UniversalClientSPI_Semaphore_Open;
	pImpl->Semaphore_Post = UniversalClientSPI_Semaphore_Post;
	pImpl->Semaphore_Wait = UniversalClientSPI_Semaphore_Wait;
	pImpl->Semaphore_Close = UniversalClientSPI_Semaphore_Close;
	pImpl->Semaphore_WaitTimeout = UniversalClientSPI_Semaphore_WaitTimeout;

	pImpl->Mutex_Open = UniversalClientSPI_Mutex_Open;
	pImpl->Mutex_Lock = UniversalClientSPI_Mutex_Lock;
	pImpl->Mutex_Unlock = UniversalClientSPI_Mutex_Unlock;
	pImpl->Mutex_Close = UniversalClientSPI_Mutex_Close;

	pImpl->Thread_Open = UniversalClientSPI_Thread_Open;
	pImpl->Thread_Sleep = UniversalClientSPI_Thread_Sleep;
	pImpl->Thread_Close = UniversalClientSPI_Thread_Close;

	pImpl->PS_Delete = UniversalClientSPI_PS_Delete;
	pImpl->PS_Write = UniversalClientSPI_PS_Write;
	pImpl->PS_Read = UniversalClientSPI_PS_Read;
	pImpl->PS_GetProperty = UniversalClientSPI_PS_GetProperty;
	pImpl->PS_Initialize = UniversalClientSPI_PS_Initialize;
	pImpl->PS_Terminate = UniversalClientSPI_PS_Terminate;

	pImpl->Device_GetCSSN = UniversalClientSPI_Device_GetCSSN;
	//pImpl->Device_SetCSSK = UniversalClientSPI_Device_SetCSSK;
	pImpl->Device_SetExtendedCSSK = UniversalClientSPI_Device_SetExtendedCSSK;
	pImpl->Device_GetPrivateData = UniversalClientSPI_Device_GetPrivateData;
	pImpl->Device_GetSecurityState = UniversalClientSPI_Device_GetSecurityState;
	pImpl->Device_GetPlatformIdentifiers = UniversalClientSPI_Device_GetPlatformIdentifiers;
	pImpl->Device_GetPersonalizedData = UniversalClientSPI_Device_GetPersonalizedData;
	pImpl->Device_GetDeviceID = UniversalClientSPI_Device_GetDeviceID;
	pImpl->Device_GetIPAddress = UniversalClientSPI_Device_GetIPAddress;
	pImpl->Device_GetPVRSecurityState = UniversalClientSPI_Device_GetPVRSecurityState;
	pImpl->Device_GetChipConfigurationCheck = UniversalClientSPI_Device_GetChipConfigurationCheck;
	pImpl->Device_SetCSSN = UniversalClientSPI_Device_SetCSSN;
	pImpl->Device_GetPINCode = UniversalClientSPI_Device_GetPINCode;
	pImpl->Device_SetMulti2Parameter = UniversalClientSPI_Device_SetMulti2Parameter;

	pImpl->Stream_Open = UniversalClientSPI_Stream_Open;
	pImpl->Stream_AddComponent = UniversalClientSPI_Stream_AddComponent;
	pImpl->Stream_RemoveComponent = UniversalClientSPI_Stream_RemoveComponent;
	pImpl->Stream_Start = UniversalClientSPI_Stream_Start;
	pImpl->Stream_Stop = UniversalClientSPI_Stream_Stop;
	pImpl->Stream_OpenFilter = UniversalClientSPI_Stream_OpenFilter;
	pImpl->Stream_SetFilter = UniversalClientSPI_Stream_SetFilter;
	pImpl->Stream_CloseFilter = UniversalClientSPI_Stream_CloseFilter;
	pImpl->Stream_Connect = UniversalClientSPI_Stream_Connect;
	pImpl->Stream_Extended_Connect = UniversalClientSPI_Stream_Extended_Connect;
	pImpl->Stream_Disconnect = UniversalClientSPI_Stream_Disconnect;
	pImpl->Stream_Extended_Connect = UniversalClientSPI_Stream_Extended_Connect;
	pImpl->Stream_SetDescramblingKey = UniversalClientSPI_Stream_SetDescramblingKey;
	pImpl->Stream_CleanDescramblingKey = UniversalClientSPI_Stream_CleanDescramblingKey;
	pImpl->Stream_Close = UniversalClientSPI_Stream_Close;
	pImpl->Stream_Send = UniversalClientSPI_Stream_Send;

	pImpl->PVR_SetSessionKey = UniversalClientSPI_PVR_SetSessionKey;
	pImpl->PVR_SetExtendedSessionKey = UniversalClientSPI_PVR_SetExtendedSessionKey;

	pImpl->CopyControl_Macrovision_SetConfig = UniversalClientSPI_CopyControl_Macrovision_SetConfig;
	pImpl->CopyControl_Macrovision_SetMode = UniversalClientSPI_CopyControl_Macrovision_SetMode;
	pImpl->CopyControl_SetCCI = UniversalClientSPI_CopyControl_SetCCI;

	pImpl->FatalError = UniversalClientSPI_FatalError;

	pImpl->Smartcard_Open = UniversalClientSPI_Smartcard_Open;
	pImpl->Smartcard_Close = UniversalClientSPI_Smartcard_Close;
	pImpl->Smartcard_Reset = UniversalClientSPI_Smartcard_Reset;
	pImpl->Smartcard_Communicate = UniversalClientSPI_Smartcard_Communicate;

	pImpl->DateTime_GetTimeOfDay = UniversalClientSPI_DateTime_GetTimeOfDay;
	pImpl->Crypto_Verify = UniversalClientSPI_Crypto_Verify;

	pImpl->Timer_Open = UniversalClientSPI_Timer_Open;
	pImpl->Timer_Close = UniversalClientSPI_Timer_Close;
	pImpl->Timer_Start = UniversalClientSPI_Timer_Start;
	pImpl->Timer_Stop = UniversalClientSPI_Timer_Stop;

	pImpl->IFCP_Communicate = UniversalClientSPI_IFCP_Communicate;
	pImpl->IFCP_LoadImage = UniversalClientSPI_IFCP_LoadImage;

	pImpl->SetExtraTrickModeControl = UniversalClientSPI_SetExtraTrickModeControl;
	pImpl->HGPC_SendHNAMessage = UniversalClientSPI_HGPC_SendHNAMessage;
	pImpl->SCOT_LoadTransformationData = UniversalClientSPI_SCOT_LoadTransformationData;

	pImpl->Message_CallBack = UniversalClientSPI_Message_CallBack;
}
