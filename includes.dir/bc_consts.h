/*****************************************************************************
 ******************************************************************************
 *
 *         File : bc_consts.h
 *
 *  Description : File to be included by the host software with all
 *                definitions of constants
 *
 *    Copyright : BETARESEARCH 2003 (c)
 *    Copyright : COMVENIENT  2008 (c)
 *    Copyright : Verimatrix 2011 (c)
 *
 ******************************************************************************
 *****************************************************************************/

/**************************** CVS Infos ****************************************
 *
 *  $Source: /home/boxop/cvsroot/bc2_cam_src/bc_consts.h,v $
 *  $Date: 2012/12/17 12:25:52 $
 *  $Revision: 1.4.1.1 $
 *
 ***************************** CVS Infos ***************************************/

#ifndef _BC_CONSTS_H_DEF_
#define _BC_CONSTS_H_DEF_

typedef enum
{
	k_PageSearch,
	k_PageLocked,
	k_DisableFilter
}  enFilterMode_t;

typedef enum
{
	k_SC_Ok = 0,
	k_SC_NotPresent,
	k_SC_HwError,
	k_SC_Rejected,
	k_SC_UpdateRequired,
	k_SC_NSC
} enScState_t;

typedef enum
{
	k_DS_Ok = 0,
	k_DS_Error,
	k_DS_NoECMs,
	k_DS_ClearOrForeignEs,
	k_DS_Preview,
	k_DS_Pairing,
	k_DS_MS,
	k_DS_NoCWs,
	k_DS_Region,
	k_Init   // only for internal use
} enDescState_t;

typedef enum
{
	k_ConnectBc = 0,
	k_DisconnectBc
} enBcCmd_t;

typedef enum
{
	k_BcPinVerified            = 0x00,
	k_BcPinChanged             = 0x01,
	k_BcPinFailure             = 0x21,
	k_BcPinBlocked             = 0x22,
	k_BcPinMayNotBeChanged     = 0x23,
	k_BcPinMayNotBeBypassed    = 0x24,
	k_BcPinBadIndex            = 0x25,
	k_BcPinBadLength           = 0x26,
	k_BcPinNotEnoughPurse      = 0x30,
	k_BcPinGeneralError        = 0xFF
} enBcNotify_t;

typedef enum
{
	k_ConnectSc = 0,
	k_DisconnectSc,
	k_ResetSc,
	k_GetATRSc,
	k_CardDetectSc
} enCmd_t;

typedef enum
{
	k_Success    = 0,
	k_Error      = 1,
	k_UnknownCmd = 2
} enReturn_t;

typedef enum
{
	BC_SC_NONE = 0,
	BC_SC_RW_COMPLETED,
	BC_SC_SETPARAM_COMPLETED,
	BC_SC_POWERDOWN_COMPLETED,
	BC_SC_INSERTED,
	BC_SC_REMOVED,
	BC_SC_ERROR,
	BC_SC_RESET,
	BC_SC_MUTE
} enBcScNotify_t;

#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifndef EOF
#define EOF (-1)
#endif


#define CARD_SLOTS                          1   // number of card slots

// block ids for non volatile memory
#define NVM_BLOCK_0                         0
#define NVM_BLOCK_1                         1
#define NVM_BLOCK_2                         2
#define NVM_BLOCK_3                         3
#define NVM_BLOCK_4                         4
#define NVM_BLOCK_5                         5
#define NVM_BLOCK_6                         6
#define NVM_BLOCK_7                         7
#define NVM_BLOCK_8                         8
#define NVM_BLOCK_9                         9

#define k_BcNSc                             1
#define k_BcSuccess                         0
#define k_BcError                          -1
#define k_BcGeneralError                   -2
#define k_BcEmmQueueOverflowError          -3
#define k_BcEcmQueueOverflowError          -4
#define k_BcFilterInUseError               -5
#define k_BcNoRespAvailable                -6
#define k_BcScBusy                         -7
#define k_BcNothingDone                    -8
#define k_BcNotSupported                   -9
#define k_BcTimedOut                       -10

#define k_BcMacroVisionControlNotAvailable  0xFF
#define k_CaIdNotAvailable                  0xFFFF

#define k_BcNoPairing                         0
#define k_BcPairingInProgress                 1
#define k_BcPairingOk                         2
#define k_BcPairingBad                        3

#define MAX_EMM_INDEX                       32
#define MAX_ADDR_LEN                        4


#define BC_PIN_PC                           0x00
#define BC_PIN_IPPV_PC                      0x01
#define BC_PIN_STB_LOCK                     0x02
#define BC_PIN_SHOPPING                     0x03

#ifdef BC_DVR_INCLUDED
#define k_BcDVRBadInfo -2
#define k_BcDVRServiceNotActive -3
#define k_BcDVRChannelAlreadyInUse -4
#define k_BcDVRChannelNotInUse -5
#define k_BcDVRNoTime -6
#define k_BcDVRBadStoreData -7
#define k_BcDVRDataError  -8
#define k_BcDVRNoRecording  -9
#define k_BcDVRNoReplay  -10
#endif

#endif
// _BC_CONSTS_H_DEF_
