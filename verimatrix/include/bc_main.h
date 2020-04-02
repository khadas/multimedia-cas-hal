/*****************************************************************************
 ******************************************************************************
 *
 *         File : bc_main.h
 *
 * Description : MAIN module header file for CAMLIB.000.2-IGL2.17S-E00
 *
 *    Copyright : BETARESEARCH 2003 (c)
 *    Copyright : COMVENIENT  2008 (c)
 *    Copyright : Verimatrix  2011-2015 (c)
 *
 ******************************************************************************
 *****************************************************************************/

/**************************** CVS Infos ****************************************
 *
 *  $Source: /home/boxop/cvsroot/bc2_cam_src/bc_main.h,v $
 *  $Date: 2015/06/25 11:26:32 $
 *  $Revision: 1.17 $
 *
 ***************************** CVS Infos ***************************************/

#define _VERSION_2_00_
#ifndef _BCMAIN_H_DEF_
#define _BCMAIN_H_DEF_

#ifndef _BC_TYPES_H_
#include "bc_types.h"
#endif
#ifndef _BC_CONSTS_H_DEF_
#include "bc_consts.h"
#endif

// ***************************************************************************
//      betacrypt library externals
//
// input/output to be used by the host system
//
// ECM PID (max 8) / Stream PID (max 8)
// BC - Betacrypt
// SC - Smartcard
// FS - Filtersection / descrambler
// MMI - Man Machine Interface
// PC - Parental Control
// OSD - On Screen Display
// ISC - Interactive Smart Card
// RC - Return Channel
// LIBC - Interface to functions from libc
// ***************************************************************************


// ***************************************************************************
// ***************** Output functions of the host system *********************

extern int16_t BC_Init(void_t);
extern int16_t BC_CheckNSc( void_t );

#ifdef BC_NSC_INCLUDED
extern int16_t  BC_InitNSc(uint8_t* pabPtr, uint16_t* pwLen );
extern int16_t BC_InitNScComm( uint8_t* pabPtr, uint16_t* pwLen,
		uint8_t* pabBoxSerNo,
		uint8_t* pabManuId,
		uint8_t* pabManuData,
		uint8_t* pabProvId,
		uint8_t* pabProvData );
#endif
extern void_t   BC_Task(void_t);
extern void_t   BC_GetVersion(uint8_t* pacVersion, uint8_t* pacDate, uint8_t* pacTime);
extern uint16_t BC_Get_CASystemID(void_t);
extern int16_t  BC_SetEMM_Pid(uint16_t wEmmPid);
extern uint8_t  BC_GetMacroVisionCtrl(uint16_t wServiceId, uint8_t bServiceIdx);
extern int16_t  BC_CheckPin(uint8_t bPinLength, uint8_t* pabPin, uint8_t bPinIndex, uint8_t bReason, uint8_t bServiceIdx);
extern int16_t  BC_ChangePin(uint8_t bOldPinLength, uint8_t* pabOldPin,
		uint8_t bNewPinLength, uint8_t* pabNewPin,
		uint8_t bPinIndex);
extern int16_t  BC_Ioctl(enBcCmd_t cmd, void_t* pvParams, uint16_t* pwLen);
extern int16_t  BC_StartDescrambling(uint16_t wServiceId, uint16_t wIndex,
		uint16_t * pawEcmPid, uint16_t *pawStreamPid,
		uint8_t bServiceIdx);
extern int16_t  BC_StopDescrambling(uint16_t wServiceId, uint8_t bServiceIdx);
extern int16_t  BC_SetSTBFilterAddress( uint8_t bAddressLen, uint8_t* pabAddress );

// initialize the OSM window system. wMaxWidth and wMaxHeight define
// the real pixel size of the screen that can be used for displaying
// text messages. The values for wX and wY will always be handed over
// within the boundaries
//     0 <= wX < wMaxWidth
//     0 <= wY < wMaxHeight
// bUnblockString is appended to the message, if the window can be
// removed by the customer. E.g. if the customer must press the
// OK-button, the string could look like "OK?". This text is
// appended on a separate line.
extern void_t   BC_InitWindow( uint16_t wMaxWidth, uint16_t wMaxHeight,
		uint8_t* pabUnblockString );
extern int16_t  BC_GetSCNo( uint8_t* pabSerNo, uint16_t wLength );

// BC_GetPurse Param is a function pointer of type:
// void function( uint8_t bNumber, uint32_t* lPurse,
//   uint16_t wMult, uint16_t wDiv,
//   uint8_t bLocation, uint8_t bSign0,
//   uint8_t bSign1000, uint8_t bCount, uint8_t bLen,
//   uint8_t *abText);
// bNumber gives the number of entries in lPurse-Array
// lPurse is the array of purse-values
// all other parameters see ISC_OrderPin
extern void_t BC_GetPurse( void_t* pvParams );
#ifdef BC_CHAT_INCLUDED
extern uint8_t* BC_ChatName( uint8_t bChatId );
extern void_t BC_StartChat( uint8_t bChatId );
extern void_t BC_ClearChat( void_t );
#endif

#ifdef DOWNLOAD_CHECK
extern int16_t  BC_CheckCertificate( uint8_t* pabImage, uint32_t wLength, uint8_t* pabCert, uint32_t wCertLength );
#endif

#ifdef MULTI_CA_SUPPORT
extern void_t BC_EnableCA( void_t );
extern void_t BC_DisableCA( void_t );
#endif

#ifdef BC_RC_INCLUDED
extern int16_t BC_EncryptMSG( uint8_t* pabMsg, uint16_t wPos, uint16_t wLength, uint8_t bKeyToUse );
extern int16_t BC_DecryptMSG( uint8_t* pabMsg, uint16_t wPos, uint16_t wLength, uint8_t bKeyToUse );
#endif
#ifdef BC_IP_INCLUDED
void_t BC_OpenConnection( uint32_t wIpId );
void_t BC_CloseConnection( uint32_t wIpId );
#endif
#ifdef BC_PVR_INCLUDED
int16_t BC_PVRReplay( uint32_t lEventId, uint8_t bLen, uint8_t* pabData, uint8_t bServiceIdx );
#endif
int16_t BC_CheckPairingState( void_t );

#ifdef BC_DVR_INCLUDED
int16_t BC_DVRRecord( uint8_t bServiceIdx,
                      uint8_t bChannelId,
                      uint8_t* pabInfo,
                      uint16_t wInfoLen,
                      uint8_t * pabActualTime );
int16_t BC_DVRReplay( uint8_t bChannelId,
                    uint8_t* pabInfo,
                    uint16_t wInfoLen,
                    uint8_t* pabStoreInfo,
                    uint16_t wStoreInfoLen,
                    uint8_t * pabActualTime );
int16_t BC_DVRStop( uint8_t bChannelId );
int16_t BC_DVREncrypt( uint8_t bChannelId,
                       uint8_t* pabDest,
                       uint8_t* pabSource,
                       uint32_t lSize,
                       uint8_t* pabStoreInfo,
                       uint16_t* pwStoreInfoLen );
int16_t BC_DVRDecrypt( uint8_t bChannelId,
                       uint8_t* pabDest,
                       uint8_t* pabSource,
                       uint32_t lSize );

#endif

// ***************************************************************************
// ***************** INPUT function to the host software *********************

//// ECM
extern int16_t  FS_SetECMFilter(uint8_t bFilterId, enFilterMode_t, uint16_t wEcmPid,
		uint8_t bTableId, uint8_t bVersion, uint8_t bPage);
extern int16_t  FS_ReadECM(uint8_t bFilterId, uint8_t* pabBuffer, uint16_t* pwLen);
extern int16_t  FS_FlushECM_Buffer(uint8_t bFilterId);

//// EMM
extern int16_t  FS_SetEMMFilter(uint8_t bFilterIndex, uint8_t bAddressLength,
		uint8_t* pabAddress);
extern int16_t  FS_SetEMM_Pid(uint16_t wEmmPid);
extern int16_t  FS_ReadEMM(uint8_t* pabBuffer, uint16_t* pwLen);
extern int16_t  FS_FlushEMM_Buffer(void_t);

//// DESCR
extern int16_t  FS_StartDescrambling(uint16_t wIndex, uint16_t *pawStreamPid, uint8_t bServiceIdx);
extern int16_t  FS_StopDescrambling(uint8_t bServiceIdx);

// --- MMI---
extern int16_t  MMI_SetDescrambling_State(uint16_t wIndex,
		uint16_t* pawStreamPid,
		enDescState_t * paenDescState,
		uint8_t bServiceIdx);
extern int16_t  MMI_SetSmartcard_State(enScState_t);

// --- System calls ---
extern int32_t  SYS_GetTickCount(void_t);
extern int16_t  SYS_ReadNvmBlock(uint8_t* pabDest, uint16_t wLength);
extern int16_t  SYS_WriteNvmBlock(uint8_t* pabSrc, uint16_t wLength);
#ifdef BC_NSC_INCLUDED
extern int16_t  SYS_ReadNvmData(uint8_t bBlockId, uint8_t* pabDest, uint16_t wLength);
extern int16_t  SYS_WriteNvmData(uint8_t bBlockId, uint8_t* pabSrc, uint16_t wLength);
#endif
extern int32_t  SYS_Random(void_t);
extern int16_t  SYS_SetDialogue(uint16_t wDialogLength, uint8_t* pabDialogue);

extern void_t SYS_GetBoxId( uint8_t* pabBoxId );
// --- SC ---
extern int16_t  SC_Write(uint8_t* pabBuffer, uint16_t* pwLen, uint16_t wTimeout);
extern int16_t  SC_Read(uint8_t* pabBuffer, uint16_t* pwLen);
extern int16_t  SC_IOCTL(enCmd_t cmd, void_t* pvParams, uint16_t* pwLen);

// --- OSD ---
// OSD_BuildWindow prepares an OSD of a text message given in bMsg.
// wMode is giving the display-modus of the window. The window is
// not displayed due to a call of this function.
//    wMode&3 gives the y-position of the window reference point
//    (wMode/4)&3 gives the x-position of the window reference point
//    (wMode/16)&3 gives the text-alignment inside the box
//    x- and y-position are defined in the following way:
//       (pos&1) == 1 means centered point
//       (pos&2) == 2 means take right or upper corner as reference
//
// combined values for x- and y-position in decimal
//     2                6/14                10
//      ------------------------------------
//     |                                    |
//     |                                    |
//     |                                    |
//    1/3            5/13/7/15             9/11
//     |                                    |
//     |                                    |
//     |                                    |
//      ------------------------------------
//     0                4/12                8
//
// The upper left corner is (0,0)
//
// text-alignment is defined to be
//    0  left aligned
//    1  right aligned
//    2  centered
//    3  justified
// wX and wY give the coordinates for the corner specified by the wMode
// if (wMode&0x100)=0x100 take width and height given in wW and wH, else
// ignore wW and wH and calculate width and height of the box according
// to the message.
// wBackground selects one of 16 colors for the background
// bAlpha give the alpha-blending value for the textbox
// wForeground selects one of 16 colors for the text
extern void_t   OSD_BuildWindow( uint8_t* pabMsg, int16_t wMode,
		int16_t wX, int16_t wY, int16_t wW, int16_t wH,
		int8_t bBackground, int8_t bAlpha, int8_t bForeground );
//
// OSD_DisplayWindow displays the prepared window for
// wDuration seconds using the bDisplayMode to select the
// removal of the window by the customer
// A duration of 0 means the window is not automatically removed.
// It will be removed/replaced by the next message or depending
// on the displaymode.
// If (bDisplayMode&1)==0 the window can be removed by the customer
// pressing a selected button. Further definitions can be taken form
// the detailed description of the OSM for set-top-box document
extern uint16_t  OSD_DisplayWindow( uint8_t bDisplayMode, uint16_t wDuration );

// --- interactive SC ---
//
// ask for a PIN and send the PIN check using the provided bPinIndex
// to the library using the BC_CheckPin call.
// The textselector is used to select the text displayed for customer
extern void_t   ISC_CheckPin( uint8_t bPinIndex, uint8_t bTextSelector, uint8_t bServiceIdx );
// Textselectors are:
//     0    ... check PIN for parental control
//     1    ... check PIN for Impulse Pay Per View buy
//     3    ... check PIN for parental control non-smartcard pin
//     4    ... check PIN for resuming event
//     5    ... check PIN for selecting event

// ask for a PIN and sent the PIN check using the provided bPinIndex
// to the library using the BC_CheckPin call.
// Use 1 as the textselector.
// Information on the currency to be used and the calculation of the currency
// values out of the given token values is described
//
//    available_credit = lPurse * wMult / wDiv;
//    cost_of_event = lCost * wMult / wDiv;
// bLocation gives to location of the currency description. If bLocation == 0
// the currency is placed at the end of the number, else at the beginning
// bSign0 gives the sign to be used to separate full currency units from parts
// bSign1000 gives the sign to be used to separate 1000 numbers
// bCount gives the number of part digits
// bLen gives the length of the abText string, which gives the currency text
// lEventId gives the event id of the provided event. If the event-id changes,
//          a new input mask should be presented, as the costs may have changed
//
// examples:
//   lPurse = 6000, lCost = 3, wMult = 1, wDiv = 2,
//   bLocation = 1, bSign0 = '.', bSign1000 = ',',
//   bCount = 2, bLen = 1, abText = "$":
//         Credit: $3,000.00  Cost: $1.50
//   lPurse = 6000, lCost = 3, wMult = 2, wDiv = 3,
//   bLocation = 0, bSign0 = ',', bSign1000 = '.',
//   bCount = 2, bLen = 4, abText = " EUR":
//         Credit: 4.000,00 EUR  Cost: 2,00 EUR
extern void_t   ISC_OrderPin( uint8_t bPinIndex, uint32_t lPurse,
		uint32_t lCost, uint16_t wMult, uint16_t wDiv,
		uint8_t bLocation, uint8_t bSign0,
		uint8_t bSign1000, uint8_t bCount, uint8_t bLen,
		uint8_t *abText, uint32_t lEventId, uint8_t bServiceIdx );
#ifdef BC_CHAT_INCLUDED
extern void_t CHT_Display( uint8_t* pabText );
#endif

#ifdef BC_IP_INCLUDED
void_t IP_OpenConnectionByName( uint8_t* pabName, uint16_t wPort );
void_t IP_OpenConnectionByAddress( uint8_t* lAddress, uint16_t wPort );
void_t IP_CloseConnection( uint32_t wIpId );
int16_t IP_Send( uint32_t wIpId, int16_t wLen, uint8_t* pabBuffer );
int16_t IP_Receive( uint32_t wId, int16_t wLen, uint8_t* pabBuffer );
#else
#ifdef BC_RC_INCLUDED
int16_t RC_ReadMSG( uint8_t* pabBuf, uint16_t* pwLen );
int16_t RC_FlushReadMSG_Buffer( void_t );
int16_t RC_WriteMSG( uint8_t* pabBuf, uint16_t wLen );
int16_t RC_FlushWriteMSG_Buffer( void_t );
int16_t RC_Pending( void_t );
int16_t RC_Connect( uint8_t* pabBuf, uint16_t wLen, uint16_t wKeepAliveTO, uint16_t wDisconnectTO );
int16_t RC_Disconnect( void_t );
#endif
#endif
#ifdef BC_PVR_INCLUDED
void_t PVR_Record( uint32_t lEventId,
		uint16_t wONID, uint16_t wSID, uint16_t wSIEventId,
		uint8_t* pabStart, uint8_t* pabStop, uint16_t wDur,
		uint8_t bLen, uint8_t* pabData, uint8_t bServiceIdx );
void_t PVR_Mode( uint32_t lEventId, uint8_t bServiceIdx );
void_t PVR_Start( uint32_t lEventId );
void_t PVR_Remove( uint32_t lEventId );
uint32_t PVR_Date( void_t );
#endif

#ifdef BC_MS_INCLUDED
int16_t MS_SendMasterData( uint16_t wLen, uint8_t* pabData );
int16_t MS_GetMasterData( uint16_t* wLen, uint8_t* pabData );
#endif
#ifdef BC_DVR_INCLUDED
void_t DVR_OK( uint8_t bChannelId, uint8_t bMode );
void_t DVR_UsedKey( uint8_t bChannelId, uint8_t bMode );
#endif
#ifdef BC_CIPLUS
void_t SYS_CIP_OutputControl( uint8_t bServiceIdx, uint8_t *pabCIPDesc, uint8_t bDescLen );
#else
#ifdef BC_COPYCONTROL
void_t SYS_CopyControl( uint8_t bServiceIdx, uint8_t bAnalogProt, uint8_t bCgmsa, uint8_t bHdcp, uint8_t bDownresing, uint8_t bEmiCci );
#endif
#endif

#endif
 // _BCMAIN_H_DEF_
