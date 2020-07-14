/*
 * Copyright 2009-2016 Irdeto B.V.
 *
 * This file and the information contained herein are the subject of copyright
 * and intellectual property rights under international convention. All rights
 * reserved. No part of this file may be reproduced, stored in a retrieval
 * system or transmitted in any form by any means, electronic, mechanical or
 * optical, in whole or in part, without the prior written permission of Irdeto
 * B.V.
 */

/**
 * @file UniversalClient_Types.h
 *
 * Cloaked CA Agent types.  This file contains common types that are platform specific.
 */
#ifndef UNIVERSALCLIENT_TYPES_H__INCLUDED__
#define UNIVERSALCLIENT_TYPES_H__INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int    uc_uint32;  /**< Unsigned 32-bit integer */
typedef unsigned short  uc_uint16;  /**< Unsigned 16-bit integer */
typedef short           uc_int16;  /**< Signed 16-bit integer */
typedef unsigned char   uc_byte;    /**< Unsigned 8-bit byte */
typedef char *          uc_string;  /**< Null-terminated string */
typedef char            uc_char;    /**< Single character */
typedef int             uc_sint32;  /**< Signed 32-bit integer */
typedef unsigned char   uc_uint8;   /**< Unsigned 8-bit integer */
typedef signed char     uc_int8;    /**< Signed 8-bit integer */

typedef int             uc_intptr;  /**< Signed int of the same size as a pointer */
typedef unsigned int    uc_uintptr; /**< Unsigned int of the same size as a pointer */

/**
 * Invalid handle value.  This is equivalent to a void* with all bits set (i.e., 0xFFFFFFFF)
 */
#define UC_INVALID_HANDLE_VALUE ((uc_uintptr)((uc_intptr)-1))

/**
 * Byte buffer structure
 *
 * This structure is used for passing arbitrary blocks of memory to the Cloaked CA Agent API.
 * 
 * The caller sets the \a bytes member to point to a 
 * buffer, and sets the \a length member to be the length of the buffer.
 * 
 * When used as an output parameter, the function being called will copy data up to
 * the length of the buffer into the memory specified by \a bytes. When used as an
 * input parameter, the function leaves the contents of the buffer alone. 
 */
typedef struct _uc_buffer_st
{
    /**
     * Pointer to a valid region of memory. Depending on the operation, this
     * may be a block of memory to write into or to read from.
     */
    uc_byte *bytes;

    /**
     * Length of the buffer. Depending on the operation, the number of bytes to 
     * read to or write from the \a bytes member.
     */
    uc_uint32 length;
} uc_buffer_st;

/**
* ::uc_bytes now is redefined to ::uc_buffer_st in order to remove the confusion between ::uc_bytes and ::uc_byte.
* The existing integration shall not be affected. 
*/
#define uc_bytes uc_buffer_st

/**
 * simple boolean type.
 */
#define uc_bool int

/**
 * The false value of ::uc_bool
 */
#define UC_FALSE 0

/**
 * The true value of ::uc_bool
 */
#define UC_TRUE 1

/**
 * Maximum transformation TDC size
 */
#define UC_MAX_TRANSFORMATION_TDC_SIZE            416
/**
 * Descrambling key algorithm type
 *
 * This type is part of the ::uc_key_info structure and is passed to ::UniversalClientSPI_Stream_SetDescramblingKey
 * after an ECM arrives on a connected stream and is processed by the client. 
 * It refers to the algorithm that the descrambler should use to descrambler the content using the descrambling key.
 *
 * \note If the scrambling descriptor (tag value = 0x65) is present in the PMT, the stream implementation uses the scrambling
 *       algorithm indicated in the scrambling descriptor; Otherwise, the stream implementation uses the scrambling algorithm
 *       indicated by the Cloaked CA.
 *       Refer to the ETSI EN 300468 for more details about the scrambling descriptor and scrambling mode definition. 
 */
typedef enum
{
    /** 
     * (0) Unknown or proprietary algorithm.
     * 
     * A descrambling key may arrive with this type if a proprietary scrambling solution is being used
     * that the client does not know about. In this case, it is the responsibility of the stream implementation
     * to select what descrambling algorithm to use.
     */
    UC_DK_ALGORITHM_UNKNOWN =0, 

    /**
     * (1) DVB Common Scrambling Algorithm 
     *
     * A descrambling key may arrive with this type when the scrambling solution is known to be
     * DVB-CSA1/2. The stream implementation may use this information as it sees fit. 
     */
    UC_DK_ALGORITHM_DVB_CSA  =1,

    /**
     * (2) Advanced Encryption Standard in Reverse Cipher Block Chaining mode, 128 bit key.
     *
     * A descrambling key may arrive with this type when the scrambling solution is known to be
     * AES-128 RCBC or DVB-CSA3. The stream implementation may use this information as it sees fit.
     */
    UC_DK_ALGORITHM_AES_128_RCBC = 2,

    /**
     * (3) Advanced Encryption Standard in Cipher Block Chaining mode, 128 bit key.
     *
     * A descrambling key may arrive with this type when the scrambling solution is known to be
     * AES-128 CBC or DVB-CISSA. The stream implementation may use this information as it sees fit.
     * For irdeto AES CBC, the IV is {0x49, 0x72, 0x64, 0x65, 0x74, 0x6f, 0xa9, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74}
     * For DVB -CISSA, the IV is { 0x44, 0x56, 0x42, 0x54, 0x4d, 0x43, 0x50, 0x54, 0x41, 0x45, 0x53, 0x43, 0x49, 0x53, 0x53, 0x41}
     */
    UC_DK_ALGORITHM_AES_128_CBC = 3,

    /**
     * (4) Multi-2 Scrambling mode, 64 bit key.
     */
    UC_DK_ALGORITHM_MULTI2 = 4,

    /**
     * (5) DVB-CSA3 in standard mode. 
     */
    UC_DK_ALGORITHM_DVB_CAS3_STANDARD = 5,

    /**
     * (6) DVB-CSA3 in minimally enhanced mode. 
     */
    UC_DK_ALGORITHM_DVB_CAS3_MINENHANCED = 6,
    
    /**
     * (7) DVB-CSA3 in fully enhanced mode. 
     */
    UC_DK_ALGORITHM_DVB_CAS3_FULLENHANCED = 7,

    /**
     * (8) DVB-CISSA . 
     *
     * IV is { 0x44, 0x56, 0x42, 0x54, 0x4d, 0x43, 0x50, 0x54, 0x41, 0x45, 0x53, 0x43, 0x49, 0x53, 0x53, 0x41}
     */
    UC_DK_ALGORITHM_DVB_CISSA = 8,

     /**
     * (0x80) irdeto AES RCBC. 
     */
    UC_DK_ALGORITHM_IRDETO_AES_128_RCBC = 0x80,
    
     /**
     * (0x81) irdeto AES CBC. 
     *
     * IV is {0x49, 0x72, 0x64, 0x65, 0x74, 0x6f, 0xa9, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74}
     */
    UC_DK_ALGORITHM_IRDETO_AES_128_CBC = 0x81

} uc_dk_algorithm;

/**
 * Up to Cloaked CA Agent release 2.2.1, the enum is only used to indicate descrambling key protection mechanism.
 * This type is part of the ::uc_key_info structure and is passed to ::UniversalClientSPI_Stream_SetDescramblingKey,
 * after an ECM arrives on a connected stream and is processed by the client. 
 * It refers to the method used to protect the descrambling key in transit.
 * 
 * After 2.2.1 is released, Cloaked CA Agent expects to support different key ladder providing additional key protection
 * choices, especially the AES algorithm. 
 * So, the enum is not only used in descrambling key protection but also in the protection of CSSK and PVRSK.
 *
 * For CSSK protection, this type is part of the ::uc_cssk_info structure and is passed to ::UniversalClientSPI_Device_SetExtendedCSSK
 * after a Pairing EMM arrives on a connected stream and is processed by the client.
 * The type is also passed to the client through UniversalClient_SetExtendedTestingKey as a part of ::uc_cssk_info structure,
 * when the client is in Testing mode.
 * It refers to the method used to protect the CSSK in transit.
 *
 * For PVRSK protection, this type is part of the ::uc_pvrsk_info structure and is passed to ::UniversalClientSPI_PVR_SetExtendedSessionKey,
 * It refers to the method used to protect the PVRSK in transit.
 *
 * For descrambling key protection, the method of using the enum has not changed
 */
typedef enum
{
    /**
     * (0) Unknown or proprietary protection algorithm
     *
     * Up to Cloaked CA Agent release 2.2.1, this protection type means that the descrambling key is being sent to the 
     * descrambler using a method that the client has no knowledge of.
     * In this case, it is the responsibility of the stream implementation to select which protection
     * algorithm to use.
     *
     * After 2.2.1 was released, this protection type means the key is protected by a unknown algorithm.
     */
    UC_DK_PROTECTION_UNKNOWN =0,

    /**
     * (1) Triple-DES encrypted 
     *
     * Up to Cloaked CA Agent release 2.2.1, this protection type means that the descrambling key is triple-DES encrypted
     * with the hardware or descrambler-specific session key. Descrambling keys are typically delivered with this type 
     * to ensure that they cannot be shared with another instance of a descrambler. 
     * This is intended to protect against a 'control word sharing' attack on the CA system.
     *
     * After 2.2.1 was released, this protection type means key is protected by triple-DES algorithm.
     */
    UC_DK_PROTECTION_TDES =1,

    /**
     * (2) Not encrypted
     *
     * Up to Cloaked CA Agent release 2.2.1, this protection type means that the descrambling key is not encrypted and can be
     * directly used to descramble content. Descrambling keys are delivered with this
     * type when a service is set in \b 911 \b mode or the current client is has a Security ID anchor.
     * \b 911 \b mode is a special mode that a service
     * can be placed in to bypass the regular CA system during emergencies or 
     * other appropriate situations. 
     *
     * After 2.2.1 was released, this protection type means the key is not encrypted.
     */ 
     UC_DK_PROTECTION_CLEAR =2,

    /**
     * (3) AES encrypted
     *
     * The enum value is added after 2.2.1 released, this protection type means key is protected by AES algorithm.
     * This is necessary for the AES key ladder supporting.
     */ 
     UC_DK_PROTECTION_AES =3,

     /**
     * (4) AES encrypted and transformed
     *
     * The enum value is added after 4.8.0 released. This protection type means the key is protected by the AES algorithm and transformed.
     * This is necessary for the AES key ladder when supporting transformation.
     */ 
     UC_DK_PROTECTION_AES_TRANSFORM = 4

} uc_dk_protection;

/**
 * Peer device structure
 *
 * This structure is used to identify a peer device for proximity detection.
 */
typedef struct _uc_proximity_peer
{
    /**
     * indicates the peer ID of the peer device.
     * peer ID is assigned by the application.
     */
    uc_uint32 peerID;

} uc_proximity_peer;

/**
 * Handle to a filter object 
 * 
 * A filter handle is an implementation specific value that is allocated by the implementation
 * of a stream object when the ::UniversalClientSPI_Stream_OpenFilter method is called on a connected stream.
 * While the filter is active, the stream implementation is expected to deliver ECM or EMM sections 
 * that arrive on the stream that match the filter criteria. 
 */
typedef uc_uintptr uc_filter_handle;       

/**
 * Handle to a stream object 
 *
 * A stream handle is an implementation-specific type that is returned from
 * a call to ::UniversalClientSPI_Stream_Open. 
 * A stream object is a logical construct that represents a source of ECMs or EMMs,
 * and a destination for the corresponding descrambling keys. 
 */
typedef uc_uintptr uc_stream_handle;

/**
 * Base structure of component.
 *
 * This is the base structure of a component definition that is 
 * passed to ::UniversalClientSPI_Stream_AddComponent and ::UniversalClientSPI_Stream_RemoveComponent.
 *
 * 'Components' are used to identify recipients of descrambler keys in a later call to ::UniversalClientSPI_Stream_SetDescramblingKey.
 * When this structure is actually used, it will be as part of another structure with additional information,
 * with the 'size' parameter indicating the total size of the larger structure. 
 * 
 * \note Structures based on this structure must not contain pointers to non-static memory, since the structure
 *     is copied and used asynchronously. 
 * 
 * For example:
 * \code
 * // structure that 'inherits' from uc_component
 * typedef struct _uc_mydescrambler_component
 * {
 *   uc_component base;
 *   int extra_field;
 *   int another_field;
 * } uc_mydescrambler_component;
 * \endcode
 *
 */
typedef struct _uc_component
{
    /**
     * size of structure based on uc_component.
     *
     * This is the size, in bytes, of the structure that 'inherits' from this structure.
     * This should be set to (sizeof(uc_component) + additional data).  
     */
    uc_uint32 size;
} uc_component;

/**
 * Filter definition
 *
 * This structure contains the definition of a filter for ECM and EMM sections
 * that are sent to the client for processing. This structure is passed to
 * ::UniversalClientSPI_Stream_OpenFilter to notify a stream implementation of the pattern
 * of sections it should deliver on the connection. 
 *
 * When a section arrives, the driver should match the first filterDepth 
 * bytes of the section against the filter pattern. 
 * The filter pattern is defined as a 'mask', which specifies which bits are relevant
 * for the comparison, and a 'match', which specifies the value the corresponding bits
 * should have in order to have successfully matched the pattern. 
 *
 * Here is some sample code for performing the comparison to illustrate how it is used: 
 *
 * \code
 *
 * uc_filter *pFilter = ...; // filter definition previously passed to ::UniversalClientSPI_Stream_OpenFilter. 
 * uc_byte *pSection = ...; // contents of MPEG-2 section read from hardware
 *
 * uc_bool bMatch = UC_TRUE;
 *
 * for (i=0; bMatch && i<pFilter->filterDepth; ++i)
 * {
 *     if ((pSection[i] & pFilter->mask[i]) != pFilter->match[i])
 *     {
 *         // section does NOT match  
 *         bMatch = UC_FALSE; 
 *     }
 * }
 * 
 * // ... at this point, use bMatch to determine if section should be passed to the 
 * // ::uc_notify_callback function. 
 * \endcode
 *
 * \note Integrators should be aware that filtering is an optional step intended for performance enhancement
 *     of the client and improved battery life for the device. Implementations that do not have access to 
 *     hardware-level filtering can safely ignore filters and pass on all sections received, and the client
 *     will still function correctly. 
 */
typedef struct _uc_filter {
    /**
     * Specifies which bits are important for the pattern match. 
     *
     * This points to a buffer whose length is determined by the \a filterDepth member.
     */
    uc_byte * mask;       

    /**
     * Specifies which bits to compare the masked bits against. 
     *
     * This points to a buffer whose length is determined by the \a filterDepth member.
     */
    uc_byte * match;

    /**
     * Specifies the number of bytes in the \a mask and \a match buffers
     *
     * A filterDepth of 0 means "match all sections". 
     */
    uc_uint32 filterDepth;
} uc_filter;

/**
 * Connection or SPI stream type
 *
 * This type is used to indicate which type stream that will be opened when ::UniversalClientSPI_Stream_Open is called. 
 * The following are the stream types:\n
 * ::UC_CONNECTION_STREAM_TYPE_EMM \n
 * ::UC_CONNECTION_STREAM_TYPE_ECM \n
 * ::UC_CONNECTION_STREAM_TYPE_PVR_RECORD \n
 * ::UC_CONNECTION_STREAM_TYPE_PVR_PLAYBACK \n
 * ::UC_CONNECTION_STREAM_TYPE_FTA \n
 * ::UC_CONNECTION_STREAM_TYPE_IP \n
 * ::UC_CONNECTION_STREAM_TYPE_PD \n
 * ::UC_CONNECTION_STREAM_TYPE_RESERVED 
 */
typedef uc_sint32 uc_connection_stream_type;

/** @defgroup result Result Code List
 *  List of all possible values of ::uc_result codes. 
 *
 *  Except where noted, applications and implementations should 
 *  not expect particular failure codes to always be returned from functions, other than ::UC_ERROR_SUCCESS.
 *  This is because over time and across different implementations the error codes returned from different error situations
 *  may change.
 *  @{
 */
	
/** 
 * Handle to a connection object 
 *
 * A 'connection' is a logical construct that represents the point at which CA
 * functionality is connected to a stream implementation. The connection object
 * interacts with a stream implementation to set filters (::uc_filter_handle) 
 * and receive ECMs and EMMs. After processing ECMs, keys are passed
 * to the stream implementation for descrambling the content. 
 * 
 * A connection handle is passed to an instance of a stream via ::UniversalClientSPI_Stream_Connect. 
 *
 */
typedef uc_uintptr uc_connection_handle;   

/**
 * Notify callback additional information structure
 *
 * This structure is used for passing the additional information to Cloaked CA when the notify callback function is invoked. 
 */
typedef struct _uc_notify_callback_info
{
	/**
	 * Related request ID from ::UniversalClientSPI_Stream_Send method.
	 *
	 * It is used for web service response for Hybrid Client or IP only STBs, when connection stream type is ::UC_CONNECTION_STREAM_TYPE_IP.
	 *
	 * It is useless if ::UniversalClientSPI_Stream_Send method is not invoked.
	 */
	uc_uint32 requestId;

	/**
	 * Pointer to the associate ID buffer
	 *
	 * The associate ID buffer is created and managed by SPI layer. Cloaked CA Agent only passes it through after the ECM is processed, 
	 * and does not manipulate the memory of this pointer.
	 *
	 * See also \ref vod_playback_flow "VOD Playback Flow - Out-Of-Band ECM"
	 *
	 * It is only used by Cloaked CA Agent for Secure Chipset based STBs.
	 */
	void *pAssociateID;

	/**
	 * Indicates a peer device
	 * 
	 * It is used for Proximity Detection, when the connection stream type is ::UC_CONNECTION_STREAM_TYPE_PD.
	 */
	uc_proximity_peer peer;

	/**
	 * Indicates the TTL value in the IP packet.
	 *
	 * It is used for Proximity Detection, when the connection stream type is ::UC_CONNECTION_STREAM_TYPE_PD.
	 * This field must be the same as the TTL field in the IP packet of PD message received from a peer.
	 */
	uc_uint32 ttl;

} uc_notify_callback_info;

/**
 * Function pointer type used to notify the client of new ECM or EMM sections.
 *
 * A function pointer of this type is passed to the implementation of a stream via the ::UniversalClientSPI_Stream_Connect
 * method. The stream implementation is expected to deliver new ECM or EMM sections that match the currently active set
 * of filters (see ::UniversalClientSPI_Stream_OpenFilter) to this function, 
 * after a call to ::UniversalClientSPI_Stream_Start and until a call to ::UniversalClientSPI_Stream_Disconnect occurs. 
 *
 * \note Implementations that receive one section at a time can safely pass the data directly, whereas implementations that receive blocks of sections 
 *	   can also safely pass the data directly without having to parse the sections and break it into individual section.
 *
 * @param[in] connectionHandle The value of the connection handle previously passed to the stream implementation's 
 *	   ::UniversalClientSPI_Stream_Connect method. 
 * @param[in] pSections Containing the MPEG-2 sections to process.
 *	   The uc_buffer_st::bytes member must point to a buffer containing the raw data of 
 *	   the sections, and the uc_buffer_st::length member must be set to the number of bytes
 *	   in the sections.
 */
typedef void (*uc_notify_callback)(
	uc_connection_handle connectionHandle,
	const uc_buffer_st * pSections);

/**
 * Function pointer type used to notify the client of data(ECM sections or web service response or proximity detection message) with additional information. 
 * 
 * A function pointer of this type is passed to the implementation of a stream via the ::UniversalClientSPI_Stream_Extended_Connect 
 * method. The stream implementation is expected to deliver data(ECM sections or web service response or proximity detection message) that match the currently active set 
 * of filters (see ::UniversalClientSPI_Stream_OpenFilter) to this function, 
 * after a call to ::UniversalClientSPI_Stream_Start and until a call to ::UniversalClientSPI_Stream_Disconnect occurs.
 * 
 * \note For ECM sections which are contained in the index files, it is required that all ECM sections in one crypto period 
 * are delivered in one call. For ECM sections which are contained in the transport streams, the ECM sections can be sent 
 * via this interface one by one.
 * 
 * See also \ref vod_playback_flow "VOD Playback Flow - Out-Of-Band ECM"
 *
 * @param[in] connectionHandle The value of the connection handle previously passed to the stream implementation's 
 *     ::UniversalClientSPI_Stream_Connect method. 
 * @param[in] pData Containing data(ECM sections or web service response or proximity detection message) to process.
 *     The uc_buffer_st::bytes member must point to a buffer containing the raw data of 
 *     ECM sections or web service response or proximity detection message, and the uc_buffer_st::length member must be set to the number of bytes
 *     in ECM sections or web service response or proximity detection message.
 * @param[in] pNotifyCallbackInfo Containing the association information and request ID of the delivered pData. For ECM sections delivery, 
 *     the pAssociateID data field of the structure is passed out in the ECM status notification after the ECM sections 
 *     are processed by Cloaked CA Agent. For web service response, the request ID is from ::UniversalClientSPI_Stream_Send method.
 *     For proximity detection message, the peer is used to indicate the peer device that sends the message.
 */
typedef void(* uc_notify_callback_extended)(
    uc_connection_handle connectionHandle, 
    const uc_buffer_st *pData,
    uc_notify_callback_info *pNotifyCallbackInfo);

/**
 * Key info structure
 *
 * This is a structure that is passed to a stream implementation from 
 * a call to ::UniversalClientSPI_Stream_SetDescramblingKey. It contains information about
 * a particular descrambling key. 
 */
typedef struct _uc_key_info
{
    /**
     * The scrambling algorithm that this key will be used for.
     *
     * Typically a descrambler will only support one type of algorithm, so this data
     * is really used for validation purposes in practice. However, it can also be
     * used to select which algorithm to use when multiple algorithms are available.
     */
    uc_dk_algorithm descramblingKeyAlgorithm;

    /**
     * The protection method used to secure this key.
     *
     * For example, this may be used to tie a descrambling key to a unique instance
     * of a descrambler hardware to prevent the key from being useful in another
     * descrambling environment.
     * If descramblingKeyProtection is UC_DK_PROTECTION_CLEAR, whatever the secure chipset mode
     * is, using the pDescramblingKey.
     */ 
    uc_dk_protection descramblingKeyProtection;

    /**
     * The key material of the descrambling key.
     *
     * This contains the raw data of the key. How this key is protected is determined by the 
     * uc_key_info::descramblingKeyProtection member, and how the key will be used by the 
     * descrambler is determined by the uc_key_info::descramblingKeyAlgorithm member.
     * The uc_buffer_st::bytes member points to the raw data of the key, and 
     * the uc_buffer_st::length member is the number of bytes in the key.
     */
    uc_buffer_st *pDescramblingKey;
    
} uc_key_info;

/**
 * Result code enumerator type. 
 */
typedef enum {
    /** (0x00000000) The operation was successful. */
    UC_ERROR_SUCCESS                        = 0x00000000,

    /** (0x00000001) One or more required parameters were NULL. */
    UC_ERROR_NULL_PARAM                     = 0x00000001, 

    /** (0x00000002) Memory could not be allocated. */
    UC_ERROR_OUT_OF_MEMORY                  = 0x00000002, 

    /** (0x00000003) Unable to create requested resource. */
    UC_ERROR_UNABLE_TO_CREATE               = 0x00000003,

    /** (0x00000004) Generic OS failure. */
    UC_ERROR_OS_FAILURE                     = 0x00000004,

    /** (0x00000005) The timeout expired before the object was ready. */
    UC_ERROR_WAIT_ABORTED                   = 0x00000005, 

    /** (0x00000006) The buffer passed in is too small. */
    UC_ERROR_INSUFFICIENT_BUFFER            = 0x00000006, 

    /** (0x00000007) The specified resource could not be found. */
    UC_ERROR_RESOURCE_NOT_FOUND             = 0x00000007,

    /** (0x00000008) The resource name specified is invalid. */
    UC_ERROR_BAD_RESOURCE_NAME              = 0x00000008, 

    /** (0x00000009) The requested feature is not implemented. */
    UC_ERROR_NOT_IMPLEMENTED                = 0x00000009, 

    /** (0x0000000A) A connection is still open; stream cannot be closed. */
    UC_ERROR_CONNECTION_STILL_OPEN          = 0x0000000A, 

    /** (0x0000000B) The handle is not valid. */
    UC_ERROR_INVALID_HANDLE                 = 0x0000000B,

    /** (0x0000000C) The handle is valid but is not the correct type. */
    UC_ERROR_WRONG_HANDLE_TYPE              = 0x0000000C, 

    /** (0x0000000D) Too many handles are opened already. */
    UC_ERROR_TOO_MANY_HANDLES               = 0x0000000D,

    /** (0x0000000E) An attempt to shut down was made while a handle is still open. */
    UC_ERROR_HANDLE_STILL_OPEN              = 0x0000000E,

    /** (0x0000000F) This operation cannot be completed because the Cloaked CA Agent was already started. */
    UC_ERROR_ALREADY_STARTED                = 0x0000000F,

    /** (0x00000010) This operation cannot be completed because the Cloaked CA Agent was already stopped. */
    UC_ERROR_ALREADY_STOPPED                = 0x00000010,

    /** (0x00000011) An internal message queue is full and cannot accept more messages. */
    UC_ERROR_QUEUE_FULL                     = 0x00000011,

    /** (0x00000012) A required implementation of an SPI method is missing. */
    UC_ERROR_MISSING_SPI_METHOD             = 0x00000012,

    /** (0x00000013) The version of the SPI implementation is not compatible with the client. */
    UC_ERROR_INCOMPATIBLE_SPI_VERSION       = 0x00000013,

    /** (0x00000014) An invalid message was received. */
    UC_ERROR_MESSAGE_INVALID                = 0x00000014,

    /** (0x00000015) The specified length was not valid. */
    UC_ERROR_INVALID_LENGTH                 = 0x00000015,

    /** (0x00000016) Some required internal data is missing. */
    UC_ERROR_MISSING_DATA                   = 0x00000016,

    /** (0x00000017) Page is not what we want. */
    UC_ERROR_NOT_WANTED_ECMPAGE             = 0x00000017,

    /** (0x00000018) Generic driver failure or mismatched pipe selection. On the Cloaked CA Agent 4.10.1, this error will be returned by ::UniversalClientSPI_IFCP_Communicate or ::UniversalClientSPI_Stream_SetDescramblingKey when setting key on unexpected pipe*/
    UC_ERROR_DRIVER_FAILURE                 = 0x00000018,

    /** (0x00000019) Not entitled. */
    UC_ERROR_NOT_ENTITLED                   = 0x00000019,

    /** (0x0000001A) Invalid PK. */
    UC_ERROR_INVALID_PK                     = 0x0000001A,

    /** (0x0000001B) Invalid GK. */
    UC_ERROR_INVALID_GK                     = 0x0000001B,

    /** (0x0000001C) Invalid TG. */
    UC_ERROR_INVALID_TG                     = 0x0000001C,

    /** (0x0000001D) Missing CWDK. */
    UC_ERROR_INVALID_CWDK                   = 0x0000001D,

    /** (0x0000001E) No CA regional info. */
    UC_ERROR_NO_CA_REGIONAL_INFO            = 0x0000001E,

    /** (0x0000001F) Regional blocking. */
    UC_ERROR_REGIONAL_BLOCKING              = 0x0000001F,

    /** (0x00000020) Restricted opcode. */
    UC_ERROR_RESTRICTED_OPCODE              = 0x00000020,

    /** (0x00000021) Timestamp filter failed. */
    UC_ERROR_TIMESTAMP_FILTER               = 0x00000021,

    /** (0x00000022) Type filter failed. */
    UC_ERROR_TYPE_FILTER                    = 0x00000022,

    /** (0x00000023) Signature verification failed. */
    UC_ERROR_SIGNATURE_VERIFICATION         = 0x00000023,

    /** (0x00000024) TMS failed. */
    UC_ERROR_TMS_FAILED                     = 0x00000024,

    /** (0x00000025) Not PVR entitled. */
    UC_ERROR_NOT_PVR_ENTITLED               = 0x00000025,

    /** (0x00000026) This operation cannot be completed because PMT is not notified. */
    UC_ERROR_UNABLE_TO_CONFIG_PVR_RECORD    = 0x00000026,

    /** (0x00000027) This operation cannot be completed while a request for PVR record  is still being processed. */
    UC_ERROR_CONFIG_PVR_RECORD_STILL_OPEN   = 0x00000027,

    /** (0x00000028) This operation cannot be completed because PVR MSK is missing. */
    UC_ERROR_MISSING_PVR_MSK                = 0x00000028,

    /** (0x00000029) The recorded content expired */
    UC_ERROR_PVR_CONTENT_EXPIRED            = 0x00000029,

    /** (0x0000002A) Failed to generate PVR session key */
    UC_ERROR_FAILED_TO_GENERATE_SESSION_KEY = 0x0000002A,

    /** (0x0000002B) The PVR metadata is invalid */
    UC_ERROR_INVALID_PVR_METADATA          = 0x0000002B,

    /** (0x0000002C) The client type is wrong, a feature only supports a certain client type
    (For example, PVR works only on clients with secure chipset). 
    */
    UC_ERROR_CLIENT_TYPE_ERROR              = 0x0000002C,   

    /** (0x0000002D) Invalid sector. */
    UC_ERROR_INVALID_SECTOR                 = 0x0000002D,
    
    /** (0x0000002E) Client type error, PPV VOD feature should base on Secure Chipset mode. */
    UC_ERROR_VOD_CLIENT_TYPE_ERROR          = 0x0000002E,
    
    /** (0x0000002F) No serial number. */
    UC_ERROR_VOD_NO_SERIAL_NUMBER           = 0x0000002F,
    
    /** (0x00000030) Invalid nonce. */
    UC_ERROR_VOD_INVALID_NONCE              = 0x00000030,

    /** (0x00000031) Pkey Hash mismatch */
    UC_ERROR_PKEY_HASH_MISMATCH             = 0x00000031,

    /** (0x00000032) The variant of the device identifiers is not compatible with the client. */
    UC_ERROR_INCOMPATIBLE_VARIANT           = 0x00000032,

    /** (0x00000033) No Nationality. */
    UC_ERROR_NO_NATIONALITY                 = 0x00000033,

    /** (0x00000034) The uniqueaddress is invalid with the client. */
    UC_ERROR_INVALID_UNIQUE_ADDRESS         = 0x00000034,

    /** (0x00000035) This result code is not used now. */
    UC_ERROR_DIGITAL_COPY_NOMORE            = 0x00000035,
    
    /** (0x00000036) Black out. */
    UC_ERROR_BLACK_OUT                      = 0x00000036,

    /** (0x00000037) Homing Channel Failed. */
    UC_ERROR_HOMING_CHANNEL_FAILED          = 0x00000037,

    /** (0x00000038) FlexiFlash Failed. */
    UC_ERROR_FLEXIFLASH_FAILED          = 0x00000038,

    /** (0x00000039) Middleware User Data Failed */
    UC_ERROR_MIDDLEWARE_USER_DATA_FAILED      = 0x00000039,

    /** (0x0000003A) Pre-Enable product expired */
    UC_ERROR_PRE_ENABLE_PRODUCT_EXPIRED     = 0x0000003A,

    /** (0x0000003B) Missing Pre-Enable Session Key */
    UC_ERROR_MISSING_PESK           = 0x0000003B,

    /** (0x0000003C) The OTP data is invalid */
    UC_ERROR_INVALID_OTP_DATA           = 0x0000003C,

    /** (0x0000003D) The personalized data is invalid */
    UC_ERROR_INVALID_PERSONALIZED_DATA           = 0x0000003D,
    
    /** (0x0000003E) New CG for FSU product received */
    UC_ERROR_NEW_CG_FOR_FSU_RECEIVED           = 0x0000003E,

    /** (0x0000003F) New CG for Push VOD product received */
    UC_ERROR_NEW_CG_FOR_PUSHVOD_RECEIVED           = 0x0000003F,

    /** (0x00000040) CG Mismatch */
    UC_ERROR_CG_MISMATCH           = 0x00000040,

    /** (0x00000041) SG Mismatch */
    UC_ERROR_SG_MISMATCH           = 0x00000041,

    /** (0x00000042) Invalid PK Index */
    UC_ERROR_INVALID_PK_INDEX           = 0x00000042,

    /** (0x00000043) Invalid GK Index */
    UC_ERROR_INVALID_GK_INDEX           = 0x00000043,
    
    /** (0x00000044) Macrovision Failed. */
    UC_ERROR_MACROVISION_FAILED           = 0x00000044,

    /** (0x00000045) SN RANGE Failed. */
    UC_ERROR_SN_RANGE_FAILED           = 0x00000045,

    /** (0x00000046) Unified Client Error. */
    UC_ERROR_CONVERGENT_CLIENT_GENERIC_ERROR      = 0x00000046,

    /** (0x00000047) Smart Card is out. */
    UC_ERROR_SMARTCARD_OUT      = 0x00000047,

    /** (0x00000048) Unknown Card (non-Irdeto), or the smart card is upside down. */
    UC_ERROR_SMARTCARD_UNKNOWN    = 0x00000048,

    /** (0x00000049) Card Error, communications with Smart Card have failed. */
    UC_ERROR_SMARTCARD_ERROR      = 0x00000049,

    /** (0x0000004A) Corrupted Data, the data is corrupted */
    UC_ERROR_IO_DATA_CORRUPTED      = 0x0000004A,    

    /** (0x0000004B) Invalid change verion. */
    UC_ERROR_INVALID_CHANGE_VERSION      = 0x0000004B,

    /** (0x0000004C) This Block has been downloaded. */
    UC_ERROR_FLEXIFLASH_BLOCK_DOWNLOAD_DUPLICATION      = 0x0000004C,

    /** (0x0000004D) The Global SC EMM has been processed by Client. */
    UC_ERROR_GLOBAL_SC_EMM_DUPLICATION      = 0x0000004D,

    /** (0x0000004E) Stop EMM processing. */
    UC_ERROR_STOP_EMM_PROCESSING      = 0x0000004E,
    
    /** (0x0000004F) Load Cloaked CA package failed. */
    UC_ERROR_LOAD_CCAPACKAGE_FAILED      = 0x0000004F,

    /** (0x00000050) Invalid CFG data. */
    UC_ERROR_INVALID_CFG_DATA      = 0x00000050, 

    /** (0x00000051) Package data is invalid. */
    UC_ERROR_INVALID_PACKAGE_DATA      = 0x00000051,

    /** (0x00000052) The VM failed. */
    UC_ERROR_VM_FAILURE      = 0x00000052,  
    
    /** (0x00000053) The securecore is not loaded. */
    UC_ERROR_SECURECORE_NOT_LOADED      = 0x00000053,

    /** (0x00000054) Invalid area index. */
    UC_ERROR_INVALID_AREA_INDEX      = 0x00000054,

    /** (0x00000055) An character is not expected when parse a CFG file */
    UC_ERROR_UNEXPECTED_CHARACTER = 0x00000055,

    /** (0x00000056) Get section Data without parse a CFG file. */
    UC_ERROR_NO_CFG_PARSED = 0x00000056,

    /** (0x00000057) Parsing a CFG file before release the former parsing result. */
    UC_ERROR_CFG_PARSED_ALREADY = 0x00000057,

    /** (0x00000058) No specified section found in the CFG file. */
    UC_ERROR_SECTION_NOT_FOUND = 0x00000058,

    /** (0x00000059) The VM with special id has already defined. */
    UC_ERROR_VM_ALREADY_DEFINED = 0x00000059,

    /** (0x0000005A) Error happen during create the "vm config" object. */
    UC_ERROR_VM_CREATE_VMCONFIG = 0x0000005A,

    /** (0x0000005B) Error happen during create the vm instance. */
    UC_ERROR_VM_CREATE = 0x0000005B,

    /** (0x0000005C) Too many vm created, vm number reach top limit. */
    UC_ERROR_VM_TOP_LIMIT =  0x0000005C,

    /** (0x0000005D) Error ocurr during loading bytecode image to vm. */
    UC_ERROR_VM_LOAD_IMAGE = 0x0000005D,

    /** (0x0000005E) Error ocurr during memory map from native memory space to vm memory space. */
    UC_ERROR_VM_MEMMAP = 0x0000005E,

    /** (0x0000005F) Error ocurr during execute vm. */
    UC_ERROR_VM_EXECUTE = 0x0000005F,

    /** (0x00000060) Error ocurr VM IO. */
    UC_ERROR_VM_IO = 0x00000060,

    /** (0x00000061) Error ocurr VM RESET. */
    UC_ERROR_VM_RESET = 0x00000061,

    /** (0x00000062) The root key hash check failed. */
    UC_ERROR_ROOT_KEY_HASH_CHECK_FAILED = 0x00000062,

    /** (0x00000063) Unsupported package compress algorithm. */
    UC_ERROR_COMPRESS_ALGORITHM_NOT_SUPPORT = 0x00000063,
    
    /** (0x00000064) The SYS ID is invalid. */
    UC_ERROR_INVALID_SYS_ID = 0x00000064,

    /** (0x00000065) The version of the client is too low to support Cloaked CA package download. */
    UC_ERROR_LOW_CLIENT_VERSION = 0x00000065,

    /** (0x00000066) The CA System ID is invalid */
    UC_ERROR_INVALID_CA_SYSTEM_ID = 0x00000066,

    /** (0x00000067) Anchor Failed(illegal device). */
    UC_ERROR_DEVICE_INVALID                 = 0x00000067,

    /** (0x00000068) Request entitlementkeys failed. */
    UC_ERROR_REQUEST_ENTITLEMENT_FAILED     = 0x00000068,

    /** (0x00000069) No response for request for a certain time interval. */
    UC_ERROR_REQUEST_ENTITLEMENT_RESPONSE_TIME_OUT   = 0x00000069,

    /** (0x0000006A) CCIS internal error. */
    UC_ERROR_CCIS_INTERNAL_ERROR            = 0x0000006A,

    /** (0x0000006B) Anchor failed (DeviceID/UA mismatch: for IP only STBs, the application should register again). */
    UC_ERROR_DEVICEID_UA_MISMATCH           = 0x0000006B,

    /** (0x0000006C) VOD not entitled. */
    UC_ERROR_VOD_NOT_ENTITLED               = 0x0000006C,

    /** (0x0000006D) Missing Secure PVR CPSK. */
    UC_ERROR_MISSING_CPSK               = 0x0000006D,

    /** (0x0000006E) Asset ID mismatch. */
    UC_ERROR_ASSET_ID_MISMATCH = 0x0000006E,

    /** (x00000006F) PVR Recording is prohibited due to copy control setting */
    UC_ERROR_PVR_COPY_CONTROL_PROHIBITED = 0x0000006F,


    /** (x000000070) PVR sharing is prohibited due to is shareable setting */
    UC_ERROR_HN_PVR_NOT_SHAREABLE = 0x00000070,

    /** (x000000071) PVR sharing is prohibited due to domain id mismatch */
    UC_ERROR_HN_PVR_NOT_IN_DOMAIN = 0x00000071,

    /** (0x00000072) Fail to process Shared PVRMSK EMM. */
    UC_ERROR_SHARED_PVRMSK_PROCESS_FAIL = 0x00000072,

    /** (0x00000073) White Box Algorithm is invalid. */
    UC_ERROR_INVALID_WB_ALGORITHM = 0x00000073,

    /** (0x00000074) White Box Algorithm is invalid for Pairing EMM. */
    UC_ERROR_INVALID_WB_ALGORITHM_FOR_PAIRING_EMM = 0x00000074,

    /** (0x00000075) White Box Algorithm is invalid for Product Overwrite EMM. */
    UC_ERROR_INVALID_WB_ALGORITHM_FOR_PO_EMM = 0x00000075,

    /** (0x00000076) White Box Algorithm is invalid for Advertisement EMM. */
    UC_ERROR_INVALID_WB_ALGORITHM_FOR_AD_EMM = 0x00000076,

    /** (0x00000077) The chip configuration check is not supported. */
    UC_ERROR_CCC_NOT_SUPPORT = 0x00000077,

    /** (0x00000078) Client registry Failed. */
    UC_ERROR_INITIALIZATION_FAILED = 0x00000078,

    /** (0x00000079) no response for request for a certain time interval. */
    UC_ERROR_CLIENT_REGISTRATION_RESPONSE_TIME_OUT = 0x00000079,

    /** (0x0000007A) PIN CODE Limitation Failed. */
    UC_ERROR_PIN_CODE_LIMIT_FAILED = 0x0000007A,

    /** (0x0000007B) Cannot find the current CG's secret private data. */
    UC_ERROR_CG_PRIVATE_DATA_NOT_PAIRING = 0x0000007B,

    /** (0x0000007C) Proximity Detection is disabled by the Head-end. */
    UC_ERROR_PROXIMITY_DETECTION_DISABLED = 0x0000007C,

    /** (0x0000007D) The data provided to be encrypted/decrypted is invalid. */
    UC_ERROR_PROXIMITY_INVALID_DATA = 0x0000007D,

    /** (0x0000007E) The peer ID does not represent a valid peer or session.  */
    UC_ERROR_PROXIMITY_PEER_UNKNOWN = 0x0000007E,

    /** (0x0000007F) The key being used to encrypt/decrypt data is not ready.  */
    UC_ERROR_PROXIMITY_KEY_NOT_READY = 0x0000007F,

    /** (0x00000080) The proximity service is not configured yet.  */
    UC_ERROR_PROXIMITY_SERVICE_NOT_CONFIGURED = 0x00000080,

    /** (0x00000081) The PVR key ladder level in Pairing EMM does not match with that in secure chipset. */
    UC_ERROR_PVR_KEY_LADDER_LEVEL_NOT_MATCH = 0x00000081,

    /** (0x00000082) Pairing EMM is rejected as the secure chipset does not support IFCP mode. */
    UC_ERROR_PAIRING_EMM_REJECTED_IFCP_NOT_SUPPORTED = 0x00000082,

    /** (0x00000083) The IFCP RAM image is not loaded to the secure chipset successfully. */
    UC_ERROR_IFCP_IMAGE_NOT_LOADED      = 0x00000083,

    /** (0x00000084) SKE failed (This is not used on Cloaked CA Agent 4.2.0). */
    UC_ERROR_SKE_FAILED = 0x00000084,

    /** (0x00000085) The Secure Pre-enablement feature is not supported in IFCP. */
    UC_ERROR_PE_NOT_SUPPORTED      = 0x00000085,

    /** (0x00000086) The arbitrary value does not match feature bitmap set.*/
    UC_ERROR_IFCP_INVALID_ARBITRARY_LENGTH      = 0x00000086,

    /** (0x00000087) The arbitrary value check failed in IFCP.*/
    UC_ERROR_IFCP_AUTHENTICATION_FAILED      = 0x00000087, 

    /** (0x00000088) ECM is rejected as the secure chipset does not support IFCP mode. */
    UC_ERROR_ECM_REJECTED_IFCP_NOT_SUPPORTED = 0x00000088,

    /** (0x00000089) Unknown App Response from IFCP. */
    UC_ERROR_IFCP_UNKNOWN_APP_RESPONSE = 0x00000089,
    
    /** (0x0000008A) Fail when compute HASH value. */
    UC_ERROR_HASH_COMPUTE = 0x0000008A,
    
    /** (0x0000008B) Signal Announcement EMM is rejected as the FSU stream has been received successfully. */
    UC_ERROR_SIGNAL_ANNOUNCEMENT_EMM_NOT_NEEDED = 0x0000008B,

    /** (0x0000008C) Field Trial ECM is rejected as FSU stream receiving failed. */
    UC_ERROR_ECM_REJECTED_FSU_STREAM_FAILED = 0x0000008C,

    /** (0x0000008D) FSU stream was not successfully received. */
    UC_ERROR_FSU_STREAM_FAILED = 0x0000008D,

    /** (0x0000008E) The FSU stream CA System ID was not found in CAT. */
    UC_ERROR_MISSING_FSU_STREAM_PID_IN_CAT = 0x0000008E,

    /** (0x0000008F) The CAT was not notified to Cloaked CA Agent for FSU. */
    UC_ERROR_NO_CAT_NOTIFIED_FOR_FSU = 0x0000008F,

    /** (0x00000090) Not enough heap memory to load the new secure core package during FSU. */
    UC_ERROR_NO_ENOUGH_MEMORY_TO_LOAD_NEW_SECURE_CORE_DURING_FSU = 0x00000090,

    /** (0x00000091) The operation cannot be cancelled by user. */
    UC_ERROR_OPERATION_CANNOT_BE_CANCELED = 0x00000091,    

    /** (0x00000092) This operation cannot be completed because PVR MSK and CPSK are missing. */
    UC_ERROR_MISSING_PVR_MSK_CPSK = 0x00000092,

    /** (0x00000093) Invalid HGPC timestamp */
    UC_ERROR_HGPC_INVALID_TIMESTAMP = 0x00000093,

    /** (0x00000094) Invalid HGPC secure client */
    UC_ERROR_HGPC_INVALID_CLIENT = 0x00000094,

    /** (0x00000095) HGPC HNA message timeout */
    UC_ERROR_HGPC_HNA_MSG_TIMEOUT = 0x00000095,

    /** (0x00000096) TT not support in MSR mode */
    UC_ERROR_TT_NOT_SUPPORT_FOR_MSR = 0x00000096,

    /** (0x00000097) TT application data version mismatch */
    UC_ERROR_TT_APP_DATA_VERSION_MISMATCH = 0x00000097,

    /** (0x00000098) Traitor Tracing feature is not supported in IFCP */
    UC_ERROR_TT_NOT_SUPPORT_IN_IFCP = 0x00000098,

    /** (0x00000099) Incorrect number of CWs in the Traitor Tracing application data */
    UC_ERROR_TT_INCORRECT_CW_NUMBER = 0x00000099,

    /** (0x0000009A) Transformation IFCP TDC load failed */
    UC_ERROR_IFCP_TDC_LOAD_FAILED = 0x0000009A,

    /** (0x0000009B) Transformation IFCP TDC load unfinished */
    UC_ERROR_IFCP_TDC_LOAD_UNFINISHED = 0x0000009B,

    /** (0x0000009C) The secure core does not match the transformation mode */
    UC_ERROR_SCOT_SECURECORE_NOT_MATCHED = 0x0000009C,

    /** (0x0000009D) Either the TDC SPI was not implemented or an error occurred when Cloaked CA loaded TDC via this SPI */
    UC_ERROR_SCOT_TDC_NOT_LOAD = 0x0000009D,

    /** (0x0000009E)  the AD mode in the pairing EMM mismatches what is in the ECM */
    UC_ERROR_IFCP_AD_MODE_MISMATCH = 0x0000009E,

    /** (0x000000A0) General IFCP Auth Ctrl Error, indicates that an unexpected Auth Ctrl value was received */
    UC_ERROR_IFCP_AUTH_CTRL_ERR = 0x000000A0,

    /** (0x000000A1) SMP General CUR Failure from IFCP, may include Display and Record Errors */
    UC_ERROR_SMP_CUR_NOT_MEET = 0x000000A1,

    /** (0x000000A2) There is a Gereral App Response issue in IFCP, can be a CUR mismatch or Auth Ctrl check */
    UC_ERROR_SMP_APP_RESPONSE_FAILURE = 0x000000A2,

    /** (0x000000A3) SMP is not supported in MSR mode */
    UC_ERROR_SMP_NOT_SUPPORTED_FOR_MSR = 0x000000A3,
    
    /** (0x000000A4) SCOT is not supported on the platform */
    UC_ERROR_SCOT_NOT_SUPPORTED_BY_CHIPSET = 0x000000A4

} uc_result;

/**
 * 
 * PVRSK Key info structure 
 * 
 * The structure is added after release 2.2.1.
 * The introduction of this structure provides support for different key ladders (AES key ladder, TDES key ladder).
 * It contains information about the method to protect the PVRSK. 
 * The structure is passed to ::UniversalClientSPI_PVR_SetExtendedSessionKey, and indicates the PVRSK protection method.
 */
typedef struct _uc_pvrsk_info
{
    /**
     * The protection method used to secure PVRSK.
     */
    uc_dk_protection KeyProtection;

    /**
     * The key material of the PVRSK.
     */ 
    uc_buffer_st *pPVRSK;

    /**
     * The recommended algorithm used to encrypt the recorded content.
     * If the content was recorded using different algorithms, the device application 
     * must make sure the content can be decoded correctly especially for older recorded
     * content without PVR key ladder support.
     */
    uc_dk_algorithm algorithm;

} uc_pvrsk_info;

/**
 * Indicates the type of key ladder.
 *
 * This type is used by ::uc_cssk_info to indicate the destination key ladder that CSSK should be set to. 
 */
typedef enum _uc_dk_ladder
{
    /**
     * The CW key ladder.
     */
    UC_DK_LADDER_CW = 0,
    /**
     * The PVR key ladder
     */
    UC_DK_LADDER_PVR = 1,
    /**
     * The PVR key ladder level 2
     * This is used only when a 3 level key ladder is used. The first level key ladder is identified by UC_DK_LADDER_PVR.
     * \note For a 3 level PVR key ladder, two session keys will be set to the device separately using UC_DK_LADDER_PVR and UC_DK_LADDER_PVR_L2.
     */
    UC_DK_LADDER_PVR_L2 = 2
    
} uc_dk_ladder;


/** @} */ /* End of results */

/**
 * 
 * CSSK Key info structure 
 * 
 * The structure was added after release 2.2.1.
 * The introduction of this structure provides support for different key ladders (AES key ladder, TDES key ladder; CW key ladder, PVR key ladder).
 * It contains: 1, Information about the method to protect CSSK; 2, Destination where CSSK should be set to.
 * The structure is used in these place:
 * 1, Pased to ::UniversalClientSPI_Device_SetExtendedCSSK.
 * 2, When client is in testing mode, pased to client through API ::UniversalClient_SetExtendedTestingKey.
 */
typedef struct _uc_cssk_info
{
    /**
     * Indicates whether the stream handle is valid
     */
     uc_bool    isStreamHandleValid;

    /**
     * The stream handle associated with this session (descrambing, PVR and etc). 
     */
    uc_stream_handle streamHandle;

    /**
     * The protection method used to secure the CSSK.
     */ 
    uc_dk_protection KeyProtection;

    /**
     * The destination key ladder associated with the following CSSK.
     */
    uc_dk_ladder keyLadder;

    /**
     * The key material of the CSSK
     */ 
    uc_buffer_st *pCSSK;
    
} uc_cssk_info;

#ifdef __cplusplus
}
#endif

#endif /* !UNIVERSALCLIENT_TYPES_H__INCLUDED__ */
