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
 * @file UniversalClient_IPTV_API.h
 *
 * Cloaked CA Agent IP client API. This file has methods for 
 * passing IP information of client and server that
 * are specific to the IP transport. This API is an extension to
 * the common service processing layer located in UniversalClient_Common_API.h. 
 *
 */
#ifndef UNIVERSALCLIENT_IPTV_API_H__INCLUDED__
#define UNIVERSALCLIENT_IPTV_API_H__INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

#include "UniversalClient_Common_API.h"

/** @defgroup universalclient_api Cloaked CA Agent APIs

 *  Cloaked CA Agent APIs
 *
 *  These API methods provide the necessary interfaces for the Application in client device.
 *
 *  @{
 */

/** @defgroup iptvapi Cloaked CA Agent Pull EMM and IPTV APIs
 *  All APIs related to IP-specific functionality
 *
 * These API methods provide the necessary functionality for submitting the CCIS addresses to Cloaked CA Agent. 
 * 
 * An integration can use these methods to add CA to a device that supports IP client. 
 *
 *
 * See \ref commonapi "Cloaked CA Agent Common APIs" for fundamental methods for managing services and starting
 * and stopping the Cloaked CA Agent.
 *
 * For Cloaked CA Agent for Secure Chipset based STBs: See also \ref basic_emm_pulling "Basic EMM Pulling Flow"
 * for an overview of how the EMM Pulling API is used. 
 * 
  *  @{
 */

/**
 * Submit CCIS addresses.
 *
 * Application can call this function to submit CCIS addresses. ::uc_web_service_type explains the type of CCIS address.
 *
 * For Cloaked CA Agent for Secure Chipset based STBs: The amount of server address that application can submit by one time is currently limited to 1. 
 * The type of CCIS address can be ::UC_PULL_EMM_WEB_SERVICE.
 *
 *  \note For Cloaked CA Agent for Secure Chipset based STBs: This function must be called after the Pull EMM service is opened through invoking ::UniversalClient_OpenService.
 *        Refer to \subpage setup_pullemm_powersondevice, \subpage basic_emm_pulling and \subpage basic_ott.
 *
 * @param[in] serviceHandle Service handle previously opened by a call to ::UniversalClient_OpenService.
 * @param[in] serverAddressCount the number of the CCIS addresses submitted.
 * @param[in] pWebServiceAddress Pointer points to the Structures containing the CCIS address.
 *
 * 
 * @retval 
 *    ::UC_ERROR_SUCCESS
 * @retval 
 *    ::UC_ERROR_OUT_OF_MEMORY
 * @retval
 *    ::UC_ERROR_NULL_PARAM
 * @retval
 *     Other The method may return any other errors listed in \ref result "Result Code List". 
 */    
uc_result UniversalClient_IPTV_SubmitServerAddress(
    uc_service_handle serviceHandle,
    uc_uint8 serverAddressCount,
    const uc_web_service_address *pWebServiceAddress);

/**
 * Trigger the re-try of EMM Pulling or IPTV request.
 *
 * For Cloaked CA Agent for Secure Chipset based STBs: This function will trigger the Cloaked CA Agent to retry the relevant EMM pulling request,
 * for example the Entitlement Request.
 *
 * For Cloaked CA Agent for IP only STBs: This function will trigger the Cloaked CA Agent to retry the relevant IPTV request, 
 * for example the Entitlement Request and Client Registration Request.
 *
 * Application can call this function when the following EMM and ECM error codes received from Cloaked CA Agent,
 * EMM error codes are ::ERR_MSG_E200,::ERR_MSG_E201,::ERR_MSG_E202,::ERR_MSG_E203 and ::ERR_MSG_E205 and ECM error code is ::ERR_MSG_E016.
 *
 * \note For Cloaked CA Agent for Secure Chipset based STBs: Refer to \subpage pull_emm_retry.
 *
 * @retval 
 *    ::UC_ERROR_SUCCESS
 * @retval
 *    ::UC_ERROR_MESSAGE_INVALID
 * @retval
 *    ::UC_ERROR_ALREADY_STOPPED
 * @retval
 *     Other The method may return any other errors listed in \ref result "Result Code List". 
 */    
uc_result UniversalClient_IPTV_RetryRequest(void);


/** @} */ /* End of groups */


/** @} */ /* End of Univeral Client APIs */


#ifdef __cplusplus
}
#endif

#endif /* !UNIVERSALCLIENT_IPTV_API_H__INCLUDED__ */

