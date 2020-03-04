#ifndef _AM_CAS_H_
#define _AM_CAS_H_

#ifndef ANDROID
#define CA_DEBUG(_level,_fmt...) \
        do { \
        if ((_level)<=(CA_DEBUG_LEVEL))\
        {\
                fprintf(stderr, "CA_DEBUG:");\
                fprintf(stderr, _fmt);\
                fprintf(stderr, "\n");\
        }\
        } while(0)
#else
#include <android/log.h>
#define CA_DEBUG(_level,_fmt...) \
        do { \
        if ((_level)<= (CA_DEBUG_LEVEL))\
        {\
                log_print(_fmt);\
        }\
        } while(0)
#endif

#define UNUSED(x) (x=x)
#define CAS_ASSERT(expression)    if (!expression) { \
                                        CA_DEBUG(2, "Null poiter. Line %d\n", __LINE__); \
                                        return AM_ERROR_GENERAL_ERORR; \
                                  }
#define MAX_CHAN_COUNT (8)
#define MAX_DATA_LEN (8)
#define MAX_STOREINFO_LEN (1024)

typedef unsigned int uint32_t;
typedef unsigned short int uint16_t;
typedef unsigned char uint8_t;

/**\brief Service Mode of the program*/
typedef enum {
	SERVICE_DVB,
	SERVICE_IPTV
}CA_SERVICE_MODE_t;

/**\brief Service type of the program*/
typedef enum {
	SERVICE_PLAY,
	SERVICE_DVR
}CA_SERVICE_TYPE_t;

/**\brief Service descrambling information*/
typedef struct {
	uint16_t service_id;
	uint8_t dsc_dev;
	uint8_t dvr_dev;
	CA_SERVICE_MODE_t service_mode;
	CA_SERVICE_TYPE_t service_type;
	uint16_t ecm_pid;
	uint16_t stream_pids[MAX_CHAN_COUNT];
	uint32_t stream_num;
	uint8_t ca_private_data[MAX_DATA_LEN];
	uint8_t ca_private_data_len;
}AM_CA_ServiceInfo_t;

/**\brief CAS private information*/
typedef struct {
	uint8_t info[16];
	uint16_t infoLen;
	void *reserved;
}AM_CA_PrivateInfo_t;

/**\brief CAS dvr information*/
typedef struct {
	uint8_t storeInfo[MAX_STOREINFO_LEN];
	uint32_t actualStoreInfoLen;
}AM_CA_StoreInfo_t;

/**\brief CAS crypto parameters*/
typedef struct {
	uint8_t *buf_in;
	uint8_t *buf_out;
	uint32_t buf_len;
	uint32_t buf_type;
}AM_CA_CryptoPara_t;

/**\brief Error code of the CAS-Hal module*/
typedef enum {
	AM_ERROR_SUCCESS,
	AM_ERROR_NOT_LOAD,
	AM_ERROR_NOT_SUPPORTED,
	AM_ERROR_OVERFLOW,
	AM_ERROR_GENERAL_ERORR
}AM_RESULT;

typedef size_t CasHandle;
typedef size_t CasSession;

/**\brief Wether the specified system id is supported
 * \param CA_system_id
 * \param[in] CA_system_id The system id of the CA system
 * \retval AM_TRUE or AM_FALSE
 * \return Error code
 */
uint8_t AM_CA_IsSystemIdSupported(int CA_system_id);

/**\brief Instantiate a CA system of the specified system id
 * \param CA_system_id handle
 * \param[in] CA_system_id The system id of the CA system
 * \param[out] handle Return the handle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Init(int CA_system_id, CasHandle* handle);

/**\brief Terminate a CA system
 * \param handle
 * \param[in] handle The CasHandle of specified CA system
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_Term(CasHandle handle);

/**\brief Open a session to descramble one or more streams scrambled by the CAS
 * \param handle session
 * \param[in] handle The handle of specified CA system
 * \param[out] session The newly opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_OpenSession(CasHandle handle, CasSession* session);

/**\brief Close the opened descrambling session
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_CloseSession(CasSession session);

/**\brief Start descrambling for the specified session of the CA system
 * \param session serviceInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The descrambling parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StartDescrambling(CasSession session, AM_CA_ServiceInfo_t * serviceInfo);

/**\brief Stop descrambling for the specified session of the CA system
 * \param session
 * \param [in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_StopDescrambling(CasSession session);

/**\brief Update the descrambling pid
 * \param session The opened session
 * \param[in] oldStreamPid The stream pid already set.
 * \param[in] newStreamPid The stream pid to be set.
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_UpdateDescramblingPid(CasSession session, uint16_t oldStreamPid, uint16_t newStreamPid);

/**\brief Set EMM Pid for the specified CA system
 * \param handle emmPid
 * \param[in] handle The handle of initialized CA system
 * \param[in] emmPid The emmPid of current ts
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_SetEmmPid(CasHandle handle, uint16_t emmPid);

/**\brief Start DVR for the specified session of the CA system
 * \param session serviceInfo privateInfo
 * \param[in] session The opened session
 * \param[in] serviceInfo The service information for recording
 * \param[out] privateInfo The private data for extended use
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStart(CasSession session, AM_CA_ServiceInfo_t *serviceInfo, AM_CA_PrivateInfo_t *privateInfo);

/**\brief Stop DVR for the specified session of the CA system
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStop(CasSession session);

/**\brief Encrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param session cryptoPara storeInfo
 * \param[in] session The opened session
 * \param[in] cryptoPara The encrypt parameters
 * \param[out] storeInfo The returned decrypto key information
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVREncrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara, AM_CA_StoreInfo_t *storeInfo);

/**\brief Decrypt a buffer described by a AM_CA_CryptoPara_t struct
 * \param session cryptoPara
 * \param[in] session The opened session
 * \param[in] cryptoPara The decrypt parameters
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRDecrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara);

/**\brief Play recorded streams
 * \param session storeInfo privateInfo
 * \param[in] session The opened session
 * \param[in] storeInfo The decrypto key information
 * \param[in] privateInfo The private data for extended use
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRReplay(CasSession session, AM_CA_StoreInfo_t *storeInfo, AM_CA_PrivateInfo_t *privateInfo);

/**\brief Stop DVR replay
 * \param session
 * \param[in] session The opened session
 * \retval AM_SUCCESS On success
 * \return Error code
 */
AM_RESULT AM_CA_DVRStopReplay(CasSession session);
#endif
