#ifndef DESC_CLIENTAPI_H
#define DESC_CLIENTAPI_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KEY_TYPE_EVEN,
    KEY_TYPE_ODD,
    KEY_TYPE_EVEN_IV,
    KEY_TYPE_ODD_IV
} key_type_t;

typedef enum {
    DSC_ALGO_CSA2,
    DSC_ALGO_CSA3,
    DSC_ALGO_AES,
    DSC_ALGO_INVALID
} desc_algo_t;

typedef enum {
    KL_ALGO_TDES = 0,
    KL_ALGO_AES
} kl_algo_t;;

typedef enum {
    USER_M2M,
    USER_TSN,
    USER_TSD,
    USER_TSE
} kt_user_t;

typedef struct {
    uint8_t ecw[16];
    uint8_t ek1[16];
    uint8_t ek2[16];
    uint8_t ek3[16];
    uint8_t ek4[16];
    uint8_t ek5[16];
    uint8_t size;

    uint8_t module_id;
    uint8_t ladder_size;
    kl_algo_t kl_algo;
    uint32_t kte;
    desc_algo_t kt_algo;
    kt_user_t user_id;
} kl_run_conf_t;

/**\brief Init Secure DESC client
 * \retval 0 On Success
 * \return Error code.
 */
int DESC_Init(void);

/**\brief Deinit Secure DESC client
 * \retval 0 On Success
 * \return Error code.
 */
int DESC_Deinit(void);

/**\brief Allocate key for dvb descrambler
 * \param[in] type The key type
 * \param[out] kte The allocated keytable entry
 * \retval 0 On Success
 * \return Error code.
 */
int DESC_AllocateKey(key_type_t type, uint32_t *kte);

/**\brief Set clear key for kte
 * \param[in] kte The keytable entry
 * \param[in] key The clear key
 * \param[in] algo The descrambling algo
 * \param[in] uid The keytable user id
 * \param[in] size The clear key length
 * \retval 0 On Success
 * \return Error code.
 */
int DESC_SetClearKey(uint32_t kte, uint8_t *key,
                desc_algo_t algo, kt_user_t uid, uint32_t size);

/**\brief Free key
 * \param[in] kte The keytable entry
 * \retval 0 On Success
 * \return Error code.
 */
int DESC_FreeKey(uint32_t kte);

/**\brief Run Keyladder
 * \param[in] kl_conf The keyladder param
 * \retval 0 On Success
 * \return Error code.
 */
int DESC_Keyladder_Run(kl_run_conf_t *kl_conf);

#ifdef __cplusplus
}
#endif
#endif /* DESC_CLIENTAPI_H */
