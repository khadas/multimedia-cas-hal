/*
 * Copyright (C) 2015 Amlogic, Inc.
 *
 *
 */
#ifndef CACLIENTAPI_H
#define CACLIENTAPI_H

#include <stdint.h>
#include "cacrypto.h"

#define CR_LEN 16
#define KEY_LEN 16
#define MAX_DESC_COUNT 8
#define MAX_DESC_DEV_NO 2

/**
 * Initialize CA Client
 *
 * Not necessary to call manually.
 *
 * Returns 0 on success
 */
int32_t CA_init(void);

/**
 * Uninitialize CA Client
 *
 * Returns 0 on success
 */
int32_t CA_uninit(void);

/**
 * Read Chip ID
 *
 * id:  8 byte buffer to receive chip id
 * Returns 0 on success
 */
int32_t CA_GetChipID(uint8_t id[8]);

/**
 * Read Chip ID +
 *
 * id:  16 byte buffer to receive chip id +
 * Returns 0 on success
 */
int32_t CA_GetChipIDExt(uint8_t id[16]);

/**
 * Read some areas of efuse
 *
 * Returns 0 on success
 */
int32_t CA_ReadEfuse(void *data, unsigned int offset, unsigned int len);

/**
 * Setup Keyladder
 *
 * vendor_id:         pointer to vendor id.  Should be 2 bytes in length.
 * with_module_id:    0 or 1.  Whether to derive different root keys by adding a module id.
 * module_id:         8-bit module id
 * root_key_algo:     root key algorithm (enum Algo)
 * root_key_idx:      index of root key to use. Use '0' if only 1 root key.
 * ladder_algo:       keyladder algorithm (enum Algo)
 * ladder_size:       number of keys in keyladder
 * ek5-ek1:           For n-stage keyladders, ekn-1 can be given and others NULL for doing
 *                    challenge/response.
 * ek5:               pointer to k5 encrypted with k6. For 6 stage keyladder.
 *                      Should be 16 bytes (KEY_LEN) or NULL for smaller keyladders.
 * ek4:               pointer to k4 encrypted with k5. For 5+ stage keyladder.
 *                      Should be 16 bytes (KEY_LEN) or NULL for smaller keyladders.
 * ek3:               pointer to k3 encrypted with k5. For 5+ stage keyladder.
 *                      Should be 16 bytes (KEY_LEN) or NULL for smaller keyladders.
 * ek2:               pointer to k2 encrypted with k3. For 3+ stage keyladder.
 *                      Should be 16 bytes (KEY_LEN).
 * ek1:               pointer to k1 encrypted with k2. For 3+ stage keyladder.
 *                      Should be 16 bytes (KEY_LEN).
 * Returns 0 on success
 */
int32_t CA_SetupKeyladder(
        const uint8_t vendor_id[2],
        const uint8_t with_module_id,
        const uint8_t module_id,
        const Algo root_key_algo,
        const uint8_t root_key_idx,
        const Algo ladder_algo,
        const uint8_t ladder_size,
        const uint8_t ek5[16],
        const uint8_t ek4[16],
        const uint8_t ek3[16],
        const uint8_t ek2[16],
        const uint8_t ek1[16]);

/**
 * Perform challenge/response using keyladder.
 *
 * CA_SetupKeyladder should be called before this with at least crypto algorithm and ekn-1.
 *
 * challenge:         pointer to challenge data. Should be 16 bytes (CR_LEN).
 * response:          pointer to buffer to receive response. Should be 16 bytes (CR_LEN).
 * Returns 0 on success
 */
int32_t CA_GetResponse2Challenge(
        const uint8_t challenge[16],
        uint8_t response[16]);

/**
 * Install a control word.
 *
 * Control word can be decrypted using keyladder or a clear CW can be installed directly.
 *
 * cw:          control word
 * cw_len:      length of control word in bytes
 * cw_even_odd: identifies control word is the even or odd key.  Use 0 for even, 1 for odd.
 * cw_algo:     crypto Algo type to decrypt cw. If cw is not encrypted, use CLEAR.
 * iv:          IV used to decrypt cw, if cw is encrypted.
 * iv_algo:     crypto Algo type to decrypt iv in keyladder. If iv is not encrypted, use CLEAR.
 * Returns 0 on success
 */
int32_t CA_InstallCW(uint8_t *cw,
                     uint32_t cw_len,
                     uint8_t cw_even_odd,
                     Algo cw_algo,
                     uint8_t iv[16],
                     Algo iv_algo,
                     const uint8_t root_key_idx,
                     uint8_t bServiceIdx);


// must keep same as SCRAMBLE_ALGO_t in am_ca.h:
typedef enum {
    CA_DSC_ALGO_DVB_CSA,
    CA_DSC_ALGO_AES,
    CA_DSC_ALGO_INVALID,
    CA_DSC_ALGO_NONE,
} ca_descramble_algo_e;

typedef enum {
    CA_DSC_MODE_ECB,
    CA_DSC_MODE_CBC
} ca_descramble_mode_e;

typedef enum {
    CA_DSC_ALIGN_LEFT,
    CA_DSC_ALIGN_RIGHT
} ca_descramble_alignment_e;

typedef struct {
	uint16_t pid[MAX_DESC_COUNT];
	uint16_t channel[MAX_DESC_COUNT];
	uint32_t dsc_dev_no;
	uint32_t dvr_dev_no;
	uint32_t stream_num;//indicate numbers of stream, e.g, if have video and audio, set stream_num to 2
    uint32_t /*ca_descramble_algo_e*/ algo;
    uint32_t /*ca_descramble_mode_e*/ mode;
    uint32_t /*ca_descramble_alignment_e*/ alignment;
    uint32_t service_index;
    uint32_t service_type;
} ca_service_info_t;

int32_t CA_OpenService(int32_t *handle);
/**
 * Set service info
 *
 * info:          service info
 * Returns 0 on success
 */
int32_t CA_SetServiceInfo(int32_t handle, ca_service_info_t *info);
int32_t CA_CloseService(int32_t handle);

/**
 * Install a key into HW Crypto.
 *
 * The key can be decrypted using keyladder or a clear key can be installed directly.
 *
 * key:          the key
 * key_len:      length of the key in bytes
 * key_algo:     crypto Algo type to decrypt the key. If the key is not encrypted, use CLEAR.
 * iv:           optional IV to install.
 * iv_algo:      crypto Algo type to decrypt iv in keyladder. If iv is not encrypted, use CLEAR.
 * thread:       crypto engine thread.
 * Returns 0 on success
 */
int32_t CA_InstallCryptoKey(Algo algo,
                            uint8_t *key,
                            uint32_t key_len,
                            Algo key_algo,
                            uint8_t iv[16],
                            Algo iv_algo,
                            const uint8_t root_key_idx,
                            uint8_t thread,
                            uint32_t flag);

#define SECBUF0_MAX (512*1024)
/**
 * Get secure output buffer
 *
 * buf:           output buffer
 * len:           length
 * Returns 0 on success.
 */
int32_t CA_GetSecureBuffer(uint8_t **buf, int len);

/**
 * Copy data to secure buffer.
 *
 * data:          input data
 * len:           input data len
 * handle:        handle to secure output buffer
 * outlen:        len of used input data
 * Returns 0 on success
 */
int32_t CA_CopySecure(uint8_t *data, int len, void *handle, int *outlen);

/**
 * Decrypt TS data to secure buffer.
 *
 * data:          input data
 * len:           input data len
 * handle:        handle to secure output buffer
 * outlen:        len of used input data
 * Returns 0 on success
 */
int32_t CA_DecryptTS(uint8_t *data, int len, void *handle, int *outlen, Algo algo, uint8_t r2r_seq_engine_idx);

/**
 * Align secmem, replace NAL start bytes, ...
 *
 * out/in:        handle to secure buffer
 * len:           input data len
 * args[0]:       flags
 * Returns 0 on success
 */
int32_t CA_ProcessSecure(void *out, void *in, uint32_t len, uint64_t *args, uint32_t argc);

#define CENC_DECRYPT_MAGIC 0x636e6361
#define MAX_SAMPLE_CNT 1
#define MAX_SUBSAMPLE_CNT 8
typedef struct {
    uint32_t magic;    // CENC_DECRYPT_MAGIC
    uint32_t hdrlen;   // length of entire struct
    uint32_t flags;    // 1=arg=iv
    uint8_t  arg[MAX_SAMPLE_CNT][16];  // 0
    uint32_t sub_len;  // total length (enc+clear)*subSample_cnt*sample_cnt
    uint32_t sample_cnt; // decrypt total sample cnt
    uint32_t subSample_cnt[MAX_SAMPLE_CNT];
    uint32_t subSample_len[MAX_SAMPLE_CNT];// total subSample len = header+clear+enc
    uint16_t clear_size[MAX_SAMPLE_CNT][MAX_SUBSAMPLE_CNT];//subsample clear size
    uint32_t enc_size[MAX_SAMPLE_CNT][MAX_SUBSAMPLE_CNT];//subsample enc size
} cenc_decrypt_header_t;

typedef enum {
    CA_EXTRA_MODE_DISABLE,
    CA_EXTRA_MODE_ENABLE_CENC_AUDIO,
    CA_EXTRA_MODE_ENABLE_CENC_VIDEO,
    CA_EXTRA_MODE_UPDATE_IV,
    CA_EXTRA_MODE_UPDATE_AFIFO_POS,
    CA_EXTRA_MODE_HPD_EVENT,
    CA_EXTRA_MODE_SET_DVR_SERVICES,
    CA_EXTRA_MODE_MAX,
} ca_extra_mode_e;

#define SECURE_VBUF_LEN     (188 * 16 * 128 * 4 + 384*1024)
#define SECURE_ABUF_LEN     (188 * 16 * 128)
#define SECURE_BUF_LEN      (SECURE_VBUF_LEN+SECURE_ABUF_LEN)
#define USE_SEC_MEM
#define SECURE_CRYPTO_LEN   (2*1024*1024) //use for secmem, store dash tmp enc/dec data

typedef enum {
    COPY_TYPE_NONE   = 0,
    COPY_TYPE_SECURE = 1,
    COPY_TYPE_NORMAL = 2,
} COPY_TYPE_e;
/**
 * Set extra mode
 *
 * Returns 0 on success
 */
int32_t CA_SetExtra(uint32_t mode, uint32_t len, uint8_t *args, void *u);

/**
 * Allocate memory to be used for decryption/encryption.
 *
 * Minimal or no copy operations will be performed on this memory when passed to
 * encrypt() and decrypt() for encryption/decryption.
 *
 * size:    bytes to allocate
 * Returns pointer to memory on success, or NULL on failure
 */
void *CA_CryptoAlloc(size_t size);

/**
 * Frees memory allocated by CA_SHMAlloc().
 *
 * p:    pointer to memory returned by CA_SHMAlloc()
 */
void CA_CryptoFree(void *p);

/**
 * Decrypt data.
 *
 * key:         pointer to decryption key or NULL to use key installed by keyladder
 * key_len:     length of key in bytes
 * key_algo:    crypto Algo to decrypt key. If key is not encrypted, use CLEAR.
 * in:          input ciphertext. Can optionally be pointer to memory returned by CA_SHMAlloc()
 * out:         output plaintext. Can optionally be pointer to memory returned by CA_SHMAlloc()
 *                  or same value as 'in' argument.
 * len:         length of 'in'
 * algo:        crypto Algo to use to decrypt 'in'.
 * iv:          IV used to decrypt data, if applicable.
 * thread:      crypto engine thread.
 * Returns 0 on success
 */
int32_t CA_Decrypt(uint8_t *key,
                   uint32_t key_len,
                   Algo key_algo,
                   void *in,
                   void *out,
                   uint32_t len,
                   Algo algo,
                   uint8_t *iv,
                   uint8_t thread);

/**
 * Encrypt data.
 *
 * key:         pointer to encryption key or NULL to use key installed by keyladder
 * key_len:     length of key in bytes
 * key_algo:    crypto Algo to decrypt key. If key is not encrypted, use CLEAR.
 * in:          input plaintext. Can optionally be pointer to memory returned by CA_SHMAlloc()
 * out:         output ciphertext. Can optionally be pointer to memory returned by CA_SHMAlloc()
 *                  or same value as 'in' argument.
 * len:         length of 'in'
 * algo:        crypto Algo to use to encrypt 'in'.
 * iv:          IV used to encrypt data, if applicable.
 * thread:      crypto engine thread.
 * Returns 0 on success
 */
int32_t CA_Encrypt(uint8_t *key,
                   uint32_t key_len,
                   Algo key_algo,
                   void *in,
                   void *out,
                   uint32_t len,
                   Algo algo,
                   uint8_t *iv,
                   uint8_t thread);

int32_t CA_DscOpen(int32_t dev_no, int32_t *index);
int32_t CA_DscSetPid(int32_t dev_no, int32_t index, int32_t pid);
int32_t CA_DscSetKey(int32_t dev_no, int32_t index, int32_t type, uint8_t *key);
int32_t CA_DscClose(int32_t dev_no, int32_t index);
int32_t CA_DscReset(int32_t dev_no, int32_t all);

#endif // CACLIENTAPI_H
