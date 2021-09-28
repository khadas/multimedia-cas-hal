#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "cutils/properties.h"

#include "am_cas.h"
#include "am_cas_internal.h"
#include "am_crypt.h"

#ifndef CA_DEBUG_LEVEL
#define CA_DEBUG_LEVEL 2
#endif

typedef struct {
    void *p_des;
    uint8_t buf[188];
    int buf_len;
    int bypass;
    int meta_fd;
    uint64_t meta_id;
} aenc_sess_t;

typedef struct {
    AM_CA_ServiceInfo_t service_info;
} aenc_meta_t;

static int file_read(const char *fname, char *buf, size_t buf_len)
{
    int fd = open(fname, O_RDONLY);
    ssize_t len = 0;

    if (fd != -1)
        len = read(fd, buf, buf_len);

    close(fd);

    return len;
}

static int aml_enc_pre_init(void)
{
    //ret ok to continue
    CA_DEBUG(0, "[aml_enc]pre_init ok");
    return 0;
}

static int aml_enc_init(CasHandle handle)
{
    UNUSED(handle);
    //ret ok to continue
    CA_DEBUG(0, "[aml_enc]init ok");
    return 0;
}

static char *aml_enc_get_version(void)
{
    return CAS_HAL_VER;
}

static int aml_enc_isSystemId_supported(int CA_system_id)
{
    //support all, include free stream
    CA_DEBUG(0, "[aml_enc]supported CA_system_id[%#x]", CA_system_id);
    return 1;
}

static int aml_enc_open_session(CasHandle handle, CasSession session, CA_SERVICE_TYPE_t service_type)
{
    UNUSED(handle);

    char buf[4096];
    char *p1, *p2;
    uint8_t  des_key[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint64_t key_v = 0;

    int ret = file_read("/proc/cpuinfo", buf, sizeof(buf));
    if ((ret != 0) && (p1 = strstr(buf, "Serial"))) {
        if ((p2 = strstr(p1, ": "))) {
            char *pc = p2 + 2;

            while (1) {
                int r;
                uint8_t n;

                r = sscanf(pc, "%02hhx", &n);
                if (r != 1)
                    break;

                key_v = ((key_v << 5) | n);
                pc += 2;
            }

            *(uint64_t*)des_key = key_v;
       }
    }

    CA_DEBUG(0, "[aml_enc]des key: %02x%02x%02x%02x%02x%02x%02x%02x\n",
        des_key[0], des_key[1], des_key[2], des_key[3],
        des_key[4], des_key[5], des_key[6], des_key[7]);

    aenc_sess_t *p_sess = (aenc_sess_t *)calloc(1, sizeof(aenc_sess_t));
    if (!p_sess) {
        CA_DEBUG(0, "[aml_enc] no memory");
        return -1;
    }

    void *p_des = AM_CRYPT_des_open(des_key, 64);
    if (!p_des) {
        CA_DEBUG(0, "[aml_enc]des open fail");
        free(p_sess);
        return -1;
    }

    p_sess->p_des = p_des;
    p_sess->bypass = property_get_bool("vendor.tv.dtv.cas.bypass", 0);

    CA_DEBUG(0, "[aml_enc]session opened [%p], bypass[%d]", p_sess, p_sess->bypass);

    ((CAS_SessionInfo_t *)session)->private_data = p_sess;
    ((CAS_SessionInfo_t *)session)->service_info.service_type = service_type;

    return 0;
}

static int aml_enc_close_session(CasSession session)
{
    CAS_ASSERT(session);
    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;
    CAS_ASSERT(p_sess);
    CAS_ASSERT(p_sess->p_des);
    CA_DEBUG(0, "[aml_enc]session close [%p]", p_sess);
    AM_CRYPT_des_close(p_sess->p_des);
    free(p_sess);
    ((CAS_SessionInfo_t *)session)->private_data = NULL;

    return 0;
}

static int pid_is_enable(uint16_t pid, CasSession session)
{
    AM_CA_ServiceInfo_t *p_sinfo = &((CAS_SessionInfo_t *)session)->service_info;

    if (p_sinfo) {
        int i;
        for (i = 0; i < p_sinfo->stream_num; i++) {
            if (p_sinfo->stream_pids[i] == pid)
                return 1;
        }
    }
    return 0;
}

static int meta_proc(CasSession session, AM_CA_CryptoPara_t *cryptoPara, int decrypt)
{
    char *proc_name = decrypt ? "decrypt" : "encrypt";
    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;
    int fail = 1;

    if (p_sess->meta_id == cryptoPara->segment_id)
        return 0;

    if (p_sess->meta_fd != -1) {
        close(p_sess->meta_fd);
        p_sess->meta_fd = -1;
    }

    {
        char meta_name[1024];

        snprintf(meta_name, sizeof(meta_name),
            "%s-%04llu.aenc.dat",
            cryptoPara->location, (uint64_t)cryptoPara->segment_id);
        p_sess->meta_fd = open(meta_name,
            (decrypt? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC) | O_SYNC,
            S_IRUSR | S_IWUSR);
    }

    //todo: encrypt the meta
    if (p_sess->meta_fd != -1) {
        AM_CA_ServiceInfo_t *p_sinfo = &((CAS_SessionInfo_t *)session)->service_info;
        aenc_meta_t meta = { .service_info = *p_sinfo, };

        if (decrypt) {
            ssize_t ret = read(p_sess->meta_fd, &meta, sizeof(meta));

            if (ret == sizeof(meta)) {
                *p_sinfo = meta.service_info;
                fail = 0;
            }
        } else {
            ssize_t ret = write(p_sess->meta_fd, &meta, sizeof(meta));
            if (ret == sizeof(meta))
                fail = 0;
        }

        p_sess->meta_id = cryptoPara->segment_id;
    }

    CA_DEBUG(0, "[aml_enc]%s, meta processed [%s], [%s.%04llu]",
        proc_name,
        fail ? "fail" : "ok",
        cryptoPara->location, (uint64_t)cryptoPara->segment_id);

    return 0;
}

static int aml_enc_dvr_sync_proc(CasSession session, AM_CA_CryptoPara_t *cryptoPara, int decrypt)
{
    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;
    uint8_t *src = (uint8_t *)cryptoPara->buf_in.addr;
    uint8_t *dst = (uint8_t *)cryptoPara->buf_out.addr;
    uint32_t size = cryptoPara->buf_in.size;
    uint32_t i = 0;
    int processed = 0;
    int drop = 0;
    char *proc_name = decrypt ? "decrypt" : "encrypt";
    int des_ed = 0;

    #define PID(_ts) (((_ts)[1] & 0x1F) << 8 | (_ts)[2])

    if (p_sess->bypass) {
        memcpy(dst, src, size);
        cryptoPara->buf_len = size;
        return 0;
    }

    meta_proc(session, cryptoPara, decrypt);

    if (p_sess->buf_len) {
        int wait = 188 - p_sess->buf_len;
        if (wait <= size) {
            CA_DEBUG(0, "[aml_enc]%s last[%u]", proc_name, p_sess->buf_len);

            memcpy(p_sess->buf + p_sess->buf_len, src, wait);
            i += wait;

            if (pid_is_enable(PID(p_sess->buf), session)) {
                AM_CRYPT_des_crypt(p_sess->p_des, dst, p_sess->buf, 188, NULL, decrypt);
                des_ed += 188;
            } else {
                memcpy(dst, p_sess->buf, 188);
            }

            processed += 188;
            p_sess->buf_len = 0;
        } else {
            CA_DEBUG(0, "[aml_enc]%s still < 188, size[%u]", proc_name, size + p_sess->buf_len);

            memcpy(p_sess->buf + p_sess->buf_len, src, size);
            p_sess->buf_len += size;
            i = size;
        }
    }

    if (i == size) {
        cryptoPara->buf_len = processed;
        return 0;
    }

    while ((i + 188) <= size) {
        if (src[i] != 0x47) {
            i++;
            drop++;
            continue;
        }

        if (pid_is_enable(PID(src + i), session)) {
            AM_CRYPT_des_crypt(p_sess->p_des, dst + processed, src + i, 188, NULL, decrypt);
            des_ed += 188;
        } else {
            memcpy(dst + processed, src + i, 188);
        }

        processed += 188;
        i += 188;
    }

    if (i < size) {
        p_sess->buf_len = size - i;
        memcpy(p_sess->buf, src + i, p_sess->buf_len);
        CA_DEBUG(0, "[aml_enc]%s keep[%u]", proc_name, p_sess->buf_len);
    }

    if (drop) {
        CA_DEBUG(0, "[aml_enc]%s processed[%u] drop[%u]", proc_name, processed, drop);
    }

    cryptoPara->buf_len = processed;

    //CA_DEBUG(0, "[aml_enc]processed[%u] %s[%u]", processed, proc_name, des_ed);
    return 0;
}

static int aml_enc_dvr_encrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    return aml_enc_dvr_sync_proc(session, cryptoPara, 0);
}
static int aml_enc_dvr_decrypt(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    return aml_enc_dvr_sync_proc(session, cryptoPara, 1);
}

static int aml_enc_dvr_start(CasSession session, AM_CA_ServiceInfo_t *service_info)
{
    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;

    p_sess->meta_fd = -1;
    p_sess->meta_id = -1;
    p_sess->buf_len = 0;

    memcpy(&((CAS_SessionInfo_t *)session)->service_info, service_info, sizeof(AM_CA_ServiceInfo_t));

    CA_DEBUG(0, "[aml_enc]dvr start");
    return 0;
}

static int aml_enc_dvr_stop(CasSession session)
{
    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;

    if (p_sess->meta_fd != -1)
        close(p_sess->meta_fd);

    p_sess->meta_id = -1;
    p_sess->buf_len = 0;

    return 0;
}

static int aml_enc_dvr_replay(CasSession session, AM_CA_CryptoPara_t *cryptoPara)
{
    UNUSED(cryptoPara);

    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;

    p_sess->meta_fd = -1;
    p_sess->meta_id = -1;
    p_sess->buf_len = 0;

    CA_DEBUG(0, "[aml_enc]dvr replay");
    return 0;
}

static int aml_enc_dvr_stop_replay(CasSession session)
{
    aenc_sess_t *p_sess = (aenc_sess_t *)((CAS_SessionInfo_t *)session)->private_data;

    if (p_sess->meta_fd != -1)
        close(p_sess->meta_fd);

    p_sess->meta_id = -1;
    p_sess->buf_len = 0;

    return 0;
}

//static int aml_enc_dvr_set_pre_param(CasSession session, AM_CA_PreParam_t *param);
//static int aml_enc_register_event_cb(CasSession session, CAS_EventFunction_t event_fn);
//static int aml_enc_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len);

const struct AM_CA_Impl_t cas_ops = {
    .pre_init = aml_enc_pre_init,
    .init = aml_enc_init,
    .term = NULL,//aml_enc_term,
    .isSystemIdSupported = aml_enc_isSystemId_supported,
    .open_session = aml_enc_open_session,
    .close_session = aml_enc_close_session,
    .dvr_set_pre_param = NULL,//aml_enc_dvr_set_pre_param,
    .dvr_start = aml_enc_dvr_start,
    .dvr_stop = aml_enc_dvr_stop,
    .dvr_encrypt = aml_enc_dvr_encrypt,
    .dvr_decrypt = aml_enc_dvr_decrypt,
    .dvr_replay = aml_enc_dvr_replay,
    .dvr_stop_replay = aml_enc_dvr_stop_replay,
    .register_event_cb = NULL,//aml_enc_register_event_cb,
    .ioctl = NULL,//aml_enc_ioctl,
    .get_version = aml_enc_get_version,
};


