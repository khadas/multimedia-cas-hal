#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc_consts.h"
#include "bc_main.h"
#include "am_cas.h"
#include "am_cas_internal.h"
#include "cas_json.h"

#define VMX_CAS_STRING "Verimatrix"
#define CA_DEBUG_LEVEL 2

/* The wrapper cJSON structure */
typedef struct {
    /* The cJSON type of the item*/
    int type;
    /* The item's name string*/
    char *key;
    /* The item's value string if type==cJSON_String*/
    char *valuestring;
    /* The item's value if type==cJSON_Number*/
    double valuedouble;    
}wrapper_cJSON;

extern CasSession get_service_session(int idx);
extern CAS_EventFunction_t get_service_event_cb(int idx);

const cJSON *wrapper_cJSON_Create(wrapper_cJSON *jsons, int count, char *out_json)
{
    int i;
    const cJSON *output = NULL;
    const cJSON *item = NULL;

    output = cJSON_CreateObject();
    if (!output) {
	CA_DEBUG(1, "%s create failed", __func__);
	goto exit;
    }

    for (i = 0; i < count; i++) {
	if (jsons[i].type == cJSON_String) {
	    item = cJSON_CreateString(jsons[i].valuestring);
	} else if (jsons[i].type == cJSON_Number) {
	    item = cJSON_CreateNumber(jsons[i].valuedouble);
	}
	if (item == NULL) {
	    CA_DEBUG(1, "%s create item failed", __func__);
	    goto exit;
	}
	cJSON_AddItemToObject(output, jsons[i].key, item);
    }
    cJSON_PrintPreallocated(output, out_json, MAX_JSON_LEN, 1);
    return output;

exit:
    if (output) {
	cJSON_Delete(output);
    }
    return NULL;
}

void wrapper_cJSON_Delete(const cJSON *object)
{
    if (object) {
	cJSON_Delete(object);
    }
}

void_t   ISC_OrderPin( uint8_t bPinIndex, uint32_t lPurse,
                       uint32_t lCost, uint16_t wMult, uint16_t wDiv,
                       uint8_t bLocation, uint8_t bSign0,
                       uint8_t bSign1000, uint8_t bCount, uint8_t bLen,
                       uint8_t *abText, uint32_t lEventId, uint8_t bServiceIdx )
{
    CasSession session;
    CAS_EventFunction_t event_cb;
    const cJSON *json_object = NULL;
    char out_json[MAX_JSON_LEN];
    wrapper_cJSON jsons[15];

    CA_DEBUG( 0, "call %s bPinIndex=%#x %#x %#x lEventId=%#x serviceIdx=%#x", __FUNCTION__, bPinIndex, lPurse, lCost, lEventId, bServiceIdx );
    
    session = get_service_session(bServiceIdx);
    if (!session) {
	CA_DEBUG(1, "%s invalid session", __func__);
	return;
    }

    event_cb = get_service_event_cb(bServiceIdx);
    if (!event_cb) {
	CA_DEBUG(1, "%s no event callback", __func__);
	return;
    }

    memset(jsons, 0, sizeof(jsons));
    jsons[0].type = cJSON_String;
    jsons[0].key = ITEM_CAS;
    jsons[0].valuestring = VMX_CAS_STRING;

    jsons[1].type = cJSON_String;
    jsons[1].key = ITEM_TYPE;
    jsons[1].valuestring = ITEM_ORDER_PIN;

    jsons[2].type = cJSON_Number;
    jsons[2].key = ITEM_PIN_INDEX;
    jsons[2].valuedouble = bPinIndex;

    jsons[3].type = cJSON_Number;
    jsons[3].key = ITEM_PURSE;
    jsons[3].valuedouble = lPurse;

    jsons[4].type = cJSON_Number;
    jsons[4].key = ITEM_COST;
    jsons[4].valuedouble = lCost;

    jsons[5].type = cJSON_Number;
    jsons[5].key = ITEM_MULT;
    jsons[5].valuedouble = wMult;

    jsons[6].type = cJSON_Number;
    jsons[6].key = ITEM_DIV;
    jsons[6].valuedouble = wDiv;

    jsons[7].type = cJSON_Number;
    jsons[7].key = ITEM_LOCATION;
    jsons[7].valuedouble = bLocation;

    jsons[8].type = cJSON_Number;
    jsons[8].key = ITEM_SIGN0;
    jsons[8].valuedouble = bSign0;

    jsons[9].type = cJSON_Number;
    jsons[9].key = ITEM_SIGN1000;
    jsons[9].valuedouble = bSign1000;

    jsons[10].type = cJSON_Number;
    jsons[10].key = ITEM_COUNT;
    jsons[10].valuedouble = bCount;

    jsons[11].type = cJSON_Number;
    jsons[11].key = ITEM_LEN;
    jsons[11].valuedouble = bLen;

    jsons[12].type = cJSON_String;
    jsons[12].key = ITEM_TEXT;
    jsons[12].valuestring = abText;

    jsons[13].type = cJSON_Number;
    jsons[13].key = ITEM_EVENTID;
    jsons[13].valuedouble = lEventId;

    jsons[14].type = cJSON_Number;
    jsons[14].key = ITEM_SERVICE_INDEX;
    jsons[14].valuedouble = bServiceIdx;

    json_object = wrapper_cJSON_Create(jsons, 15, out_json);
    if (json_object) {
	event_cb(session, out_json);
	wrapper_cJSON_Delete(json_object);
    }

    CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);

    return;
}

void_t   ISC_CheckPin( uint8_t bPinIndex, uint8_t bTextSelector, uint8_t bServiceIdx )
{
    CasSession session;
    CAS_EventFunction_t event_cb;
    const cJSON *json_object = NULL;
    char out_json[MAX_JSON_LEN];
    wrapper_cJSON jsons[4];

    CA_DEBUG( 0, "call %s %#x %#x %#x", __FUNCTION__, bPinIndex, bTextSelector, bServiceIdx );
    
    session = get_service_session(bServiceIdx);
    if (!session) {
	CA_DEBUG(1, "%s invalid session", __func__);
	return;
    }

    event_cb = get_service_event_cb(bServiceIdx);
    if (!event_cb) {
	CA_DEBUG(1, "%s no event callback", __func__);
	return;
    }

    memset(jsons, 0, sizeof(jsons));
    jsons[0].type = cJSON_String;
    jsons[0].key = ITEM_CAS;
    jsons[0].valuestring = VMX_CAS_STRING;
    jsons[1].type = cJSON_Number;
    jsons[1].key = ITEM_PIN_INDEX;
    jsons[1].valuedouble = bPinIndex;
    jsons[2].type = cJSON_Number;
    jsons[2].key = ITEM_TEXT_SELECTOR;
    jsons[2].valuedouble = bTextSelector;
    jsons[3].type = cJSON_Number;
    jsons[3].key = ITEM_SERVICE_INDEX;
    jsons[3].valuedouble = bServiceIdx;
    json_object = wrapper_cJSON_Create(jsons, 4, out_json);
    if (json_object) {
	event_cb(session, out_json);
	wrapper_cJSON_Delete(json_object);
    }

    CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);
    return;
}

// --- MMI---
int16_t  MMI_SetDescrambling_State( uint16_t wIndex,
                                    uint16_t *pawStreamPid,
                                    enDescState_t *paenDescState,
                                    uint8_t bServiceIdx )
{
    CasSession session;
    CAS_EventFunction_t event_cb;
    const cJSON *json_object = NULL;
    char out_json[MAX_JSON_LEN];
    wrapper_cJSON jsons[3];
    int descrambled;

    CA_DEBUG( 1, "@@call %s, [%d]state=%d, wIndex=%d", 
	__FUNCTION__, bServiceIdx, *paenDescState, wIndex );

    if (*paenDescState == 0) {
	descrambled = 1;
    } else {
	descrambled = 0;
    }
    session = get_service_session(bServiceIdx);
    CAS_ASSERT(session);

    event_cb = get_service_event_cb(bServiceIdx);
    CAS_ASSERT(event_cb);

    jsons[0].type = cJSON_String;
    jsons[0].key = ITEM_CAS;
    jsons[0].valuestring = VMX_CAS_STRING;
    jsons[1].type = cJSON_String;
    jsons[1].key = ITEM_TYPE;
    jsons[1].valuestring = ITEM_DESC_STATE;
    jsons[2].type = cJSON_Number;
    jsons[2].key = ITEM_DESC_STATE;
    jsons[2].valuedouble = descrambled;
    json_object = wrapper_cJSON_Create(jsons, 3, out_json);
    if (json_object) {
	event_cb(session, out_json);
	wrapper_cJSON_Delete(json_object);
    }

    CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);
    
    return 0;
}

int vmx_interact_ioctl(CasSession session, const char *in_json, const char *out_json, uint32_t out_len)
{
    int ret = -1;
    int item_cnt = 0;
    const cJSON *input = NULL;
    const cJSON *cas = NULL;
    const cJSON *cmd = NULL;

    const cJSON *json_object = NULL;
    wrapper_cJSON jsons[10];

    input = cJSON_Parse(in_json);
    if (input == NULL) {
	const char *error_ptr = cJSON_GetErrorPtr();
	if (error_ptr) {
	    CA_DEBUG(1, "%s, Error before: %s\n", __func__, error_ptr);\
	    ret = -1;
	    goto end;
	}
    }

    cas = cJSON_GetObjectItemCaseSensitive(input, ITEM_CAS);
    if (!cJSON_IsString(cas) || (strcmp(cas->valuestring, VMX_CAS_STRING))) {
	CA_DEBUG(1, "%s, not Vermatrix cas cmd", __func__);
	ret = -1;
	goto end;
    }

    cmd = cJSON_GetObjectItemCaseSensitive(input, ITEM_CMD);
    if (!cJSON_IsString(cmd) || !cmd->valuestring) {
	CA_DEBUG(1, "%s invalid cmd", __func__);
	ret = -1;
	goto end;
    }

    jsons[0].type = cJSON_String;
    jsons[0].key = ITEM_CAS;
    jsons[0].valuestring = VMX_CAS_STRING;
    if (out_len < MAX_JSON_LEN) {
	CA_DEBUG(1, "%s out_json maybe overflow %#x", out_len);
    }
    if (!strcmp(cmd->valuestring, ITEM_GETSCNO)) {
	uint8_t ser[35] = {0};
	uint16_t serlen = sizeof(ser);
	const cJSON *cardno = NULL;

	vmx_bc_lock();
	ret = BC_GetSCNo(ser, serlen);
	vmx_bc_unlock();
	CA_DEBUG(0, "BC_GetSCNo ret=%d, serial number:%s\n\n", ret, ser);

	jsons[1].type = cJSON_String;
	jsons[1].key = ITEM_TYPE;
	jsons[1].valuestring = ITEM_CARDNO;
	jsons[2].type = cJSON_String;
	jsons[2].key = ITEM_CARDNO;
	jsons[2].valuestring = ser;
	item_cnt = 3;
    } else if (!strcmp(cmd->valuestring, ITEM_GETVERSION)) {
	uint8_t version[32];
	uint8_t date[20];
	uint8_t timestr[20];

	BC_GetVersion(version, date, timestr);
	CA_DEBUG(0, "BC_GetVersion version:%s\n\n", version);

	jsons[1].type = cJSON_String;
	jsons[1].key = ITEM_TYPE;
	jsons[1].valuestring = ITEM_GETVERSION;
	jsons[2].type = cJSON_String;
	jsons[2].key = ITEM_VERSION;
	jsons[2].valuestring = version;
	jsons[3].type = cJSON_String;
	jsons[3].key = ITEM_DATE;
	jsons[3].valuestring = date;
	jsons[4].type = cJSON_String;
	jsons[4].key = ITEM_TIME;
	jsons[4].valuestring = timestr;
	item_cnt = 5;
	ret = 0;
    } else if (!strcmp(cmd->valuestring, ITEM_CHECK_PIN)) {
	const cJSON *pin = NULL;
	const cJSON *pinIndex = NULL;
	const cJSON *reason = NULL;
	int serviceIdx;

	pin = cJSON_GetObjectItemCaseSensitive(input, ITEM_PIN);
	if (!cJSON_IsString(pin) || !pin->valuestring) {
	    goto end;
	}
	pinIndex = cJSON_GetObjectItemCaseSensitive(input, ITEM_PIN_INDEX);
	if (!cJSON_IsNumber(pinIndex)) {
	    goto end;
	}
	reason = cJSON_GetObjectItemCaseSensitive(input, ITEM_REASON);
	if (!cJSON_IsNumber(reason)) {
	    goto end;
	}
	serviceIdx = get_service_idx(session);
	ret = BC_CheckPin(strlen(pin->valuestring), pin->valuestring, pinIndex->valuedouble, reason->valuedouble, serviceIdx);
	if (ret) {
	    CA_DEBUG(1, "BC_CheckPin failed ret: %d, pin: %s, svc_idx: %d",
		ret, pin->valuestring, serviceIdx);
	} else {
	    CA_DEBUG(0, "BC_CheckPin ok");
	}
    }
    else {
	CA_DEBUG(1, "%s unknown cmd: %s", __func__, cmd->valuestring);
	goto end;
    }

    json_object = wrapper_cJSON_Create(jsons, item_cnt, out_json);
    if (json_object) {
	wrapper_cJSON_Delete(json_object);
    }
    CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);

end:
    if (ret) {
	CA_DEBUG(1, "%s failed. in_json:\n%s", __func__, in_json);
    }
    if (input) {
	cJSON_Delete(input);
    }
    return ret;
}
