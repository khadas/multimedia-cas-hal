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
} wrapper_cJSON;

extern CasSession get_service_session(int idx);
extern CAS_EventFunction_t get_service_event_cb(int idx);

cJSON *wrapper_cJSON_Create(wrapper_cJSON *jsons, int count, char *out_json)
{
	int i;
	cJSON *output = NULL;
	cJSON *item = NULL;

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

void wrapper_cJSON_Delete(cJSON *object)
{
	if (object) {
		cJSON_Delete(object);
	}
}

void get_purse(uint8_t bNumber, uint32_t* lPurse,
	uint16_t wMult, uint16_t wDiv,
	uint8_t bLocation, uint8_t bSign0,
	uint8_t bSign1000, uint8_t bCount,
	uint8_t bLen, uint8_t *abText)
{
	CAS_EventFunction_t event_cb;
	cJSON *json_object = NULL;
	char out_json[MAX_JSON_LEN];
	wrapper_cJSON jsons[12];
	int item;

	event_cb = (CAS_EventFunction_t)get_global_event_cb();
	if (!event_cb) {
		CA_DEBUG(1, "%s no event callback", __func__);
		return;
	}

	memset(jsons, 0, sizeof(jsons));
	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_CAS;
	jsons[item++].valuestring = VMX_CAS_STRING;

	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_TYPE;
	jsons[item++].valuestring = ITEM_GET_PURSE;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_NUMBER;
	jsons[item++].valuedouble = bNumber;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_PURSE;
	jsons[item++].valuedouble = *lPurse;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_MULT;
	jsons[item++].valuedouble = wMult;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_DIV;
	jsons[item++].valuedouble = wDiv;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_LOCATION;
	jsons[item++].valuedouble = bLocation;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_SIGN0;
	jsons[item++].valuedouble = bSign0;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_SIGN1000;
	jsons[item++].valuedouble = bSign1000;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_COUNT;
	jsons[item++].valuedouble = bCount;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_LEN;
	jsons[item++].valuedouble = bLen;

	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_TEXT;
	jsons[item].valuestring = abText;

	json_object = wrapper_cJSON_Create(jsons, 12, out_json);
	if (json_object) {
		event_cb((CasSession)NULL, out_json);
		wrapper_cJSON_Delete(json_object);
	}

	CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);
}

void_t   OSD_BuildWindow( uint8_t *pabMsg, int16_t wMode,
	int16_t wX, int16_t wY, int16_t wW, int16_t wH,
	int8_t bBackground, int8_t bAlpha, int8_t bForeground )
{
	CAS_EventFunction_t event_cb;
	cJSON *json_object = NULL;
	char out_json[MAX_JSON_LEN];
	wrapper_cJSON jsons[11];

	CA_DEBUG( 0, "%s: %s", __FUNCTION__, pabMsg  );
	event_cb = (CAS_EventFunction_t)get_global_event_cb();
	if (!event_cb) {
		CA_DEBUG(1, "%s no global event callback", __func__);
		return;
	}

	memset(jsons, 0, sizeof(jsons));
	jsons[0].type = cJSON_String;
	jsons[0].key = ITEM_CAS;
	jsons[0].valuestring = VMX_CAS_STRING;

	jsons[1].type = cJSON_String;
	jsons[1].key = ITEM_TYPE;
	jsons[1].valuestring = ITEM_OSD_ATTR;

	jsons[2].type = cJSON_String;
	jsons[2].key = ITEM_OSD_CONTENT;
	jsons[2].valuestring = pabMsg;

	jsons[3].type = cJSON_Number;
	jsons[3].key = ITEM_OSD_MODE;
	jsons[3].valuedouble = wMode;

	jsons[4].type = cJSON_Number;
	jsons[4].key = ITEM_OSD_X;
	jsons[4].valuedouble = wX;

	jsons[5].type = cJSON_Number;
	jsons[5].key = ITEM_OSD_Y;
	jsons[5].valuedouble = wY;

	jsons[6].type = cJSON_Number;
	jsons[6].key = ITEM_OSD_W;
	jsons[6].valuedouble = wW;

	jsons[7].type = cJSON_Number;
	jsons[7].key = ITEM_OSD_H;
	jsons[7].valuedouble = wH;

	jsons[8].type = cJSON_Number;
	jsons[8].key = ITEM_OSD_BG;
	jsons[8].valuedouble = bBackground;

	jsons[9].type = cJSON_Number;
	jsons[9].key = ITEM_OSD_ALPHA;
	jsons[9].valuedouble = bAlpha;

	jsons[10].type = cJSON_Number;
	jsons[10].key = ITEM_OSD_FG;
	jsons[10].valuedouble = bForeground;
	json_object = wrapper_cJSON_Create(jsons, 11, out_json);
	if (json_object) {
		event_cb((CasSession)NULL, out_json);
		wrapper_cJSON_Delete(json_object);
	}

	CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);

	return;
}

uint16_t  OSD_DisplayWindow( uint8_t bDisplayMode, uint16_t wDuration )
{
	CAS_EventFunction_t event_cb;
	cJSON *json_object = NULL;
	char out_json[MAX_JSON_LEN];
	wrapper_cJSON jsons[4];

	CA_DEBUG( 1, "@@call %s @@", __FUNCTION__ );
	event_cb = (CAS_EventFunction_t)get_global_event_cb();
	if (!event_cb) {
		CA_DEBUG(1, "%s no global event callback", __func__);
		return 1;
	}

	memset(jsons, 0, sizeof(jsons));
	jsons[0].type = cJSON_String;
	jsons[0].key = ITEM_CAS;
	jsons[0].valuestring = VMX_CAS_STRING;

	jsons[1].type = cJSON_String;
	jsons[1].key = ITEM_TYPE;
	jsons[1].valuestring = ITEM_OSD_DISPLAY;

	jsons[2].type = cJSON_Number;
	jsons[2].key = ITEM_OSD_DISPLAY_MODE;
	jsons[2].valuedouble = bDisplayMode;

	jsons[3].type = cJSON_Number;
	jsons[3].key = ITEM_OSD_DISPLAY_DURATION;
	jsons[3].valuedouble = wDuration;

	json_object = wrapper_cJSON_Create(jsons, 4, out_json);
	if (json_object) {
		event_cb((CasSession)NULL, out_json);
		wrapper_cJSON_Delete(json_object);
	}

	CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);

	return 1;
}

void_t vmx_notify_func(enBcNotify_t n)
{
	int item = 0;
	int state = 0;
	CAS_EventFunction_t event_cb;
	cJSON *json_object = NULL;
	char out_json[MAX_JSON_LEN];
	wrapper_cJSON jsons[15];

	if (!(event_cb = get_service_event_cb(0))) {
		if (!(event_cb = get_service_event_cb(1))) {
			if (!(event_cb = get_service_event_cb(0x80))) {
				if (!(event_cb = get_service_event_cb(0x81))) {
					event_cb = (CAS_EventFunction_t)get_global_event_cb();
				}
			}
		}
	}
	if (!event_cb) {
		CA_DEBUG(1, "%s no event callback", __func__);
		return;
	}

	if (n = k_BcPinVerified) {
		state = 1;
	} else {
		state = 0;
	}

	memset(jsons, 0, sizeof(jsons));
	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_CAS;
	jsons[item++].valuestring = VMX_CAS_STRING;

	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_TYPE;
	jsons[item++].valuestring = ITEM_PIN_STATE;

	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_ERROR_CODE;
	jsons[item++].valuedouble = state;

	json_object = wrapper_cJSON_Create(jsons, item, out_json);
	if (json_object) {
		event_cb((CasSession)NULL, out_json);
		wrapper_cJSON_Delete(json_object);
	}

	CA_DEBUG(1, "%s out_json:\n%s", __func__, out_json);
}

void_t   ISC_OrderPin( uint8_t bPinIndex, uint32_t lPurse,
	uint32_t lCost, uint16_t wMult, uint16_t wDiv,
	uint8_t bLocation, uint8_t bSign0,
	uint8_t bSign1000, uint8_t bCount, uint8_t bLen,
	uint8_t *abText, uint32_t lEventId, uint8_t bServiceIdx )
{
	CasSession session;
	CAS_EventFunction_t event_cb;
	cJSON *json_object = NULL;
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
	int item = 0;
	CasSession session;
	CAS_EventFunction_t event_cb;
	cJSON *json_object = NULL;
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
	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_CAS;
	jsons[item++].valuestring = VMX_CAS_STRING;
	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_TYPE;
	jsons[item++].valuestring = ITEM_CHECK_PIN;
	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_PIN_INDEX;
	jsons[item++].valuedouble = bPinIndex;
	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_TEXT_SELECTOR;
	jsons[item++].valuedouble = bTextSelector;
	jsons[item].type = cJSON_Number;
	jsons[item].key = ITEM_SERVICE_INDEX;
	jsons[item++].valuedouble = bServiceIdx;
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
	cJSON *json_object = NULL;
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

int vmx_interact_ioctl(CasSession session, const char *in_json, char *out_json, uint32_t out_len)
{
	int ret = -1;
	int item = 0;
	int service_idx = 0;
	cJSON *input = NULL;
	cJSON *cas = NULL;
	cJSON *cmd = NULL;

	cJSON *json_object = NULL;
	wrapper_cJSON jsons[10];

	input = cJSON_Parse(in_json);
	if (input == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr) {
			CA_DEBUG(1, "%s, Error before: %s\n", __func__, error_ptr);
			\
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

	service_idx = get_service_idx(session);
	if (service_idx == -1) {
		service_idx = 1;
	}

	jsons[item].type = cJSON_String;
	jsons[item].key = ITEM_CAS;
	jsons[item++].valuestring = VMX_CAS_STRING;
	if (out_len < MAX_JSON_LEN) {
		CA_DEBUG(1, "%s out_json maybe overflow %#x", out_len);
	}
	if (!strcmp(cmd->valuestring, ITEM_GETSCNO)) {
		uint8_t ser[35] = {0};
		uint16_t serlen = sizeof(ser);
		cJSON *cardno = NULL;

		vmx_bc_lock();
		ret = BC_GetSCNo(ser, serlen);
		vmx_bc_unlock();
		CA_DEBUG(0, "BC_GetSCNo ret=%d, serial number:%s\n\n", ret, ser);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_CARDNO;
		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_CARDNO;
		jsons[item++].valuestring = ser;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_GETVERSION)) {
		uint8_t version[32];
		uint8_t date[20];
		uint8_t timestr[20];

		BC_GetVersion(version, date, timestr);
		CA_DEBUG(0, "BC_GetVersion version:%s\n\n", version);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_GETVERSION;
		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_VERSION;
		jsons[item++].valuestring = version;
		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_DATE;
		jsons[item++].valuestring = date;
		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TIME;
		jsons[item++].valuestring = timestr;
		ret = 0;
	} else if (!strcmp(cmd->valuestring, ITEM_CHECK_PIN)) {
		int i;
		uint8_t pinbcd[16];
		cJSON *pin, *pinIndex, *reason;

		pin = cJSON_GetObjectItem(input, ITEM_PIN);
		if (!cJSON_IsString(pin) || !pin->valuestring) {
			goto end;
		}
		pinIndex = cJSON_GetObjectItem(input, ITEM_PIN_INDEX);
		if (!cJSON_IsNumber(pinIndex)) {
			goto end;
		}
		reason = cJSON_GetObjectItem(input, ITEM_REASON);
		if (!cJSON_IsNumber(reason)) {
			goto end;
		}
		vmx_bc_lock();
		for (i = 0; i < strlen(pin->valuestring); i++) {
			pinbcd[i] = pin->valuestring[i] - '0';
		}
		ret = BC_CheckPin(strlen(pin->valuestring), pinbcd,
				  pinIndex->valueint, reason->valueint, service_idx);

		vmx_bc_unlock();
		CA_DEBUG(1, "BC_CheckPin ret:%d. len:%d, pin:%s, pinIndex:%d, reason:%d, svc_idx:%d",
			ret, strlen(pin->valuestring), pin->valuestring,
			pinIndex->valueint, reason->valueint, service_idx);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_CHECK_PIN;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_CHANGE_PIN)) {
		cJSON *oldPin, *oldPinLen, *newPin, *newPinLen, *pinIndex;

		oldPin = cJSON_GetObjectItemCaseSensitive(input, ITEM_OLD_PIN);
		if (!cJSON_IsString(oldPin) || !oldPin->valuestring) {
			goto end;
		}
		oldPinLen = cJSON_GetObjectItem(input, ITEM_OLD_PIN_LEN);
		if (!cJSON_IsNumber(oldPinLen)) {
			goto end;
		}
		newPin = cJSON_GetObjectItemCaseSensitive(input, ITEM_NEW_PIN);
		if (!cJSON_IsString(newPin) || !newPin->valuestring) {
			goto end;
		}
		newPinLen = cJSON_GetObjectItem(input, ITEM_NEW_PIN_LEN);
		if (!cJSON_IsNumber(newPinLen)) {
			goto end;
		}
		pinIndex = cJSON_GetObjectItem(input, ITEM_PIN_INDEX);
		if (!cJSON_IsNumber(pinIndex)) {
			goto end;
		}
		ret = BC_ChangePin(oldPinLen->valueint, oldPin->valuestring,
				newPinLen->valueint, newPin->valuestring,
				pinIndex->valueint);
		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_CHANGE_PIN;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_GET_PURSE)) {
		BC_GetPurse(get_purse);
		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_GET_PURSE;
	} else if (!strcmp(cmd->valuestring, ITEM_WATERMARK)) {
		cJSON *on, *config, *strength;

		on = cJSON_GetObjectItem(input, ITEM_ON);
		if (!cJSON_IsNumber(on)) {
			goto end;
		}
		config = cJSON_GetObjectItem(input, ITEM_CONFIG);
		if (!cJSON_IsNumber(config)) {
			goto end;
		}
		strength = cJSON_GetObjectItem(input, ITEM_STRENGTH);
		if (!cJSON_IsNumber(strength)) {
			goto end;
		}

		vmx_bc_lock();
		ret = watermark_test_config(service_idx,
				on->valueint,
				config->valueint,
				strength->valueint);
		vmx_bc_unlock();

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_WATERMARK;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_OUTPUT_CONTROL)) {
		cJSON *flag, *analog, *cgmsa, *emicci;

		flag = cJSON_GetObjectItem(input, ITEM_FLAG);
		if (!cJSON_IsNumber(flag)) {
			goto end;
		}
		analog = cJSON_GetObjectItem(input, ITEM_ANALOG);
		if (!cJSON_IsNumber(analog)) {
			goto end;
		}
		cgmsa = cJSON_GetObjectItem(input, ITEM_CGMSA);
		if (!cJSON_IsNumber(cgmsa)) {
			goto end;
		}
		emicci = cJSON_GetObjectItem(input, ITEM_EMICCI);
		if (!cJSON_IsNumber(emicci)) {
			goto end;
		}

		ret = output_control_test_config(service_idx,
				flag->valueint,
				analog->valueint,
				cgmsa->valueint,
				emicci->valueint);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_OUTPUT_CONTROL;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_SVP)) {
		cJSON *addr;

		addr = cJSON_GetObjectItem(input, ITEM_ADDR);
		if (!cJSON_IsNumber(addr)) {
			goto end;
		}

		ret = secure_video_path_test(service_idx, addr->valueint);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_SVP;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_SET_ALGO)) {
		cJSON *algo;

		algo = cJSON_GetObjectItem(input, ITEM_ALGO);
		if (!cJSON_IsNumber(algo)) {
			goto end;
		}

		CA_DEBUG(0, "DVR=%d\n", algo->valueint);
		ret = dvr_test_config(0, algo->valueint);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_SET_ALGO;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_ARB)) {
		cJSON *flag;

		flag = cJSON_GetObjectItem(input, ITEM_FLAG);
		if (!cJSON_IsNumber(flag)) {
			goto end;
		}

		ret = antirollback_test_config(flag->valueint);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_ARB;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else if (!strcmp(cmd->valuestring, ITEM_TA2TA)) {
		cJSON *clientid, *data, *len;

		clientid = cJSON_GetObjectItem(input, ITEM_CLIENTID);
		if (!cJSON_IsNumber(clientid)) {
			goto end;
		}
		data = cJSON_GetObjectItem(input, ITEM_DATA);
		if (!cJSON_IsString(data)) {
			goto end;
		}
		len = cJSON_GetObjectItem(input, ITEM_LEN);
		if (!cJSON_IsNumber(len)) {
			goto end;
		}

		ret = ta2ta_test_config(
				clientid->valueint,
				data->valuestring,
				len->valueint);

		jsons[item].type = cJSON_String;
		jsons[item].key = ITEM_TYPE;
		jsons[item++].valuestring = ITEM_TA2TA;
		jsons[item].type = cJSON_Number;
		jsons[item].key = ITEM_ERROR_CODE;
		jsons[item++].valuedouble = ret;
	} else {
		CA_DEBUG(1, "%s unknown cmd: %s", __func__, cmd->valuestring);
		goto end;
	}

	json_object = wrapper_cJSON_Create(jsons, item, out_json);
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
