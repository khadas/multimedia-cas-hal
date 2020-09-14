#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <am_cas.h>

#define CA_DEBUG_LEVEL (2)

typedef short (*TestCB_t)(
	unsigned char bMode,
	unsigned char bInfo,
	unsigned char *pabData,
	unsigned int lLen);

TestCB_t g_testcb = NULL;
void SYS_InstallTestCallback(TestCB_t cb)
{
	printf("%s %p\n", __func__, cb);

	if (cb) {
		g_testcb = cb;
	}
}

int dvr_test_config(uint8_t fromenv, uint8_t testcase)
{
	short ret = -1;
	char bInfo = 0xff;
	char *dvr = getenv("DVR");

	if (fromenv && dvr) {
		bInfo = atoi(dvr);
	} else {
		bInfo = testcase;
	}

	printf("%s call cb dvr bInfo = %d\n", __func__, bInfo);
	if (g_testcb) {
		ret = g_testcb(0x1 /*dvr*/, bInfo, NULL, 0);
		printf("cb ret=%d\n", ret);
	} else {
		printf("no test cb installed\n");
	}

	return ret;
}

int watermark_test_config(
	int service_index,
	uint8_t on,
	uint8_t config,
	uint8_t strength)
{
	struct vmData_t {
		unsigned char bOnOff;
		unsigned char bConfig;
		unsigned char bStrength;
	};
	struct vmData_t data = {on, config, strength};
	int ret = -1;

	if (g_testcb) {
		ret = g_testcb(0x2 /*videomark*/,
				service_index,
				(unsigned char*)&data,
				sizeof(data));
		CA_DEBUG(0, "videomark[%d] cb ret=%d\n", service_index, ret);
	} else {
		printf("no test cb installed\n");
	}

	return ret;
}

int output_control_test_config(
	int service_index,
	int flag,
	uint8_t analog,
	uint8_t cgmsa,
	uint8_t emicci)
{
	struct outputData_t {
		unsigned char bOnOff;
		unsigned char bAnalogProtection;
		unsigned char bCgmsa;
		unsigned char bHdcp;
		unsigned char bDownResing;
		unsigned char bEmiCci;
	};
	struct outputData_t data = {0, 0, 0, 0, 0, 0};
	int ret = -1;
	if (flag & 0x80)
		data.bOnOff = 1;
	if (flag & 0x40)
		data.bDownResing = 0x80;

	data.bHdcp = (flag & 0x3);
	data.bAnalogProtection = analog;
	data.bCgmsa = cgmsa;
	data.bEmiCci = emicci;

	if (g_testcb) {
		printf("output control onoff=%d hdcp=%d downresing=%#x \
	bAnalogProtection=%#x bCgmsa=%#x bEmiCci=%#x\n",
			data.bOnOff, data.bHdcp, data.bDownResing,
			data.bAnalogProtection, data.bCgmsa, data.bEmiCci);
		ret = g_testcb(0x0 /*output control*/,
				service_index,
				(unsigned char*)&data,
				sizeof(data));
		printf("output control cb ret=%d\n", ret);
	} else {
		printf("no test cb installed\n");
	}

	return ret;
}

int secure_video_path_test(int service_index, uint8_t *paddr)
{
	int ret = -1;

	if (g_testcb) {
		ret = g_testcb(0x05 /*svp*/,
				service_index,
				paddr, 0);
		printf("secure video path test ret->%d\n");
	} else {
		printf("no test cb installed\n");
	}

	return ret;
}

int antirollback_test_config(unsigned char bInfo)
{
	int ret = -1;
	uint8_t data[16] = {0};

	if (bInfo != 0 && bInfo != 1) {
		printf("bad arg\n");
		return ret;
	}

	if (g_testcb) {
		printf("antirollback test config bInfo=%u\n", bInfo);
		ret = g_testcb(0x3 /*arb*/, bInfo, &data[0], 0);
		printf("antirollback test cb ret=%d\n", ret);
	} else {
		printf("no test cb installed\n");
	}

	return ret;
}

int ta2ta_test_config(
	unsigned char clientid,
	unsigned char *data,
	unsigned int len)
{
	int ret = -1;

	if (len < 2 || len > 2048 || !data) {
		printf("bad arg\n");
	}

	if (g_testcb) {
		printf("ta2ta test config clientid=%u len=%u\n", clientid, len);
		ret = g_testcb(0x6 /*ta2ta*/, clientid, data, len);
		printf("ta2ta test cb ret=%d\n", ret);
	} else {
		printf("no test cb installed\n");
	}

	return ret;
}
