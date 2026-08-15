/*
 * TLS Certificate Utilities
 *
 * See cert_utilities.h for a description of this module's role.
 *
 * Copyright 2020-2022 Dan Julio
 *
 * This file is part of tCam.
 *
 * tCam is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * tCam is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with tCam.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
#include "cert_utilities.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <stdlib.h>
#include <string.h>


//
// Cert Utilities constants
//
#define CERT_NVS_NAMESPACE "tcamtls"
#define CERT_NVS_CERT_KEY  "cert_pem"
#define CERT_NVS_PKEY_KEY  "pkey_pem"

#define CERT_PEM_MAX_LEN   2048
#define KEY_PEM_MAX_LEN    1024

// Fixed validity window: 2020 through 2050 (30 years).  Fixed strings rather than
// clock-derived because the camera's RTC starts at 1970 on power-up - a notBefore
// taken from an unset clock would make the certificate invalid.
#define CERT_NOT_BEFORE "20200101000000"
#define CERT_NOT_AFTER  "20500101000000"

#define CERT_SUBJECT "CN=tCam-Mini,O=tCam"

// Stack for the temporary generation task.  mbedTLS EC point multiplication uses
// several KB of stack temporaries; running it on a caller's (smaller) stack
// overflowed and corrupted memory.  This task exists only for the second or so
// that generation takes and its stack is returned to the heap when it exits.
#define CERT_GEN_TASK_STACK 12288


//
// Cert Utilities variables
//
static const char* TAG = "cert_utilities";

static unsigned char* cert_buf = NULL;
static unsigned char* key_buf = NULL;
static size_t cert_buf_len = 0;    // includes null terminator
static size_t key_buf_len = 0;     // includes null terminator


//
// Cert Utilities forward declarations
//
static bool cert_load_from_nvs();
static bool cert_generate();
static bool cert_store_to_nvs();


//
// Cert Utilities API
//
// Handshake between cert_get and the temporary generation task
static SemaphoreHandle_t gen_done_sem = NULL;
static volatile bool gen_result = false;

static void cert_gen_task(void* arg)
{
	gen_result = cert_generate();
	xSemaphoreGive(gen_done_sem);
	vTaskDelete(NULL);
}


bool cert_get(const unsigned char** cert_pem, size_t* cert_len,
              const unsigned char** key_pem, size_t* key_len)
{
	if (cert_buf == NULL) {
		if (!cert_load_from_nvs()) {
			ESP_LOGI(TAG, "No stored certificate - generating (this happens once)");

			// Run generation on a dedicated task with a stack sized for EC math,
			// then reclaim it - callers keep their small permanent stacks
			gen_done_sem = xSemaphoreCreateBinary();
			if (gen_done_sem == NULL) return false;

			if (xTaskCreatePinnedToCore(&cert_gen_task, "cert_gen", CERT_GEN_TASK_STACK,
			                            NULL, 1, NULL, 0) != pdPASS) {
				ESP_LOGE(TAG, "Could not start generation task");
				vSemaphoreDelete(gen_done_sem);
				gen_done_sem = NULL;
				return false;
			}

			(void) xSemaphoreTake(gen_done_sem, portMAX_DELAY);
			vSemaphoreDelete(gen_done_sem);
			gen_done_sem = NULL;

			if (!gen_result) {
				return false;
			}
			if (!cert_store_to_nvs()) {
				// Still usable this boot; it will be regenerated next time
				ESP_LOGE(TAG, "Could not persist certificate");
			}
		}
	}

	*cert_pem = cert_buf;
	*cert_len = cert_buf_len;
	*key_pem  = key_buf;
	*key_len  = key_buf_len;

	return true;
}


//
// Cert Utilities internal functions
//
static bool cert_load_from_nvs()
{
	esp_err_t err;
	nvs_handle_t h;
	size_t clen = 0, klen = 0;

	err = nvs_open(CERT_NVS_NAMESPACE, NVS_READONLY, &h);
	if (err != ESP_OK) return false;

	if ((nvs_get_blob(h, CERT_NVS_CERT_KEY, NULL, &clen) != ESP_OK) ||
	    (nvs_get_blob(h, CERT_NVS_PKEY_KEY, NULL, &klen) != ESP_OK) ||
	    (clen == 0) || (klen == 0) ||
	    (clen > CERT_PEM_MAX_LEN) || (klen > KEY_PEM_MAX_LEN)) {
		nvs_close(h);
		return false;
	}

	cert_buf = malloc(clen);
	key_buf = malloc(klen);
	if ((cert_buf == NULL) || (key_buf == NULL)) {
		nvs_close(h);
		free(cert_buf); cert_buf = NULL;
		free(key_buf);  key_buf = NULL;
		return false;
	}

	if ((nvs_get_blob(h, CERT_NVS_CERT_KEY, cert_buf, &clen) != ESP_OK) ||
	    (nvs_get_blob(h, CERT_NVS_PKEY_KEY, key_buf, &klen) != ESP_OK)) {
		nvs_close(h);
		free(cert_buf); cert_buf = NULL;
		free(key_buf);  key_buf = NULL;
		return false;
	}
	nvs_close(h);

	// Stored blobs include their null terminators; verify before trusting
	if ((cert_buf[clen-1] != 0) || (key_buf[klen-1] != 0)) {
		ESP_LOGE(TAG, "Stored certificate malformed - regenerating");
		free(cert_buf); cert_buf = NULL;
		free(key_buf);  key_buf = NULL;
		return false;
	}

	cert_buf_len = clen;
	key_buf_len = klen;
	ESP_LOGI(TAG, "Loaded certificate from NVS");
	return true;
}


static bool cert_generate()
{
	bool success = false;
	int ret;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_mpi serial;
	mbedtls_pk_context key;
	mbedtls_x509write_cert crt;
	unsigned char serial_bytes[16];
	const char* pers = "tcam_cert_gen";

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_pk_init(&key);
	mbedtls_x509write_crt_init(&crt);
	mbedtls_mpi_init(&serial);

	cert_buf = malloc(CERT_PEM_MAX_LEN);
	key_buf = malloc(KEY_PEM_MAX_LEN);
	if ((cert_buf == NULL) || (key_buf == NULL)) {
		ESP_LOGE(TAG, "Buffer allocation failed");
		goto done;
	}

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	                            (const unsigned char*) pers, strlen(pers));
	if (ret != 0) { ESP_LOGE(TAG, "drbg seed failed (-0x%04x)", -ret); goto done; }

	// EC P-256: generation takes well under a second on the ESP32, unlike RSA
	ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (ret != 0) { ESP_LOGE(TAG, "pk setup failed (-0x%04x)", -ret); goto done; }

	ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
	                          mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) { ESP_LOGE(TAG, "key generation failed (-0x%04x)", -ret); goto done; }

	// Random positive serial number
	esp_fill_random(serial_bytes, sizeof(serial_bytes));
	serial_bytes[0] &= 0x7F;
	ret = mbedtls_mpi_read_binary(&serial, serial_bytes, sizeof(serial_bytes));
	if (ret != 0) { ESP_LOGE(TAG, "serial failed (-0x%04x)", -ret); goto done; }

	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&crt, &key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &key);

	ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
	if (ret != 0) { ESP_LOGE(TAG, "set serial failed (-0x%04x)", -ret); goto done; }
	ret = mbedtls_x509write_crt_set_subject_name(&crt, CERT_SUBJECT);
	if (ret != 0) { ESP_LOGE(TAG, "subject failed (-0x%04x)", -ret); goto done; }
	ret = mbedtls_x509write_crt_set_issuer_name(&crt, CERT_SUBJECT);
	if (ret != 0) { ESP_LOGE(TAG, "issuer failed (-0x%04x)", -ret); goto done; }
	ret = mbedtls_x509write_crt_set_validity(&crt, CERT_NOT_BEFORE, CERT_NOT_AFTER);
	if (ret != 0) { ESP_LOGE(TAG, "validity failed (-0x%04x)", -ret); goto done; }
	ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	if (ret != 0) { ESP_LOGE(TAG, "constraints failed (-0x%04x)", -ret); goto done; }

	ret = mbedtls_x509write_crt_pem(&crt, cert_buf, CERT_PEM_MAX_LEN,
	                                mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) { ESP_LOGE(TAG, "cert pem write failed (-0x%04x)", -ret); goto done; }

	ret = mbedtls_pk_write_key_pem(&key, key_buf, KEY_PEM_MAX_LEN);
	if (ret != 0) { ESP_LOGE(TAG, "key pem write failed (-0x%04x)", -ret); goto done; }

	cert_buf_len = strlen((char*) cert_buf) + 1;
	key_buf_len = strlen((char*) key_buf) + 1;
	ESP_LOGI(TAG, "Generated certificate (%d + %d bytes, valid to 2050)",
	         (int) cert_buf_len, (int) key_buf_len);
	success = true;

done:
	if (!success) {
		free(cert_buf); cert_buf = NULL;
		free(key_buf);  key_buf = NULL;
	}
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return success;
}


static bool cert_store_to_nvs()
{
	esp_err_t err;
	nvs_handle_t h;

	err = nvs_open(CERT_NVS_NAMESPACE, NVS_READWRITE, &h);
	if (err != ESP_OK) return false;

	if ((nvs_set_blob(h, CERT_NVS_CERT_KEY, cert_buf, cert_buf_len) != ESP_OK) ||
	    (nvs_set_blob(h, CERT_NVS_PKEY_KEY, key_buf, key_buf_len) != ESP_OK) ||
	    (nvs_commit(h) != ESP_OK)) {
		nvs_close(h);
		return false;
	}

	nvs_close(h);
	ESP_LOGI(TAG, "Certificate stored");
	return true;
}
