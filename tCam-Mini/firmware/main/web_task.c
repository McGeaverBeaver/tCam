/*
 * Web Server Task
 *
 * See web_task.h for a description of this module's role.
 *
 * The UI itself is a single gzipped HTML file linked into the firmware image.
 * Keeping it in the application partition rather than a separate filesystem means
 * an OTA update replaces the firmware and its UI atomically - the two can never be
 * left at mismatched versions, which is the usual failure of split-image designs.
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
#include "web_task.h"
#include "web_cmd.h"
#include "dns_hijack.h"
#include "ctrl_task.h"
#include "net_utilities.h"
#include "wifi_utilities.h"
#include "system_config.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>


//
// Web Task constants
//

// Chunk used to drain an OTA upload out of the socket
#define OTA_RX_CHUNK 1024

// Upper bound on networks returned by a scan
#define SCAN_MAX_AP 20


//
// Web Task variables
//
static const char* TAG = "web_task";

static httpd_handle_t server = NULL;

// Written by the server task during an upload, polled by rsp_task
static volatile bool ota_active = false;

// The UI, gzipped and linked in by EMBED_FILES in CMakeLists.txt
extern const uint8_t index_html_gz_start[] asm("_binary_index_html_gz_start");
extern const uint8_t index_html_gz_end[]   asm("_binary_index_html_gz_end");


//
// Web Task forward declarations
//
static esp_err_t index_get_handler(httpd_req_t* req);
static esp_err_t status_get_handler(httpd_req_t* req);
static esp_err_t scan_get_handler(httpd_req_t* req);
static esp_err_t ota_post_handler(httpd_req_t* req);
static esp_err_t redirect_handler(httpd_req_t* req, httpd_err_code_t err);
static bool start_webserver();


//
// Web Task API
//
void web_task()
{
	net_info_t* net_infoP;

	ESP_LOGI(TAG, "Start task");

	// The listening socket cannot be bound before the interface has an address
	while (!(*net_is_connected)()) {
		vTaskDelay(pdMS_TO_TICKS(500));
	}

	if (!start_webserver()) {
		ESP_LOGE(TAG, "Could not start web server");
		vTaskDelete(NULL);
		return;
	}

	// Only hijack DNS while we are the access point.  On someone else's network
	// there is a real resolver and answering for every name would be hostile.
	// Note: cur_ip_addr index 3 holds the FIRST octet (see ps_utilities), and the
	// first octet is the lowest byte in network order.
	if (wifi_is_ap_mode()) {
		net_infoP = (*net_get_info)();
		dns_hijack_start(((uint32_t) net_infoP->cur_ip_addr[3])       |
		                 ((uint32_t) net_infoP->cur_ip_addr[2] << 8)  |
		                 ((uint32_t) net_infoP->cur_ip_addr[1] << 16) |
		                 ((uint32_t) net_infoP->cur_ip_addr[0] << 24));
		ESP_LOGI(TAG, "Captive portal active on %d.%d.%d.%d",
		         net_infoP->cur_ip_addr[3], net_infoP->cur_ip_addr[2],
		         net_infoP->cur_ip_addr[1], net_infoP->cur_ip_addr[0]);
	}

	// The server runs on its own task from here; nothing left to do but stay alive
	while (1) {
		vTaskDelay(pdMS_TO_TICKS(10000));
	}
}


bool web_ota_in_progress()
{
	return ota_active;
}


//
// Web Task internal functions
//
static bool start_webserver()
{
	esp_err_t ret;
	httpd_config_t config = HTTPD_DEFAULT_CONFIG();

	config.server_port      = WEB_PORT;
	config.ctrl_port        = 32768;
	config.stack_size       = WEB_TASK_STACK_SIZE;
	config.max_open_sockets = 4;
	config.lru_purge_enable = true;
	// Wildcard matching lets one handler answer every captive-portal probe URL
	config.uri_match_fn     = httpd_uri_match_wildcard;
	// Long enough that a slow phone does not get dropped mid-upload
	config.recv_wait_timeout = 15;
	config.send_wait_timeout = 15;
	config.close_fn          = web_cmd_close_fn;

	ret = httpd_start(&server, &config);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "httpd_start failed (%d)", ret);
		return false;
	}

	static const httpd_uri_t index_uri = {
		.uri = "/", .method = HTTP_GET, .handler = index_get_handler, .user_ctx = NULL
	};
	static const httpd_uri_t status_uri = {
		.uri = "/api/status", .method = HTTP_GET, .handler = status_get_handler, .user_ctx = NULL
	};
	static const httpd_uri_t scan_uri = {
		.uri = "/api/scan", .method = HTTP_GET, .handler = scan_get_handler, .user_ctx = NULL
	};
	static const httpd_uri_t ota_uri = {
		.uri = "/api/ota", .method = HTTP_POST, .handler = ota_post_handler, .user_ctx = NULL
	};

	httpd_register_uri_handler(server, &index_uri);
	httpd_register_uri_handler(server, &status_uri);
	httpd_register_uri_handler(server, &scan_uri);
	httpd_register_uri_handler(server, &ota_uri);
	web_cmd_register(server);

	// Anything else - including every OS connectivity probe - is bounced to the UI
	httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, redirect_handler);

	ESP_LOGI(TAG, "Web server started on port %d", WEB_PORT);
	return true;
}


static esp_err_t index_get_handler(httpd_req_t* req)
{
	httpd_resp_set_type(req, "text/html");
	httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
	// The UI ships with the firmware, so it is safe to cache until the next update
	httpd_resp_set_hdr(req, "Cache-Control", "max-age=600");

	return httpd_resp_send(req, (const char*) index_html_gz_start,
	                       index_html_gz_end - index_html_gz_start);
}


static esp_err_t status_get_handler(httpd_req_t* req)
{
	char buf[384];
	const esp_app_desc_t* app_desc;
	int brd_type;
	int if_type;
	int len;
	net_info_t* net_infoP;

	app_desc = esp_ota_get_app_description();
	net_infoP = (*net_get_info)();
	ctrl_get_if_mode(&brd_type, &if_type);

	len = snprintf(buf, sizeof(buf),
		"{\"camera\":\"%s\",\"version\":\"%s\",\"model\":%d,"
		"\"interface\":\"%s\",\"mode\":\"%s\",\"ip\":\"%d.%d.%d.%d\","
		"\"sta_ssid\":\"%s\",\"ota\":%s}",
		net_infoP->ap_ssid,
		app_desc->version,
		(brd_type == CTRL_BRD_ETH_TYPE) ? CAMERA_MODEL_NUM_ETH : CAMERA_MODEL_NUM_WIFI,
		(if_type == CTRL_IF_MODE_ETH) ? "Ethernet" : "WiFi",
		wifi_is_ap_mode() ? "ap" : "sta",
		net_infoP->cur_ip_addr[3], net_infoP->cur_ip_addr[2],
		net_infoP->cur_ip_addr[1], net_infoP->cur_ip_addr[0],
		net_infoP->sta_ssid,
		ota_active ? "true" : "false");

	httpd_resp_set_type(req, "application/json");
	return httpd_resp_send(req, buf, len);
}


static esp_err_t scan_get_handler(httpd_req_t* req)
{
	char entry[128];
	esp_err_t ret;
	uint16_t emitted;
	uint16_t i;
	uint16_t num = SCAN_MAX_AP;
	static wifi_ap_record_t records[SCAN_MAX_AP];
	wifi_scan_config_t scan_cfg = {
		.ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = false,
		.scan_type = WIFI_SCAN_TYPE_ACTIVE
	};

	// A scan takes a couple of seconds and stalls the radio, which would visibly
	// stutter a live stream, so this is only offered on demand from the settings UI
	ret = esp_wifi_scan_start(&scan_cfg, true);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "scan failed (%d)", ret);
		httpd_resp_set_type(req, "application/json");
		return httpd_resp_sendstr(req, "{\"error\":\"scan failed\",\"networks\":[]}");
	}

	esp_wifi_scan_get_ap_records(&num, records);

	httpd_resp_set_type(req, "application/json");
	httpd_resp_sendstr_chunk(req, "{\"networks\":[");

	emitted = 0;
	for (i = 0; i < num; i++) {
		// Skip unnamed networks - they cannot be selected from a list anyway
		if (records[i].ssid[0] == 0) continue;

		// Separator keys off what has actually been emitted, not the loop index,
		// so a skipped first entry cannot produce a leading comma
		snprintf(entry, sizeof(entry), "%s{\"ssid\":\"%s\",\"rssi\":%d,\"open\":%s}",
		         (emitted == 0) ? "" : ",",
		         (char*) records[i].ssid,
		         records[i].rssi,
		         (records[i].authmode == WIFI_AUTH_OPEN) ? "true" : "false");
		httpd_resp_sendstr_chunk(req, entry);
		emitted++;
	}

	httpd_resp_sendstr_chunk(req, "]}");
	return httpd_resp_sendstr_chunk(req, NULL);
}


/**
 * Firmware update by plain HTTP POST of a .bin file.
 *
 * This replaces the previous scheme, in which the camera asked the host for the
 * next chunk over the json protocol and gave up after a fixed number of retries.
 * That inverted the normal direction of control, needed a bespoke implementation in
 * every client, and failed in ways the user could not act on.  Here the browser
 * simply uploads the image; flow control is TCP's problem, and a failed upload
 * leaves the running partition untouched.
 */
static esp_err_t ota_post_handler(httpd_req_t* req)
{
	char buf[OTA_RX_CHUNK];
	esp_err_t ret;
	esp_ota_handle_t ota_handle = 0;
	const esp_partition_t* update_partition;
	int received;
	int remaining = req->content_len;

	if (remaining <= 0) {
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty upload");
		return ESP_FAIL;
	}

	update_partition = esp_ota_get_next_update_partition(NULL);
	if (update_partition == NULL) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OTA partition");
		return ESP_FAIL;
	}

	if (remaining > (int) update_partition->size) {
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Image larger than partition");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA start: %d bytes -> partition at 0x%x", remaining,
	         (unsigned int) update_partition->address);

	ret = esp_ota_begin(update_partition, remaining, &ota_handle);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_begin failed (%d)", ret);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not begin update");
		return ESP_FAIL;
	}

	ota_active = true;

	while (remaining > 0) {
		received = httpd_req_recv(req, buf, (remaining < OTA_RX_CHUNK) ? remaining : OTA_RX_CHUNK);
		if (received <= 0) {
			if (received == HTTPD_SOCK_ERR_TIMEOUT) continue;
			ESP_LOGE(TAG, "OTA receive failed");
			esp_ota_abort(ota_handle);
			ota_active = false;
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Upload interrupted");
			return ESP_FAIL;
		}

		ret = esp_ota_write(ota_handle, buf, received);
		if (ret != ESP_OK) {
			ESP_LOGE(TAG, "esp_ota_write failed (%d)", ret);
			esp_ota_abort(ota_handle);
			ota_active = false;
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Flash write failed");
			return ESP_FAIL;
		}

		remaining -= received;
	}

	// esp_ota_end validates the image; a truncated or corrupt upload is rejected
	// here and the currently running firmware is left as the boot target
	ret = esp_ota_end(ota_handle);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_end failed (%d)", ret);
		ota_active = false;
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Image failed validation");
		return ESP_FAIL;
	}

	ret = esp_ota_set_boot_partition(update_partition);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%d)", ret);
		ota_active = false;
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not set boot partition");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA complete - restarting");
	httpd_resp_set_type(req, "application/json");
	httpd_resp_sendstr(req, "{\"status\":\"ok\",\"restarting\":true}");

	// Give the response time to reach the browser before the reset
	vTaskDelay(pdMS_TO_TICKS(1000));
	esp_restart();

	return ESP_OK;
}


/**
 * Bounce unknown URLs to the UI.  Operating systems fetch a known probe URL right
 * after joining a network; a 302 to our root is what makes the phone or laptop
 * offer to open the page by itself.
 */
static esp_err_t redirect_handler(httpd_req_t* req, httpd_err_code_t err)
{
	char location[40];
	net_info_t* net_infoP = (*net_get_info)();

	(void) err;   // every 404 gets the same treatment

	// cur_ip_addr index 3 holds the first octet (see ps_utilities)
	snprintf(location, sizeof(location), "http://%d.%d.%d.%d/",
	         net_infoP->cur_ip_addr[3], net_infoP->cur_ip_addr[2],
	         net_infoP->cur_ip_addr[1], net_infoP->cur_ip_addr[0]);

	httpd_resp_set_status(req, "302 Found");
	httpd_resp_set_hdr(req, "Location", location);
	httpd_resp_send(req, NULL, 0);

	return ESP_OK;
}
