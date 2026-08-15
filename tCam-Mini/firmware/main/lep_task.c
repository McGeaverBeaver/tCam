/*
 * Lepton Task
 *
 * Contains functions to initialize the Lepton and then sampling images from it,
 * making those available to other tasks through a shared buffer and event
 * interface.
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
 * along with firecam.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
#include <stdbool.h>
#include "ctrl_task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lep_task.h"
#include "rsp_task.h"
#include "lepton_utilities.h"
#include "cci.h"
#include "vospi.h"
#include "sys_utilities.h"
#include "system_config.h"


//
// LEP Task constants
//

// Uncomment to log image acquisition timestamps
//#define LOG_ACQ_TIMESTAMP

// States
#define STATE_INIT      0
#define STATE_RUN       1
#define STATE_RE_INIT   2
#define STATE_ERROR     3


//
// LEP Task variables
//
static const char* TAG = "lep_task";

static int lep_brd_type;
static int lep_if_type;



//
// LEP Task Forward Declarations for internal functions
//
static bool wait_for_vsync(int vsync_pin);



//
// LEP Task API
//

/**
 * This task drives the Lepton camera interface.
 *   Note: GPIO signals must be initialized prior to task start.
 */
void lep_task()
{
	int lep_csn_pin;
	int lep_vsync_pin;
	int task_state = STATE_INIT;
	int rsp_buf_index = 0;
	int vsync_count = 0;
	int vsync_timeout_count = 0;
	int sync_fail_count = 0;
	int reset_fail_count = 0;
	int64_t vsyncDetectedUsec;
	
	ESP_LOGI(TAG, "Start task");
	
	// Attempt to initialize the CCI interface
	if (!cci_init()) {
		ESP_LOGE(TAG, "Lepton CCI initialization failed");
		rsp_set_cam_info_msg(RSP_INFO_INT_ERROR, "(FATAL) Lepton CCI initialization failed");
		vTaskDelete(NULL);
	}
	
	// Attempt to initialize the VoSPI interface
	ctrl_get_if_mode(&lep_brd_type, &lep_if_type);
	if (lep_brd_type == CTRL_BRD_ETH_TYPE) {
		lep_csn_pin = BRD_E_LEP_CSN_IO;
		lep_vsync_pin = BRD_E_LEP_VSYNC_IO;
	} else {
		lep_csn_pin = BRD_W_LEP_CSN_IO;
		lep_vsync_pin = BRD_W_LEP_VSYNC_IO;
	}
	if (vospi_init(lep_csn_pin) != ESP_OK) {
		ESP_LOGE(TAG, "Lepton VoSPI initialization failed");
		ctrl_set_fault_type(CTRL_FAULT_LEP_VOSPI);
		vTaskDelete(NULL);
	}

	while (true) {
		switch (task_state) {
			case STATE_INIT:  // After power-on reset
				if (lepton_init()) {
					task_state = STATE_RUN;
				} else {
					ESP_LOGE(TAG, "Lepton CCI initialization failed");
					ctrl_set_fault_type(CTRL_FAULT_LEP_CCI);
					
					task_state = STATE_ERROR;
					// Use reset_fail_count as a timer
					reset_fail_count = LEP_RESET_FAIL_RETRY_SECS;
				}
				break;
			
			case STATE_RUN:   // Initialized and running
				// Wait for vsync to be asserted.  This is deliberately a busy-wait
				// because the VoSPI segment has to be read promptly once vsync goes
				// high, but it is now bounded - see wait_for_vsync().
				if (!wait_for_vsync(lep_vsync_pin)) {
					if (++vsync_timeout_count >= LEP_VSYNC_TIMEOUT_FAULT_LIMIT) {
						vsync_timeout_count = LEP_VSYNC_TIMEOUT_FAULT_LIMIT;
						ESP_LOGE(TAG, "No vsync from Lepton - check that the sensor is seated");
						ctrl_set_fault_type(CTRL_FAULT_LEP_VOSPI);
					}
					// Yield so the rest of the system keeps running and the failure
					// is reportable rather than taking the whole camera down
					vTaskDelay(pdMS_TO_TICKS(100));
					break;
				}
				vsync_timeout_count = 0;
				vsyncDetectedUsec = esp_timer_get_time();
				
				// Attempt to process a segment
				if (vospi_transfer_segment(vsyncDetectedUsec)) {
					// Got image
					vsync_count = 0;
					
					// Copy the frame to the current half of the shared buffer and let rsp_task know
					xSemaphoreTake(rsp_lep_buffer[rsp_buf_index].lep_mutex, portMAX_DELAY);
					vospi_get_frame(&rsp_lep_buffer[rsp_buf_index]);
					xSemaphoreGive(rsp_lep_buffer[rsp_buf_index].lep_mutex);
#ifdef LOG_ACQ_TIMESTAMP
					ESP_LOGI(TAG, "Push into buf %d", rsp_buf_index);
#endif
					if (rsp_buf_index == 0) {
						xTaskNotify(task_handle_rsp, RSP_NOTIFY_LEP_FRAME_MASK_0, eSetBits);
						rsp_buf_index = 1;
					} else {
						xTaskNotify(task_handle_rsp, RSP_NOTIFY_LEP_FRAME_MASK_1, eSetBits);
						rsp_buf_index = 0;
					}
					
					// Clear the resynchronization fault indication if necessary (since we are working again)
					if (sync_fail_count >= LEP_SYNC_FAIL_FAULT_LIMIT) {
						ctrl_set_fault_type(CTRL_FAULT_NONE);
					}
					// Hold fault counters reset while operating
					sync_fail_count = 0;
					reset_fail_count = 0;
					
					vTaskDelay(pdMS_TO_TICKS(30));
				} else {
					// We should see a valid frame every 12 vsync interrupts (one frame period).
					// However, since we may be resynchronizing with the VoSPI stream and our task
					// may be interrupted by other tasks, we give the lepton extra frame periods
					// to start correctly streaming data.  We may still fail when the lepton runs
					// a FFC since that takes a long time.
					if (++vsync_count == 36) {
						vsync_count = 0;
						ESP_LOGI(TAG, "Could not get lepton image");
						
						// Pause to allow resynchronization
						// (Lepton 3.5 data sheet section 4.2.3.3.1 "Establishing/Re-Establishing Sync")
						vTaskDelay(pdMS_TO_TICKS(185));
						
						// Check for too many consecutive resynchronization failures.
						// This should only occur if something has gone wrong.
						if (sync_fail_count++ == LEP_SYNC_FAIL_FAULT_LIMIT) {
							ctrl_set_fault_type(CTRL_FAULT_LEP_SYNC);
							if (reset_fail_count == 0) {
								// Reset the first time
								task_state = STATE_RE_INIT;
							} else {
								ESP_LOGE(TAG, "Could not sync to VoSPI after task reset");
								
								// Possibly permanent error condition
								task_state = STATE_ERROR;
								
								// Use reset_fail_count as a timer
								reset_fail_count = LEP_RESET_FAIL_RETRY_SECS;
							}
						}
					}
				}
				break;
			
			case STATE_RE_INIT:  // Reset and re-init
				ESP_LOGI(TAG,  "Reset Lepton");
				
				// Assert hardware reset
				if (lep_brd_type == CTRL_BRD_ETH_TYPE) {
					gpio_set_level(BRD_E_LEP_RESET_IO, 1);
					vTaskDelay(pdMS_TO_TICKS(10));
					gpio_set_level(BRD_E_LEP_RESET_IO, 0);
				} else {
					gpio_set_level(BRD_W_LEP_RESET_IO, 1);
					vTaskDelay(pdMS_TO_TICKS(10));
					gpio_set_level(BRD_W_LEP_RESET_IO, 0);
				}
				
				// Delay for Lepton internal initialization (max 950 mSec)
    			vTaskDelay(pdMS_TO_TICKS(1000));
    			
    			// Attempt to re-initialize the Lepton
    			if (lepton_init()) {
					task_state = STATE_RUN;
					
					// Note the reset
    				reset_fail_count = 1;
				} else {
					ESP_LOGE(TAG, "Lepton CCI initialization failed");
					ctrl_set_fault_type(CTRL_FAULT_LEP_CCI);
					
					task_state = STATE_ERROR;
					// Use reset_fail_count as a timer
					reset_fail_count = LEP_RESET_FAIL_RETRY_SECS;
				}
				break;
			
			case STATE_ERROR:  // Initialization or re-init failed
				// Do nothing for a good long while
				vTaskDelay(pdMS_TO_TICKS(1000));
				if (--reset_fail_count == 0) {
					// Attempt another reset/re-init
					task_state =  STATE_RE_INIT;
				}
				break;
			
			default:
				task_state = STATE_RE_INIT;
		}
	}
}


//
// LEP Task internal functions
//

/**
 * Spin until the Lepton asserts vsync, or until LEP_VSYNC_TIMEOUT_USEC elapses.
 * Returns true if vsync was seen.
 *
 * The wait is a busy loop on purpose - the VoSPI segment must be read very soon
 * after vsync rises, and sleeping here costs frames.  The deadline is only checked
 * every 256 iterations so the common path stays tight; the cost of noticing a real
 * timeout a few microseconds late is irrelevant next to the 250 mSec budget.
 *
 * Before this was bounded, a camera whose vsync line never asserted (an unseated
 * sensor, a broken trace, a Lepton left in the wrong GPIO mode) would spin here at
 * priority 19 forever, starve the idle task on that core and trip the task
 * watchdog every five seconds with no usable diagnostic.
 */
static bool wait_for_vsync(int vsync_pin)
{
	int64_t start = esp_timer_get_time();
	uint32_t spins = 0;

	while (gpio_get_level((gpio_num_t) vsync_pin) == 0) {
		if ((++spins & 0xFF) == 0) {
			if ((esp_timer_get_time() - start) > LEP_VSYNC_TIMEOUT_USEC) {
				return false;
			}
		}
	}

	return true;
}
