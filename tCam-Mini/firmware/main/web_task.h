/*
 * Web Server Task
 *
 * Serves the on-camera user interface.  The camera becomes self-contained: joining
 * its access point (or browsing to it on the local network) is enough to get a full
 * viewer and configuration UI with no application to install.
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
#ifndef WEB_TASK_H
#define WEB_TASK_H

#include <stdbool.h>


//
// Web Task Constants
//

// Port the UI is served on.  80 so a bare address works with no port suffix.
#define WEB_PORT 80

// Stack for the server task.  Command handling runs cJSON in this context, so this
// is well above the esp_http_server default.
#define WEB_TASK_STACK_SIZE 6144


//
// Web Task API
//

/**
 * Start the web server.  Blocks briefly waiting for the network interface to come
 * up, then runs until the system is reset.
 */
void web_task();

/**
 * True while an OTA upload is in progress (used to suppress streaming).
 */
bool web_ota_in_progress();

#endif /* WEB_TASK_H */
