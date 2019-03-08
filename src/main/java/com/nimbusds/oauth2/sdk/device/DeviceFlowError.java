/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk.device;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

/**
 * OAuth 2.0 Device Flow specific errors.
 *
 * <p>
 * Related specifications:
 *
 * <ul>
 * <li>OAuth 2.0 Device Flow for Browserless and Input Constrained Devices
 * (draft-ietf-oauth-device-flow-14)
 * </ul>
 */
public final class DeviceFlowError {

	/**
	 * The authorization request is still pending as the end user hasn't yet
	 * completed the user interaction steps (Section 3.3). The client SHOULD repeat
	 * the Access Token Request to the token endpoint (a process known as polling).
	 * Before each new request the client MUST wait at least the number of seconds
	 * specified by the "interval" parameter of the Device Authorization Response
	 * (see Section 3.2), or 5 seconds if none was provided, and respect any
	 * increase in the polling interval required by the "slow_down" error.
	 */
	public static final ErrorObject AUTHORIZATION_PENDING = new ErrorObject("authorization_pending",
	                "Authorization pending", HTTPResponse.SC_BAD_REQUEST);


	/**
	 * A variant of "authorization_pending", the authorization request is still
	 * pending and polling should continue, but the interval MUST be increased by 5
	 * seconds for this and all subsequent requests.
	 */
	public static final ErrorObject SLOW_DOWN = new ErrorObject("slow_down", "Slow down",
	                HTTPResponse.SC_BAD_REQUEST);


	/**
	 * The "device_code" has expired and the device flow authorization session has
	 * concluded. The client MAY commence a new Device Authorization Request but
	 * SHOULD wait for user interaction before restarting to avoid unnecessary
	 * polling.
	 */
	public static final ErrorObject EXPIRED_TOKEN = new ErrorObject("expired_token", "Expired token",
	                HTTPResponse.SC_BAD_REQUEST);


	/**
	 * Prevents public instantiation.
	 */
	private DeviceFlowError() {

	}
}
