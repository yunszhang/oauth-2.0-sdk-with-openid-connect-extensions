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

package com.nimbusds.oauth2.sdk.ciba;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

/**
 * OAuth 2.0 Backchannel Authentication Flow Grant specific errors.
 *
 * <p>
 * Related specifications:
 *
 * <ul>
 * <li>OAuth 2.0 Backchannel Authentication Flow Grant
 * (openid-client-initiated-backchannel-authentication-core-03)
 * </ul>
 */
public final class CIBAAuthorizationGrantError {

	/**
	 * The authorization request is still pending as the end-user hasn't yet been
	 * authenticated.
	 */
	public static final ErrorObject AUTHORIZATION_PENDING = new ErrorObject("authorization_pending",
			"Authorization pending", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * A variant of "authorization_pending", the authorization request is still
	 * pending and polling should continue, but the interval MUST be increased by at
	 * least 5 seconds for this and all subsequent requests.
	 */
	public static final ErrorObject SLOW_DOWN = new ErrorObject("slow_down", "Slow down", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The auth_req_id has expired. The Client will need to make a new
	 * Authentication Request.
	 */
	public static final ErrorObject EXPIRED_TOKEN = new ErrorObject("expired_token", "Expired token",
			HTTPResponse.SC_BAD_REQUEST);

	/**
	 * If the auth_req_id is invalid or was issued to another Client.
	 */
	public static final ErrorObject INVALID_GRANT = new ErrorObject("invalid_grant", "Invalid grant",
			HTTPResponse.SC_BAD_REQUEST);

	/**
	 * If a Client continually polls quicker than the interval, the OP may return
	 * invalid_request error
	 */
	public static final ErrorObject INVALID_REQUEST = new ErrorObject("invalid_request", "Invalid request",
			HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The Client is not authorized as it is configured in Push Mode
	 */
	public static final ErrorObject UNAUTHORIZED_CLIENT =
		new ErrorObject("unauthorized_client", "Unauthorized client", HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * Prevents public instantiation.
	 */
	private CIBAAuthorizationGrantError() {

	}
}
