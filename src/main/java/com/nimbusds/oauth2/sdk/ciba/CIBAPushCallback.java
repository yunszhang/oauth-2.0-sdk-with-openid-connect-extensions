/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import java.net.URI;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * CIBA push callback to the client notification endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>TODO
 * </ul>
 */
public abstract class CIBAPushCallback extends ProtectedResourceRequest {
	
	
	/**
	 * The CIBA request ID.
	 */
	private final AuthRequestID authRequestID;
	
	
	/**
	 * Creates a new CIBA push callback.
	 *
	 * @param endpoint      The client notification endpoint. Must not be
	 *                      {@code null}.
	 * @param accessToken   The client notification token. Must not be
	 *                      {@code null}.
	 * @param authRequestID The CIBA request ID. Must not be {@code null}.
	 */
	public CIBAPushCallback(final URI endpoint,
				final BearerAccessToken accessToken,
				final AuthRequestID authRequestID) {
		super(endpoint, accessToken);
		
		if (authRequestID == null) {
			throw new IllegalArgumentException("The auth_req_id must not be null");
		}
		this.authRequestID = authRequestID;
	}
	
	
	/**
	 * Checks if the callback indicates success.
	 *
	 * @return {@code true} if the callback indicates success, else
	 *         {@code false}.
	 */
	public abstract boolean indicatesSuccess();
	
	
	/**
	 * Returns the CIBA request ID.
	 *
	 * @return The CIBA request ID.
	 */
	public AuthRequestID getAuthRequestID() {
		
		return authRequestID;
	}
	
	
	/**
	 * Casts this CIBA push callback to token delivery.
	 *
	 * @return The CIBA token push delivery.
	 */
	public CIBATokenDelivery toTokenDelivery() {
		
		return (CIBATokenDelivery) this;
	}
	
	
	/**
	 * Casts this CIBA push callback to an error delivery.
	 *
	 * @return The CIBA error push delivery.
	 */
	public CIBAErrorDelivery toErrorDelivery() {
		
		return (CIBAErrorDelivery) this;
	}
	
	
	/**
	 * Parses a CIBA push callback from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The CIBA token or error push delivery.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        CIBA push callback.
	 */
	public static CIBAPushCallback parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		
		if (jsonObject.containsKey("error")) {
			return CIBAErrorDelivery.parse(httpRequest);
		} else {
			return CIBATokenDelivery.parse(httpRequest);
		}
	}
}
