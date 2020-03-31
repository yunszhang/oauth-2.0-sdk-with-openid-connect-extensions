/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.api;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Trust negotiation response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 6.2.2 and 6.4.
 * </ul>
 */
public abstract class TrustNegotiationResponse implements Response {
	
	
	/**
	 * Casts this response to a trust negotiation success response.
	 *
	 * @return The trust negotiation success response.
	 */
	public TrustNegotiationSuccessResponse toSuccessResponse() {
		return (TrustNegotiationSuccessResponse)this;
	}
	
	
	/**
	 * Casts this response to a trust negotiation error response.
	 *
	 * @return The trust negotiation error response.
	 */
	public TrustNegotiationErrorResponse toErrorResponse() {
		return (TrustNegotiationErrorResponse)this;
	}
	
	
	/**
	 * Parses a trust negotiation response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The trust negotiation response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustNegotiationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		if (httpResponse.indicatesSuccess()) {
			return TrustNegotiationSuccessResponse.parse(httpResponse);
		} else {
			return TrustNegotiationErrorResponse.parse(httpResponse);
		}
	}
}
