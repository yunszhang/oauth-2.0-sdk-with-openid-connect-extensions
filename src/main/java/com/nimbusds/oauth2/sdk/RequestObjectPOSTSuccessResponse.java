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

package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.util.Date;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Request object POST success response.
 *
 * <p>Example request object POST success response:
 *
 * <pre>
 * HTTP/1.1 201 Created
 * Date: Tue, 2 May 2017 15:22:31 GMT
 * Content-Type: application/json
 *
 * {
 *   "iss"         : "https://c2id.com",
 *   "aud"         : "s6bhdrkqt3",
 *   "request_uri" : "urn:requests:aashoo1Ooj6ahc5C",
 *   "exp"         : 1493738581
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile,
 *         section 7.
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (draft-ietf-oauth-jwsreq-17).
 * </ul>
 */
@Immutable
public final class RequestObjectPOSTSuccessResponse extends RequestObjectPOSTResponse implements SuccessResponse {
	
	
	/**
	 * The issuer.
	 */
	private final Issuer iss;
	
	
	/**
	 * The audience (client ID).
	 */
	private final Audience aud;
	
	
	/**
	 * The request URI.
	 */
	private final URI requestURI;
	
	
	/**
	 * The request URI expiration time.
	 */
	private final Date exp;
	
	
	/**
	 * Creates a new request object POST success response.
	 *
	 * @param iss        The issuer. Must not be {@code null}.
	 * @param aud        The audience (the intended client IDMust not be
	 *                   {@code null}.).
	 * @param requestURI The request URI. Must not be {@code null}.
	 * @param exp        The request URI expiration time. Must not be
	 *                   {@code null}.
	 */
	public RequestObjectPOSTSuccessResponse(final Issuer iss,
						final Audience aud,
						final URI requestURI,
						final Date exp) {
		if (iss == null) {
			throw new IllegalArgumentException("The issuer must not be null");
		}
		this.iss = iss;
		
		if (aud == null) {
			throw new IllegalArgumentException("The audience must not be null");
		}
		this.aud = aud;
		
		if (requestURI == null) {
			throw new IllegalArgumentException("The request URI must not be null");
		}
		this.requestURI = requestURI;
		
		if (exp == null) {
			throw new IllegalArgumentException("The request URI expiration time must not be null");
		}
		this.exp = exp;
	}
	
	
	/**
	 * Returns the issuer.
	 *
	 * @return The issuer.
	 */
	public Issuer getIssuer() {
		return iss;
	}
	
	
	/**
	 * Returns the audience (the intended client ID).
	 *
	 * @return The audience.
	 */
	public Audience getAudience() {
		return aud;
	}
	
	
	/**
	 * Returns the request URI.
	 *
	 * @return The request URI.
	 */
	public URI getRequestURI() {
		return requestURI;
	}
	
	
	/**
	 * Returns the expiration time.
	 *
	 * @return The expiration time.
	 */
	public Date getExpirationTime() {
		return exp;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	/**
	 * Returns a JSON object representation of this request object POST
	 * success response.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject jsonObject = new JSONObject();
		
		jsonObject.put("iss", iss.getValue());
		jsonObject.put("aud", aud.getValue());
		jsonObject.put("request_uri", requestURI.toString());
		jsonObject.put("exp", DateUtils.toSecondsSinceEpoch(exp));
		
		return jsonObject;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_CREATED);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setContent(toJSONObject().toJSONString());
		return httpResponse;
	}
	
	
	/**
	 * Parses a request object POST success response from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The request object POST success response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        request object POST success response.
	 */
	public static RequestObjectPOSTSuccessResponse parse(final JSONObject jsonObject)
		throws ParseException {
		
		return new RequestObjectPOSTSuccessResponse(
			new Issuer(JSONObjectUtils.getString(jsonObject, "iss")),
			new Audience(JSONObjectUtils.getString(jsonObject, "aud")),
			JSONObjectUtils.getURI(jsonObject, "request_uri"),
			DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(jsonObject, "exp")));
	}
	
	
	/**
	 * Parses a request object POST success response from the specified
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The request object POST success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        request object POST success response.
	 */
	public static RequestObjectPOSTSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_CREATED, HTTPResponse.SC_OK);
		return parse(httpResponse.getContentAsJSONObject());
	}
}
