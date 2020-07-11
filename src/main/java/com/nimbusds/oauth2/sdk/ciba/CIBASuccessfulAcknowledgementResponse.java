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

import javax.annotation.Nonnull;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

/**
 * If the Authentication Request is validated as per Section Authentication
 * Request Validation, the OpenID Provider will return an HTTP 200 OK response
 * to the Client to indicate that the authentication request has been accepted
 * and it is going to be processed. The body of this response will contain:
 *
 * <p>
 * Example HTTP response:
 *
 * <pre>
 *                       
    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
      "expires_in": 120,
      "interval": 2
    }
 * </pre>
 *
 * <p>
 */
@Immutable
public class CIBASuccessfulAcknowledgementResponse extends CIBAAuthorizationResponse implements SuccessResponse {

	/**
	 * (required). This is a unique identifier to identify the authentication
	 * request made by the Client. It MUST contain sufficient entropy (a minimum of
	 * 128 bits while 160 bits is recommended) to make brute force guessing or
	 * forgery of a valid auth_req_id computationally infeasible - the means of
	 * achieving this are implementation specific, with possible approaches
	 * including secure pseudorandom number generation or cryptographically secured
	 * self-contained tokens. The OpenID Provider MUST restrict the characters used
	 * to 'A'-'Z', 'a'-'z', '0'-'9', '.', '-' and '_', to reduce the chance of the
	 * client incorrectly decoding or re-encoding the auth_req_id; this character
	 * set was chosen to allow the server to use unpadded base64url if it wishes.
	 * The identifier MUST be treated as opaque by the client.
	 */
	private final String authReqId;
	/**
	 * (required). A JSON number with a positive integer value indicating the
	 * expiration time of the "auth_req_id" in seconds since the authentication
	 * request was received. A Client calling the token endpoint with an expired
	 * auth_req_id will receive an error.
	 */
	private final int expiresIn;
	/**
	 * (optional). A JSON number with a positive integer value indicating the
	 * minimum amount of time in seconds that the Client MUST wait between polling
	 * requests to the token endpoint. This parameter will only be present if the
	 * Client is registered to use the Poll or Ping modes. If no value is provided,
	 * clients MUST use 5 as the default value.
	 */
	private Integer interval;

	/**
	 * Creates a new successful acknowledgement response
	 * 
	 * @param authentication request id {@code auth_req_id}
	 * @param expires        in positive integer {@code expires_in}
	 */
	public CIBASuccessfulAcknowledgementResponse(@Nonnull final String authReqId, final int expiresIn) {
		super();

		if (authReqId == null) {
			throw new IllegalArgumentException("authReqId must not be null");
		}

		this.authReqId = authReqId;

		if (expiresIn < 0) {
			throw new IllegalArgumentException("expiresIn must be positive integer");
		}
		this.expiresIn = expiresIn;
	}

	/**
	 * Creates a new successful acknowledgement response
	 * 
	 * @param authentication request id {@code auth_req_id}
	 * @param expires        in positive integer {@code expires_in}
	 * @param positive       integer - minimum amount of wait between polling
	 *                       requests
	 */
	public CIBASuccessfulAcknowledgementResponse(final String authReqId, final int expiresIn, final Integer interval) {
		this(authReqId, expiresIn);

		if (interval != null && interval.intValue() < 0) {
			throw new IllegalArgumentException("interval must be positive integer");
		}
		this.interval = interval;
	}

	@Override
	public boolean indicatesSuccess() {

		return true;
	}

	/**
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		o.put("auth_req_id", authReqId);
		o.put("expires_in", expiresIn);
		o.put("interval", interval);
		return o;
	}

	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);

		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		httpResponse.setContent(toJSONObject().toString());

		return httpResponse;
	}

	/**
	 * Parses an Client Initiated Backchannel acknowledgement authorization response
	 * from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The Client Initiated Backchannel Authorization response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a Client
	 *                        Initiated Backchannel Authorization response.
	 */
	public static CIBASuccessfulAcknowledgementResponse parse(final JSONObject jsonObject) throws ParseException {

		String authReqId = (String) jsonObject.get("auth_req_id");
		Number expiresIn = jsonObject.getAsNumber("expires_in");
		Number interval = jsonObject.getAsNumber("interval");

		int expiresInInteger = -1;
		Integer intervalInt = null;
		try {
			if (expiresIn != null)
				expiresInInteger = expiresIn.intValue();
			if (expiresInInteger < 0) {
				String msg = "The \"expires_in\" parameter must be positive integer";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
		} catch (NumberFormatException e) {
			String msg = "The \"expires_in\" parameter must be an integer";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		if (interval != null) {
			try {
				intervalInt = interval.intValue();
				if (intervalInt < 0) {
					String msg = "The \"interval\" parameter must be positive integer";
					throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
				}
			} catch (NumberFormatException e) {
				String msg = "The \"interval\" parameter must be an integer";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
		}
		return new CIBASuccessfulAcknowledgementResponse(authReqId, expiresInInteger, intervalInt);
	}

	/**
	 * Parses a Client Initiated Backchannel Authentication response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The Client Initiated Backchannel Authentication response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a Client
	 *                        Initiated Backchannel Authentication response.
	 */
	public static CIBASuccessfulAcknowledgementResponse parse(final HTTPResponse httpResponse) throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		return (CIBASuccessfulAcknowledgementResponse) parse(jsonObject);
	}

	/**
	 * Gets the the minimum amount of time in seconds that the Client MUST wait
	 * between polling requests to the token endpoint.
	 * 
	 * @return the interval
	 */
	public Integer getInterval() {
		return interval;
	}

	/**
	 * * Gets the the minimum amount of time in seconds that the Client MUST wait
	 * between polling requests to
	 * 
	 * @param interval - the polling interval
	 */
	public void setInterval(final Integer interval) {
		this.interval = interval;
	}

	/**
	 * The authentication request identifier
	 * 
	 * @return the authentication request identifier
	 */
	public String getAuthReqId() {
		return authReqId;
	}

	/**
	 * The expiration time of the "auth_req_id" in seconds since the authentication
	 * request was received
	 * 
	 * @return The expiration time
	 */
	public int getExpiresIn() {
		return expiresIn;
	}
}
