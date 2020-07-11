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

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

/**
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
     "access_token": "G5kXH2wHvUra0sHlDy1iTkDJgsgUO1bN",
     "token_type": "Bearer",
     "refresh_token": "4bwc0ESC_IAhflf-ACC_vjD_ltc11ne-8gFPfA2Kx16",
     "expires_in": 120,
     "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzcyNiJ9.eyJpc3MiOiJo
       dHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIs
       ImF1ZCI6InM2QmhkUmtxdDMiLCJlbWFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb20i
       LCJleHAiOjE1Mzc4MTk4MDMsImlhdCI6MTUzNzgxOTUwM30.aVq83mdy72ddIFVJ
       LjlNBX-5JHbjmwK-Sn9Mir-blesfYMceIOw6u4GOrO_ZroDnnbJXNKWAg_dxVynv
       MHnk3uJc46feaRIL4zfHf6Anbf5_TbgMaVO8iczD16A5gNjSD7yenT5fslrrW-NU
       _vtmi0s1puoM4EmSaPXCR19vRJyWuStJiRHK5yc3BtBlQ2xwxH1iNP49rGAQe_LH
       fW1G74NY5DaPv-V23JXDNEIUTY-jT-NbbtNHAxnhNPyn8kcO2WOoeIwANO9BfLF1
       EFWtjGPPMj6kDVrikec47yK86HArGvsIIwk1uExynJIv_tgZGE0eZI7MtVb2UlCw
       DQrVlg"
    }
 * </pre>
 *
 * <p>
 */
@Immutable
public class CIBASuccessfulTokenResponse extends CIBAAuthorizationResponse implements SuccessResponse {

	@Override
	public boolean indicatesSuccess() {

		return true;
	}

	/**
	 * 
	 * @param accessToken
	 * @param authReqId
	 */
	public CIBASuccessfulTokenResponse(AccessToken accessToken, String authReqId) {
		super();

		if (accessToken == null) {
			throw new IllegalArgumentException("The access_token must not be null");
		}

		if (authReqId == null) {
			throw new IllegalArgumentException("The auth_req_id must not be null");
		}

		this.accessToken = accessToken;
		this.authReqId = authReqId;
	}

	/**
	 * required) The access token returned after successful authorization
	 */
	private final AccessToken accessToken;

	/**
	 * (required) his is a unique identifier to identify the authentication request
	 * made by the Client. It MUST contain sufficient entropy (a minimum of 128 bits
	 * while 160 bits is recommended) to make brute force guessing or forgery of a
	 * valid auth_req_id computationally infeasible - the means of achieving this
	 * are implementation specific, with possible approaches including secure
	 * pseudorandom number generation or cryptographically secured self-contained
	 * tokens
	 */
	private final String authReqId;

	/**
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

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
	 * Parses an Client Initiated Backchannel authorization response from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The Client Initiated Backchannel Authorization response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a Client
	 *                        Initiated Backchannel Authorization response.
	 */
	public static CIBASuccessfulTokenResponse parse(JSONObject jsonObject)
			throws ParseException {
		String authReqId = jsonObject.get("access_token").toString();
		AccessToken accessToken = AccessToken.parse(jsonObject);
		return new CIBASuccessfulTokenResponse(accessToken, authReqId);
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
	public static CIBASuccessfulTokenResponse parse(final HTTPResponse httpResponse) throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		return (CIBASuccessfulTokenResponse) parse(jsonObject);
	}

	/**
	 * Gets the access token
	 * 
	 * @return the access token
	 */
	public AccessToken getAccessToken() {
		return accessToken;
	}

	/**
	 * Gets the Authentication request id
	 * 
	 * @return the Authentication request id
	 */
	public String getAuthReqId() {
		return authReqId;
	}
}
