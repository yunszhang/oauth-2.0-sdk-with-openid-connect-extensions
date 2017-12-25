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

package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;


/**
 * UserInfo response test.
 */
public class UserInfoResponseTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		UserInfoSuccessResponse successResponse = new UserInfoSuccessResponse(new UserInfo(new Subject("alice")));

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

		assertTrue(userInfoResponse.indicatesSuccess());

		successResponse = userInfoResponse.toSuccessResponse();

		assertEquals(new Subject("alice"), successResponse.getUserInfo().getSubject());
	}


	public void testParseBearerTokenError()
		throws Exception {

		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

		assertFalse(userInfoResponse.indicatesSuccess());

		errorResponse = userInfoResponse.toErrorResponse();

		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());
	}
}
