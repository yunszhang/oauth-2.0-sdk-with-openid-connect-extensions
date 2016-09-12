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

package com.nimbusds.oauth2.sdk.client;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * Tests the client delete request.
 */
public class ClientDeleteRequestTest extends TestCase {


	public void testParseWithMissingAuthorizationHeader()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.DELETE, new URL("https://c2id.com/client-reg/123"));

		try {
			ClientDeleteRequest.parse(httpRequest);

			fail();

		} catch (ParseException e) {

			assertTrue(e.getErrorObject() instanceof BearerTokenError);

			BearerTokenError bte = (BearerTokenError)e.getErrorObject();

			assertEquals(401, bte.getHTTPStatusCode());
			assertNull(bte.getCode());
			assertEquals("Bearer", bte.toWWWAuthenticateHeader());
		}
	}
}
