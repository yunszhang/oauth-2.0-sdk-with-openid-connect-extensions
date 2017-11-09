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


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;


/**
 * Tests the client credentials grant.
 */
public class ClientCredentialsGrantTest extends TestCase {


	public void testConstructor() {

		ClientCredentialsGrant grant = new ClientCredentialsGrant();
		assertEquals(GrantType.CLIENT_CREDENTIALS, grant.getType());

		Map<String,String> params = grant.toParameters();
		assertEquals("client_credentials", params.get("grant_type"));
		assertEquals(1, params.size());
	}


	public void testParse()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "client_credentials");

		ClientCredentialsGrant grant = ClientCredentialsGrant.parse(params);
		assertEquals(GrantType.CLIENT_CREDENTIALS, grant.getType());
	}


	public void testParseMissingGrantType() {

		try {
			ClientCredentialsGrant.parse(new HashMap<String, String>());
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing \"grant_type\" parameter", e.getErrorObject().getDescription());
		}
	}


	public void testParseInvalidGrantType(){

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "invalid-grant");

		try {
			ClientCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
			assertEquals("Unsupported grant type: The \"grant_type\" must be client_credentials", e.getErrorObject().getDescription());
		}
	}
}
