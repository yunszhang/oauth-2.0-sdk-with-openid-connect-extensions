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

package com.nimbusds.oauth2.sdk.auth;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests client secret basic authentication.
 */
public class ClientSecretPostTest extends TestCase {


	public void testSerializeAndParse()
		throws ParseException {

		// Test vectors from OAuth 2.0 RFC

		final String id = "s6BhdRkqt3";
		final String pw = "7Fjfp0ZBr1KtDRbnfVdmIw";

		ClientID clientID = new ClientID(id);
		Secret secret = new Secret(pw);

		ClientSecretPost csp = new ClientSecretPost(clientID, secret);

		assertTrue(csp instanceof PlainClientSecret);

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, csp.getMethod());

		assertEquals(id, csp.getClientID().getValue());
		assertEquals(pw, csp.getClientSecret().getValue());

		Map<String,List<String>> params = csp.toParameters();

		assertEquals(Collections.singletonList(id), params.get("client_id"));
		assertEquals(Collections.singletonList(pw), params.get("client_secret"));
		assertEquals(2, params.size());

		csp = ClientSecretPost.parse(params);

		assertEquals(id, csp.getClientID().toString());
		assertEquals(pw, csp.getClientSecret().getValue());
	}
	
	
	public void testParse_missingClientID() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_secret", Collections.singletonList("secret"));
		try {
			ClientSecretPost.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Malformed client secret post authentication: Missing \"client_id\" parameter", e.getMessage());
		}
	}
	
	
	public void testParse_missingClientSecret() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList("alice"));
		try {
			ClientSecretPost.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Malformed client secret post authentication: Missing \"client_secret\" parameter", e.getMessage());
		}
	}
}
