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


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.auth.Secret;
import junit.framework.TestCase;


/**
 * Tests the password grant.
 */
public class ResourceOwnerPasswordCredentialsGrantTest extends TestCase {


	public void testConstructor() {

		String username = "alice";
		Secret password = new Secret("secret");
		ResourceOwnerPasswordCredentialsGrant grant = new ResourceOwnerPasswordCredentialsGrant(username, password);
		assertEquals(GrantType.PASSWORD, grant.getType());
		assertEquals(username, grant.getUsername());
		assertEquals(password, grant.getPassword());

		Map<String,List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("password"), params.get("grant_type"));
		assertEquals(Collections.singletonList("alice"), params.get("username"));
		assertEquals(Collections.singletonList("secret"), params.get("password"));
		assertEquals(3, params.size());
	}


	public void testParse()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		ResourceOwnerPasswordCredentialsGrant grant = ResourceOwnerPasswordCredentialsGrant.parse(params);
		assertEquals(GrantType.PASSWORD, grant.getType());
		assertEquals("alice", grant.getUsername());
		assertEquals("secret", grant.getPassword().getValue());
	}


	public void testParseMissingGrantType() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing grant_type parameter", e.getErrorObject().getDescription());
		}
	}


	public void testParseUnsupportedGrantType() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("invalid_grant"));
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
			assertEquals("Unsupported grant type: The grant_type must be password", e.getErrorObject().getDescription());
		}
	}


	public void testParseMissingUsername() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("password", Collections.singletonList("secret"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty username parameter", e.getErrorObject().getDescription());
		}
	}


	public void testParseMissingPassword() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("username", Collections.singletonList("alice"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty password parameter", e.getErrorObject().getDescription());
		}
	}


	public void testEquality() {

		assertTrue(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))
			.equals(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))));
	}


	public void testInequality() {

		assertFalse(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))
			.equals(new ResourceOwnerPasswordCredentialsGrant("bob", new Secret("secret"))));

		assertFalse(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))
			.equals(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("no-secret"))));
	}
}
