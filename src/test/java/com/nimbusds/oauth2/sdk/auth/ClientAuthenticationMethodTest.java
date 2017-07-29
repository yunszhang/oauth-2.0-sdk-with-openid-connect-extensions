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


import junit.framework.TestCase;


/**
 * Tests client authentication method class.
 */
public class ClientAuthenticationMethodTest extends TestCase {


	public void testConstants() {
	
		assertEquals("client_secret_basic", ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertEquals("client_secret_post", ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
		assertEquals("client_secret_jwt", ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
		assertEquals("private_key_jwt", ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
		assertEquals("tls_client_auth", ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue());
		assertEquals("pub_key_tls_client_auth", ClientAuthenticationMethod.PUB_KEY_TLS_CLIENT_AUTH.getValue());
		assertEquals("none", ClientAuthenticationMethod.NONE.getValue());
	}


	public void testGetDefault() {

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, 
		             ClientAuthenticationMethod.getDefault());
	}


	public void testParse() {

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.parse("client_secret_basic"));
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.parse("client_secret_post"));
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, ClientAuthenticationMethod.parse("client_secret_jwt"));
		assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.parse("private_key_jwt"));
		assertEquals(ClientAuthenticationMethod.TLS_CLIENT_AUTH, ClientAuthenticationMethod.parse("tls_client_auth"));
		assertEquals(ClientAuthenticationMethod.PUB_KEY_TLS_CLIENT_AUTH, ClientAuthenticationMethod.parse("pub_key_tls_client_auth"));
		assertEquals(ClientAuthenticationMethod.NONE, ClientAuthenticationMethod.parse("none"));
	}


	public void testParseNull() {

		try {
			ClientAuthenticationMethod.parse(null);
			fail();
		} catch (NullPointerException e) {
			//  ok
		}
	}


	public void testParseEmptyValue() {

		try {
			ClientAuthenticationMethod.parse("");
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}
	}
}
