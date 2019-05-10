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


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;


/**
 * Tests the response mode class.
 */
public class ResponseModeTest extends TestCase {


	public void testConstants() {

		assertEquals("query", ResponseMode.QUERY.getValue());
		assertEquals("fragment", ResponseMode.FRAGMENT.getValue());
		assertEquals("form_post", ResponseMode.FORM_POST.getValue());
		assertEquals("query.jwt", ResponseMode.QUERY_JWT.getValue());
		assertEquals("fragment.jwt", ResponseMode.FRAGMENT_JWT.getValue());
		assertEquals("form_post.jwt", ResponseMode.FORM_POST_JWT.getValue());
		assertEquals("jwt", ResponseMode.JWT.getValue());
	}


	public void testConstructor() {

		ResponseMode mode = new ResponseMode("query");
		assertEquals("query", mode.getValue());
	}


	public void testEquality() {
		
		assertEquals(new ResponseMode("query"), new ResponseMode("query"));
	}


	public void testInequality() {
		
		assertNotEquals(new ResponseMode("fragment"), new ResponseMode("query"));
	}
	
	
	public void testResolve_explicit() {
		
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code", "token")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("id_token")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("token")));
		
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code", "token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("token")));
		
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code")));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code", "token")));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("id_token")));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("token")));
		
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code", "token")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("id_token")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("token")));
		
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code", "token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("token")));
		
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code")));
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code", "token")));
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("id_token")));
		assertEquals(ResponseMode.FORM_POST_JWT, ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("token")));
	}
	
	
	public void testResolve_fromBaseJWTMode() {
		
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code", "token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("id_token")));
		assertEquals(ResponseMode.FRAGMENT_JWT, ResponseMode.resolve(ResponseMode.JWT, new ResponseType("token")));
		assertEquals(ResponseMode.QUERY_JWT, ResponseMode.resolve(ResponseMode.JWT, null));
	}
	
	
	public void testResolve_fromResponseType() {
		
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(null, new ResponseType("code")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(null, new ResponseType("code", "token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(null, new ResponseType("code", "token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(null, new ResponseType("code", "id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(null, new ResponseType("token", "id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(null, new ResponseType("id_token")));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.resolve(null, new ResponseType("token")));
		assertEquals(ResponseMode.QUERY, ResponseMode.resolve(null, null));
	}
}
