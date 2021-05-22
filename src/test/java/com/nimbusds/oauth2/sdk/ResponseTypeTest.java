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


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;


public class ResponseTypeTest extends TestCase {
	
	
	public void testConstants() {
		
		// OAuth 2.0
		assertEquals(new ResponseType("code"), ResponseType.CODE);
		assertEquals(new ResponseType("token"), ResponseType.TOKEN);
		
		// OpenID Connect implicit
		assertEquals(new ResponseType("id_token", "token"), ResponseType.IDTOKEN_TOKEN);
		assertEquals(new ResponseType("id_token"), ResponseType.IDTOKEN);
		
		// OpenID Connect hybrid
		assertEquals(new ResponseType("code", "id_token"), ResponseType.CODE_IDTOKEN);
		assertEquals(new ResponseType("code", "id_token", "token"), ResponseType.CODE_IDTOKEN_TOKEN);
		assertEquals(new ResponseType("code", "token"), ResponseType.CODE_TOKEN);
	}
	
	
	public void testConstantsAreNotModifiable() {
		
		for (ResponseType rt: Arrays.asList(
			ResponseType.CODE,
			ResponseType.TOKEN,
			ResponseType.IDTOKEN_TOKEN,
			ResponseType.IDTOKEN,
			ResponseType.CODE_IDTOKEN,
			ResponseType.CODE_IDTOKEN_TOKEN,
			ResponseType.CODE_TOKEN
		)) {
			try {
				rt.add(ResponseType.Value.CODE);
				fail();
			} catch (UnsupportedOperationException e) {
				assertNull(e.getMessage());
			}
			
			try {
				rt.remove(ResponseType.Value.CODE);
				fail();
			} catch (UnsupportedOperationException e) {
				assertNull(e.getMessage());
			}
			
			try {
				rt.clear();
				fail();
			} catch (UnsupportedOperationException e) {
				assertNull(e.getMessage());
			}
			
			try {
				rt.removeAll(Collections.singleton(ResponseType.Value.CODE));
				fail();
			} catch (UnsupportedOperationException e) {
				assertNull(e.getMessage());
			}
			
			try {
				rt.addAll(Collections.singleton(ResponseType.Value.CODE));
				fail();
			} catch (UnsupportedOperationException e) {
				assertNull(e.getMessage());
			}
			
			try {
				rt.retainAll(Collections.singleton(ResponseType.Value.CODE));
				fail();
			} catch (UnsupportedOperationException e) {
				assertNull(e.getMessage());
			}
		}
	}
	
	
	public void testValueConstants() {

		assertEquals("code", ResponseType.Value.CODE.toString());
		assertEquals("token", ResponseType.Value.TOKEN.toString());
	}


	public void testVarargConstructor() {

		ResponseType rt = new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN);

		assertTrue(rt.contains(ResponseType.Value.CODE));
		assertTrue(rt.contains("code"));
		assertTrue(rt.contains(OIDCResponseTypeValue.ID_TOKEN));
		assertTrue(rt.contains("id_token"));
		assertEquals(2, rt.size());

		assertFalse(rt.contains(ResponseType.Value.TOKEN));
		assertFalse(rt.contains("token"));
	}


	public void testStringVarargConstructor() {

		ResponseType rt = new ResponseType("code", "id_token");

		assertTrue(rt.contains(ResponseType.Value.CODE));
		assertTrue(rt.contains(OIDCResponseTypeValue.ID_TOKEN));
		assertEquals(2, rt.size());
	}


	public void testStringVarargConstructorNull() {

		try {
			new ResponseType((String)null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The value must not be null or empty string", e.getMessage());
		}
	}


	public void testCodeFlowDetection() {

		assertTrue(new ResponseType("code").impliesCodeFlow());
		assertFalse(new ResponseType("token").impliesCodeFlow());
		assertFalse(new ResponseType("code", "token").impliesCodeFlow());
		assertFalse(new ResponseType("code", "id_token", "token").impliesCodeFlow());
		assertFalse(new ResponseType("token", "id_token").impliesCodeFlow());
		assertFalse(new ResponseType("code", "id_token").impliesCodeFlow());
		assertFalse(new ResponseType("id_token").impliesCodeFlow());
	}


	public void testImplicitFlowDetection() {
		
		assertFalse(new ResponseType("code").impliesImplicitFlow());
		assertTrue(new ResponseType("token").impliesImplicitFlow());
		assertFalse(new ResponseType("code", "token").impliesImplicitFlow());
		assertFalse(new ResponseType("code", "id_token", "token").impliesImplicitFlow());
		assertTrue(new ResponseType("token", "id_token").impliesImplicitFlow());
		assertFalse(new ResponseType("code", "id_token").impliesImplicitFlow());
		assertTrue(new ResponseType("id_token").impliesImplicitFlow());
	}


	public void testHybridFlowDetection() {
		
		assertFalse(new ResponseType("code").impliesHybridFlow());
		assertFalse(new ResponseType("token").impliesHybridFlow());
		assertTrue(new ResponseType("code", "token").impliesHybridFlow());
		assertTrue(new ResponseType("code", "id_token", "token").impliesHybridFlow());
		assertFalse(new ResponseType("token", "id_token").impliesHybridFlow());
		assertTrue(new ResponseType("code", "id_token").impliesHybridFlow());
		assertFalse(new ResponseType("id_token").impliesHybridFlow());
	}


	public void testSerializeAndParse() throws ParseException {

		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		rt.add(new ResponseType.Value("id_token"));

		rt = ResponseType.parse(rt.toString());

		assertTrue(rt.contains(ResponseType.Value.CODE));
		assertTrue(rt.contains(new ResponseType.Value("id_token")));
		assertEquals(2, rt.size());
	}


	public void testParseNull() {

		try {
			ResponseType.parse(null);
			fail();
		} catch (ParseException e) {
			assertEquals("Null or empty response type string", e.getMessage());
		}
	}


	public void testParseEmptyString() {

		try {
			ResponseType.parse(" ");
			fail();
		} catch (ParseException e) {
			assertEquals("Null or empty response type string", e.getMessage());
		}
	}


	public void testContains() {

		List<ResponseType> rtList = new ArrayList<>();

		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);

		ResponseType rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);

		assertEquals(2, rtList.size());

		rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);
		assertTrue(rtList.contains(rt1));

		rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);
		assertTrue(rtList.contains(rt2));

		ResponseType rt3 = new ResponseType();
		rt3.add(OIDCResponseTypeValue.ID_TOKEN);

		assertFalse(rtList.contains(rt3));
	}


	public void testValueComparison() {

		assertEquals(ResponseType.Value.CODE, new ResponseType.Value("code"));
	}


	public void testMultipleEquality()
		throws Exception {
		
		assertEquals(ResponseType.parse("code id_token"), ResponseType.parse("id_token code"));
	}
}
