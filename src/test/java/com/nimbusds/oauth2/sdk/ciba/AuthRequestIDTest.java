/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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


import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.ParseException;


public class AuthRequestIDTest extends TestCase {


	public void testConstants() {
		
		assertEquals(16, AuthRequestID.MIN_BYTE_LENGTH);
		assertEquals(20, AuthRequestID.RECOMMENDED_BYTE_LENGTH);
	}
	
	
	public void testDefaultConstructor() throws ParseException {
		
		AuthRequestID authRequestID = new AuthRequestID();
		assertEquals(AuthRequestID.RECOMMENDED_BYTE_LENGTH, new Base64URL(authRequestID.getValue()).decode().length);
		
		assertEquals(authRequestID, AuthRequestID.parse(authRequestID.getValue()));
	}
	
	
	public void testDefaultConstructorRandomness() {
		// Simple check
		Set<String> values = new HashSet<>();
		
		for (int i=0; i < 100; i++) {
			values.add(new AuthRequestID().getValue());
		}
		
		assertEquals(100, values.size());
	}
	
	
	public void testByteLengthConstructor() throws ParseException {
		
		int byteLength = 16;
		AuthRequestID authRequestID = new AuthRequestID(byteLength);
		assertEquals(byteLength, new Base64URL(authRequestID.getValue()).decode().length);
		
		assertEquals(authRequestID, AuthRequestID.parse(authRequestID.getValue()));
	}
	
	
	public void testStringConstructor() throws ParseException {
	
		// GUUID
		String value = "1c266114-a1be-4252-8ad1-04986c5b9ac1";
		
		AuthRequestID authRequestID = new AuthRequestID(value);
		assertEquals(value, authRequestID.getValue());
		
		assertEquals(authRequestID, AuthRequestID.parse(authRequestID.getValue()));
	}
	
	
	public void testStringConstructor_acceptBase64URL() throws ParseException {
		
		// Generate some long b64URL-safe string
		AuthRequestID b64URL = new AuthRequestID(256);
		
		assertEquals(b64URL, new AuthRequestID(b64URL.getValue()));
		
		assertEquals(b64URL, AuthRequestID.parse(b64URL.getValue()));
	}
	
	
	public void testRejectIllegalChars() {
		
		for (String val: Arrays.asList("+", "*", "!", "@", "#")) {
			
			IllegalArgumentException exception = null;
			try {
				new AuthRequestID(val);
				fail();
			} catch (IllegalArgumentException e) {
				exception  = e;
			}
			assertEquals("Illegal character(s) in the auth_req_id value", exception.getMessage());
			
			try {
				AuthRequestID.parse(val);
				fail();
			} catch (ParseException e) {
				assertEquals("Illegal character(s) in the auth_req_id value", e.getMessage());
			}
		}
	}
	
	
	public void testEquality() {
		
		assertEquals(new AuthRequestID("abcdef"), new AuthRequestID("abcdef"));
		assertEquals(new AuthRequestID("abcdef").hashCode(), new AuthRequestID("abcdef").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotSame(new AuthRequestID("abcdef"), new AuthRequestID("ABCDEF"));
		assertNotSame(new AuthRequestID("abcdef").hashCode(), new AuthRequestID("ABCDEF").hashCode());
	}
}
