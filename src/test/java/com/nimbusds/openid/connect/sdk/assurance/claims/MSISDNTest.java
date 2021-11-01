/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class MSISDNTest extends TestCase {
	
	
	public void testMaxLengthConstant() {
		
		assertEquals(15, MSISDN.MAX_LENGTH);
	}
	
	
	public void testLifeCycle()
		throws ParseException {
	
		String value = "919825098250";
		
		MSISDN msisdn = new MSISDN(value);
		assertEquals(value, msisdn.getValue());
		
		msisdn = MSISDN.parse(msisdn.getValue());
		assertEquals(value, msisdn.getValue());
	}
	
	
	public void testNumeric() {
	
		try {
			new MSISDN("1a");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The MSISDN must be a numeric string", e.getMessage());
		}
	
		try {
			MSISDN.parse("1a");
			fail();
		} catch (ParseException e) {
			assertEquals("The MSISDN must be a numeric string", e.getMessage());
		}
	}
	
	
	public void testTooLong() {
	
		String tooLong = "1234567890123456";
		assertEquals(16, tooLong.length());
		
		try {
			new MSISDN(tooLong);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The MSISDN must not contain more than 15 digits", e.getMessage());
		}
	
		try {
			MSISDN.parse(tooLong);
			fail();
		} catch (ParseException e) {
			assertEquals("The MSISDN must not contain more than 15 digits", e.getMessage());
		}
	}
	
	
	public void testEquality() {
		
		assertEquals(new MSISDN("1"), new MSISDN("1"));
		assertEquals(new MSISDN("1").hashCode(), new MSISDN("1").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotSame(new MSISDN("1"), new MSISDN("2"));
		assertNotSame(new MSISDN("1").hashCode(), new MSISDN("2").hashCode());
	}
}
