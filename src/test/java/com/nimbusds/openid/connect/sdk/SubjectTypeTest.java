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

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the SubjectType class.
 */
public class SubjectTypeTest extends TestCase {


	public void testToString() {

		assertEquals("pairwise", SubjectType.PAIRWISE.toString());
		assertEquals("public", SubjectType.PUBLIC.toString());
	}
	
	
	public void testParse()
		throws Exception {
		
		assertEquals(SubjectType.PAIRWISE, SubjectType.parse("pairwise"));
		assertEquals(SubjectType.PUBLIC, SubjectType.parse("public"));
	}
	
	
	public void testParseExceptionNull() {
		
		try {
			SubjectType.parse(null);
			
			fail("Failed to raise parse exception");
			
		} catch (ParseException e) {
			// ok
		}
	}
	
	
	public void testParseInvalidConstant() {
		
		try {
			SubjectType.parse("abc");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
	}
}