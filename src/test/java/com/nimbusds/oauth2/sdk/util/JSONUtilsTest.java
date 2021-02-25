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

package com.nimbusds.oauth2.sdk.util;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class JSONUtilsTest extends TestCase {


	// https://github.com/netplex/json-smart-v1/issues/7
	public void testCatchNumberFormatException() {
	
		String json = "2e+";
		try {
			JSONUtils.parseJSON(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected exception: For input string: \"2e+\"", e.getMessage());
			assertTrue(e.getCause() instanceof NumberFormatException);
		}
	}
	
	
	public void testNull() {
		
		try {
			JSONUtils.parseJSON(null);
			fail();
		} catch (ParseException e) {
			assertEquals("The JSON string must not be null", e.getMessage());
			assertTrue(e.getCause() instanceof NullPointerException);
		}
	}
}
