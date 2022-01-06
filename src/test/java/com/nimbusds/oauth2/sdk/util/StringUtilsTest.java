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


public class StringUtilsTest extends TestCase {


	public void testIsAlpha() {
	
		String s = "TheQuickBrownFoxJumpsOverTheLazyDog";
		
		assertTrue(StringUtils.isAlpha(s));
		
		assertTrue(StringUtils.isAlpha(null));
		assertTrue(StringUtils.isAlpha(""));
		
		assertFalse(StringUtils.isAlpha(" "));
		assertFalse(StringUtils.isAlpha("123"));
		assertFalse(StringUtils.isAlpha("123abc"));
	}


	public void testIsNumeric() {
	
		String s = "1234567890";
		
		assertTrue(StringUtils.isNumeric(s));
		
		assertTrue(StringUtils.isNumeric(null));
		assertTrue(StringUtils.isNumeric(""));
		
		assertFalse(StringUtils.isNumeric(" "));
		assertFalse(StringUtils.isNumeric("abc"));
		assertFalse(StringUtils.isNumeric("abc123"));
	}
}
