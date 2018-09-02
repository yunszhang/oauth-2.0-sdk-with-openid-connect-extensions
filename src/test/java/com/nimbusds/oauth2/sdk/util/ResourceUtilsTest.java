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

package com.nimbusds.oauth2.sdk.util;


import java.net.URI;

import junit.framework.TestCase;


public class ResourceUtilsTest extends TestCase {
	
	
	public void testIsValidResourceURI_positive() {
		
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com:8080/")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api")));
		assertTrue(ResourceUtils.isValidResourceURI(URI.create("resource://rs1.com/api/v1")));
	}
	
	
	public void testIsValidResourceURI_negative() {
		
		assertFalse(ResourceUtils.isValidResourceURI(URI.create("https:///path")));
		assertFalse(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api?query")));
		assertFalse(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api#fragment")));
	}
}
