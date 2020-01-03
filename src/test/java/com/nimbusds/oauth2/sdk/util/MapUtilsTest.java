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


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;


public class MapUtilsTest extends TestCase {
	
	
	public void testIsEmpty() {
		
		assertTrue(MapUtils.isEmpty(null));
		assertTrue(MapUtils.isEmpty(new HashMap<>()));
		
		Map<String,String> someMap = new HashMap<>();
		someMap.put("k1", "v1");
		assertFalse(MapUtils.isEmpty(someMap));
	}
	
	
	public void testIsNotEmpty() {
		
		Map<String,String> someMap = new HashMap<>();
		someMap.put("k1", "v1");
		
		assertTrue(MapUtils.isNotEmpty(someMap));
		
		assertFalse(MapUtils.isNotEmpty(null));
		assertFalse(MapUtils.isNotEmpty(new HashMap<>()));
	}
}
