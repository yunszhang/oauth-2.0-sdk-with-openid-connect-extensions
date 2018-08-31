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


import java.util.*;

import junit.framework.TestCase;


public class MapUtilsTest extends TestCase {
	
	
	public void testToSingleValuedMap_null() {
		
		assertNull(MapUtils.toSingleValuedMap(null));
	}
	
	
	public void testToSingleValuedMap_oneEntry_singleValued_null() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Collections.singletonList((String)null));
		
		Map<String,String> out = MapUtils.toSingleValuedMap(in);
		assertNull(out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testToSingleValuedMap_oneEntry_singleValued() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Collections.singletonList("1"));
		
		Map<String,String> out = MapUtils.toSingleValuedMap(in);
		assertEquals("1", out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testToSingleValuedMap_oneEntry_twoValues() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Arrays.asList("1", "2"));
		
		Map<String,String> out = MapUtils.toSingleValuedMap(in);
		assertEquals("1", out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testToSingleValuedMap_oneEntry_threeValues() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Arrays.asList("1", "2", "3"));
		
		Map<String,String> out = MapUtils.toSingleValuedMap(in);
		assertEquals("1", out.get("a"));
		assertEquals(1, out.size());
	}
}
