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


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;


public class ListUtilsTest extends TestCase {
	
	
	public void testRemoveNullItems_null() {
		
		assertNull(ListUtils.removeNullItems(null));
	}
	
	
	public void testRemoveNullItems_empty() {
		
		List<String> list = Collections.emptyList();
		
		assertEquals(list, ListUtils.removeNullItems(list));
	}
	
	
	public void testRemoveNullItems_noneRemoved() {
		
		List<String> list = Arrays.asList("a", "b", "c");
		
		assertEquals(list, ListUtils.removeNullItems(list));
	}
	
	
	public void testRemoveNullItems_oneRemoved() {
		
		List<String> list = Arrays.asList("a", "b", null, "d");
		
		assertEquals(Arrays.asList("a", "b", "d"), ListUtils.removeNullItems(list));
	}
}
