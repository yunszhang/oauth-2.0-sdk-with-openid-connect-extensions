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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.opensaml.xmlsec.signature.J;


public class JSONArrayUtilsTest extends TestCase {


	public void testJSONArrayParse()
		throws Exception {

		String s = "[\"apples\", \"pears\"]";

		JSONArray a = JSONArrayUtils.parse(s);
		assertEquals("apples", a.get(0));
		assertEquals("pears", a.get(1));
		assertEquals(2, a.size());
	}


	public void testParseWithTrailingWhiteSpace()
		throws Exception {

		assertEquals(0, JSONArrayUtils.parse("[] ").size());
		assertEquals(0, JSONArrayUtils.parse("[]\n").size());
		assertEquals(0, JSONArrayUtils.parse("[]\r\n").size());
	}


	public void testToStringList() {

		JSONArray jsonArray = new JSONArray();
		jsonArray.add("apple");
		jsonArray.add(1);
		jsonArray.add(true);

		List<String> stringList = JSONArrayUtils.toStringList(jsonArray);
		assertEquals("apple", stringList.get(0));
		assertEquals("1", stringList.get(1));
		assertEquals("true", stringList.get(2));
		assertEquals(3, stringList.size());
	}


	public void testToStringListNullInput() {

		assertTrue(JSONArrayUtils.toStringList(null).isEmpty());
	}


	public void testToStringListEmptyInput() {

		assertTrue(JSONArrayUtils.toStringList(new JSONArray()).isEmpty());
	}


	public void testToURIList()
		throws ParseException {

		JSONArray jsonArray = new JSONArray();
		jsonArray.add("https://example.com");
		jsonArray.add("ldap://localhost");

		List<URI> uriList = JSONArrayUtils.toURIList(jsonArray);
		assertEquals("https://example.com", uriList.get(0).toString());
		assertEquals("ldap://localhost", uriList.get(1).toString());
		assertEquals(2, uriList.size());
	}


	public void testToURIList_parseException() {

		JSONArray jsonArray = new JSONArray();
		jsonArray.add("https://example.com");
		jsonArray.add("a b c");

		try {
			JSONArrayUtils.toURIList(jsonArray);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal URI: Illegal character in path at index 1: a b c", e.getMessage());
		}
	}


	public void testToURIListNullInput()
		throws ParseException {

		assertTrue(JSONArrayUtils.toURIList(null).isEmpty());
	}


	public void testToURIListEmptyInput()
		throws ParseException {

		assertTrue(JSONArrayUtils.toURIList(new JSONArray()).isEmpty());
	}
	
	
	public void testToJSONObjectList_asMap()
		throws ParseException {
		
		Map<String, Object> o1 = new HashMap<>();
		o1.put("k1", "v1");
		
		Map<String, Object> o2 = new HashMap<>();
		o2.put("k2", "v2");
		
		JSONArray jsonArray = new JSONArray();
		jsonArray.add(o1);
		jsonArray.add(o2);
		
		List<JSONObject> objectList = JSONArrayUtils.toJSONObjectList(jsonArray);
		
		assertEquals("v1", objectList.get(0).get("k1"));
		assertEquals("v2", objectList.get(1).get("k2"));
	}
}
