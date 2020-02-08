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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class TrustChainConstraintsTest extends TestCase {
	
	
	public void testEmpty() throws ParseException {
		
		TrustChainConstraints c = new TrustChainConstraints(-1, null,  null);
		assertEquals(-1, c.getMaxPathLength());
		assertNull(c.getPermittedEntities());
		assertNull(c.getExcludedEntities());
		
		JSONObject jsonObject = c.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		String json = c.toJSONString();
		assertEquals("{}", json);
		
		c = TrustChainConstraints.parse(jsonObject);
		assertEquals(-1, c.getMaxPathLength());
		assertNull(c.getPermittedEntities());
		assertNull(c.getExcludedEntities());
	}
	
	
	public void testFullySpecified() throws ParseException {
		
		int maxPathLength = 3;
		List<EntityID> permitted = Arrays.asList(new EntityID("1"), new EntityID("2"));
		List<EntityID> excluded = Arrays.asList(new EntityID("3"), new EntityID("4"));
		
		TrustChainConstraints c = new TrustChainConstraints(3, permitted, excluded);
		assertEquals(maxPathLength, c.getMaxPathLength());
		assertEquals(permitted, c.getPermittedEntities());
		assertEquals(excluded, c.getExcludedEntities());
		
		JSONObject jsonObject = c.toJSONObject();
		assertEquals(3, JSONObjectUtils.getInt(jsonObject, "max_path_length"));
		
		JSONObject namingConstraints = JSONObjectUtils.getJSONObject(jsonObject, "naming_constraints");
		assertEquals(Identifier.toStringList(permitted), JSONObjectUtils.getStringList(namingConstraints, "permitted"));
		assertEquals(Identifier.toStringList(excluded), JSONObjectUtils.getStringList(namingConstraints, "excluded"));
		assertEquals(2, namingConstraints.size());
		
		assertEquals(2, jsonObject.size());
		
		c = TrustChainConstraints.parse(jsonObject);
		
		assertEquals(maxPathLength, c.getMaxPathLength());
		assertEquals(permitted, c.getPermittedEntities());
		assertEquals(excluded, c.getExcludedEntities());
	}
	
	
	public void testParse_emptyNamingConstraints() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("max_path_length", 10);
		jsonObject.put("naming_constraints", new JSONObject());
		
		TrustChainConstraints c = TrustChainConstraints.parse(jsonObject);
		assertEquals(10, c.getMaxPathLength());
		assertNull(c.getPermittedEntities());
		assertNull(c.getExcludedEntities());
	}
	
	
	public void testParse_nullNamingConstraints() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("max_path_length", 10);
		jsonObject.put("naming_constraints", null);
		
		TrustChainConstraints c = TrustChainConstraints.parse(jsonObject);
		assertEquals(10, c.getMaxPathLength());
		assertNull(c.getPermittedEntities());
		assertNull(c.getExcludedEntities());
	}
	
	
	public void testParse_nullNamingConstraintsMembers() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("max_path_length", 10);
		
		JSONObject namingConstraints = new JSONObject();
		namingConstraints.put("permitted", null);
		namingConstraints.put("excluded", null);
		jsonObject.put("naming_constraints", namingConstraints);
		
		TrustChainConstraints c = TrustChainConstraints.parse(jsonObject);
		assertEquals(10, c.getMaxPathLength());
		assertNull(c.getPermittedEntities());
		assertNull(c.getExcludedEntities());
	}
	
	
	public void testEquality() {
		
		assertEquals(new TrustChainConstraints(10, null, null), new TrustChainConstraints(10, null, null));
		
		assertEquals(
			new TrustChainConstraints(
			10,
				Collections.singletonList(new EntityID("1")),
				Collections.singletonList(new EntityID("1"))),
			new TrustChainConstraints(
				10,
				Collections.singletonList(new EntityID("1")),
				Collections.singletonList(new EntityID("1"))));
	}
}
