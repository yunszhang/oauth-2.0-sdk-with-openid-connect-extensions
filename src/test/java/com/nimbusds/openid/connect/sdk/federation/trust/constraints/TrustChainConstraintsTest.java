/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


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
		List<EntityIDConstraint> permitted = new LinkedList<>();
		permitted.add(new ExactMatchEntityIDConstraint(new EntityID("https://example.com")));
		permitted.add(new ExactMatchEntityIDConstraint(new EntityID("https://example.org")));
		
		List<EntityIDConstraint> excluded = new LinkedList<>();
		excluded.add(new SubtreeEntityIDConstraint("https://.abc.example.org"));
		excluded.add(new SubtreeEntityIDConstraint("https://.xyz.example.org"));
		
		TrustChainConstraints c = new TrustChainConstraints(3, permitted, excluded);
		assertEquals(maxPathLength, c.getMaxPathLength());
		assertEquals(permitted, c.getPermittedEntities());
		assertEquals(excluded, c.getExcludedEntities());
		
		JSONObject jsonObject = c.toJSONObject();
		assertEquals(3, JSONObjectUtils.getInt(jsonObject, "max_path_length"));
		
		JSONObject namingConstraints = JSONObjectUtils.getJSONObject(jsonObject, "naming_constraints");
		assertEquals(Arrays.asList(permitted.get(0).toString(), permitted.get(1).toString()), JSONObjectUtils.getStringList(namingConstraints, "permitted"));
		assertEquals(Arrays.asList(excluded.get(0).toString(), excluded.get(1).toString()), JSONObjectUtils.getStringList(namingConstraints, "excluded"));
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
				Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID("https://example.com"))),
				Collections.singletonList((EntityIDConstraint) new SubtreeEntityIDConstraint("https://.abc.example.com"))),
			new TrustChainConstraints(
				10,
				Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID("https://example.com"))),
				Collections.singletonList((EntityIDConstraint) new SubtreeEntityIDConstraint("https://.abc.example.com"))));
	}
}
