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

package com.nimbusds.oauth2.sdk.ciba;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;


public class CIBAGrantTest extends TestCase {
	
	
	public void testGrantTypeConstant() {
		
		assertEquals(GrantType.CIBA, CIBAGrant.GRANT_TYPE);
	}
	
	
	public void testConstructParseLifeCycle() throws ParseException {
		
		AuthRequestID authRequestID = new AuthRequestID();
		
		CIBAGrant cibaGrant = new CIBAGrant(authRequestID);
		assertEquals(GrantType.CIBA, cibaGrant.getType());
		assertEquals(authRequestID, cibaGrant.getAuthRequestID());
		
		Map<String, List<String>> params = cibaGrant.toParameters();
		assertEquals(Collections.singletonList(GrantType.CIBA.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(authRequestID.getValue()), params.get("auth_req_id"));
		assertEquals(2, params.size());
		
		CIBAGrant parsed = CIBAGrant.parse(params);
		assertEquals(GrantType.CIBA, parsed.getType());
		assertEquals(authRequestID, parsed.getAuthRequestID());
	}
	
	
	public void testEquality() {
		
		AuthRequestID authRequestID = new AuthRequestID();
		
		CIBAGrant cg1 = new CIBAGrant(authRequestID);
		CIBAGrant cg2 = new CIBAGrant(authRequestID);
		
		assertEquals(cg1, cg2);
		assertEquals(cg1.hashCode(), cg2.hashCode());
	}
	
	
	public void testInequality() {
		
		CIBAGrant cg1 = new CIBAGrant(new AuthRequestID());
		CIBAGrant cg2 = new CIBAGrant(new AuthRequestID());
		
		assertNotSame(cg1, cg2);
		assertNotSame(cg1.hashCode(), cg2.hashCode());
	}
	
	
	public void testParse_missingGrantType() {
		
		Map<String, List<String>> params = new HashMap<>();
		
		try {
			CIBAGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing grant_type parameter", e.getMessage());
		}
	}
	
	
	public void testParse_invalidGrantType() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		
		try {
			CIBAGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("The grant_type must be urn:openid:params:grant-type:ciba", e.getMessage());
		}
	}
	
	
	public void testParse_missingAuthReqID() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.CIBA.getValue()));
		
		try {
			CIBAGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing or empty auth_req_id parameter", e.getMessage());
		}
	}
	
	
	public void testParse_emptyAuthReqID() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.CIBA.getValue()));
		params.put("auth_req_id", Collections.singletonList(""));
		
		try {
			CIBAGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing or empty auth_req_id parameter", e.getMessage());
		}
	}
	
	
	public void testParse_blankAuthReqID() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.CIBA.getValue()));
		params.put("auth_req_id", Collections.singletonList(""));
		
		try {
			CIBAGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing or empty auth_req_id parameter", e.getMessage());
		}
	}
	
	
	public void testParse_illegalAuthReqID() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.CIBA.getValue()));
		params.put("auth_req_id", Collections.singletonList("#abc!"));
		
		try {
			CIBAGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal character(s) in the auth_req_id value", e.getMessage());
		}
	}
}
