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

package com.nimbusds.openid.connect.sdk.claims;


import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class ExternalClaimsUtilsTest extends TestCase {
	
	// getExternalClaimSources
	
	public void testGetExternalClaimSources_specAggregatedExample()
		throws Exception {
		
		String json = 
			"{" +
			"   \"name\": \"Jane Doe\"," +
			"   \"given_name\": \"Jane\"," +
			"   \"family_name\": \"Doe\"," +
			"   \"birthdate\": \"0000-03-22\"," +
			"   \"eye_color\": \"blue\"," +
			"   \"email\": \"janedoe@example.com\"," +
			"   \"_claim_names\": {" +
			"     \"address\": \"src1\"," +
			"     \"phone_number\": \"src1\"" +
			"   }," +
			"   \"_claim_sources\": {" +
			"     \"src1\": {\"JWT\": \"jwt_header.jwt_part2.jwt_part3\"}" +
			"   }" +
			"  }";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		Map<String,JSONObject> ext = ExternalClaimsUtils.getExternalClaimSources(jsonObject);
		
		JSONObject sourceSpec = ext.get("src1");
		assertEquals("jwt_header.jwt_part2.jwt_part3", sourceSpec.get("JWT"));
		assertEquals(1, sourceSpec.size());
		
		assertEquals(1, ext.size());
	}
	
	
	public void testGetExternalClaimSources_specDistributedExample()
		throws Exception {
		
		String json =
			"{\n" +
			"   \"name\": \"Jane Doe\",\n" +
			"   \"given_name\": \"Jane\",\n" +
			"   \"family_name\": \"Doe\",\n" +
			"   \"email\": \"janedoe@example.com\",\n" +
			"   \"birthdate\": \"0000-03-22\",\n" +
			"   \"eye_color\": \"blue\",\n" +
			"   \"_claim_names\": {\n" +
			"     \"payment_info\": \"src1\",\n" +
			"     \"shipping_address\": \"src1\",\n" +
			"     \"credit_score\": \"src2\"\n" +
			"    },\n" +
			"   \"_claim_sources\": {\n" +
			"     \"src1\": {\"endpoint\":\n" +
			"                \"https://bank.example.com/claim_source\"},\n" +
			"     \"src2\": {\"endpoint\":\n" +
			"                \"https://creditagency.example.com/claims_here\",\n" +
			"              \"access_token\": \"ksj3n283dke\"}\n" +
			"   }\n" +
			"  }";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		Map<String,JSONObject> ext = ExternalClaimsUtils.getExternalClaimSources(jsonObject);
		
		JSONObject sourceSpec1 = ext.get("src1");
		assertEquals("https://bank.example.com/claim_source", sourceSpec1.get("endpoint"));
		assertEquals(1, sourceSpec1.size());
		
		JSONObject sourceSpec2 = ext.get("src2");
		assertEquals("https://creditagency.example.com/claims_here", sourceSpec2.get("endpoint"));
		assertEquals("ksj3n283dke", sourceSpec2.get("access_token"));
		
		assertEquals(2, ext.size());
	}
	
	
	public void testGetExternalClaimSources_none() {
		
		assertNull(ExternalClaimsUtils.getExternalClaimSources(new JSONObject()));
	}
	
	
	public void testGetExternalClaimSources_empty() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("_claim_sources", new JSONObject());
		
		assertNull(ExternalClaimsUtils.getExternalClaimSources(jsonObject));
	}
	
	
	public void testGetExternalClaimSources_invalidSpec() {
		
		JSONObject jsonObject = new JSONObject();
		JSONObject spec = new JSONObject();
		JSONObject claimSources = new JSONObject();
		claimSources.put("src1", "invalid");
		jsonObject.put("_claim_sources", claimSources);
		
		assertNull(ExternalClaimsUtils.getExternalClaimSources(jsonObject));
	}
	
	
	// getExternalClaimNamesForSource
	
	public void testGetExternalClaimNamesForSource_specAggregatedExample()
		throws Exception {
		
		String json =
			"{" +
			"   \"name\": \"Jane Doe\"," +
			"   \"given_name\": \"Jane\"," +
			"   \"family_name\": \"Doe\"," +
			"   \"birthdate\": \"0000-03-22\"," +
			"   \"eye_color\": \"blue\"," +
			"   \"email\": \"janedoe@example.com\"," +
			"   \"_claim_names\": {" +
			"     \"address\": \"src1\"," +
			"     \"phone_number\": \"src1\"" +
			"   }," +
			"   \"_claim_sources\": {" +
			"     \"src1\": {\"JWT\": \"jwt_header.jwt_part2.jwt_part3\"}" +
			"   }" +
			"  }";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		Set<String> names = ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "src1");
		assertTrue(names.contains("address"));
		assertTrue(names.contains("phone_number"));
		assertEquals(2, names.size());
	}
	
	
	public void testGetExternalClaimNamesForSource_specDistributedExample()
		throws Exception {
		
		String json =
			"{\n" +
			"   \"name\": \"Jane Doe\",\n" +
			"   \"given_name\": \"Jane\",\n" +
			"   \"family_name\": \"Doe\",\n" +
			"   \"email\": \"janedoe@example.com\",\n" +
			"   \"birthdate\": \"0000-03-22\",\n" +
			"   \"eye_color\": \"blue\",\n" +
			"   \"_claim_names\": {\n" +
			"     \"payment_info\": \"src1\",\n" +
			"     \"shipping_address\": \"src1\",\n" +
			"     \"credit_score\": \"src2\"\n" +
			"    },\n" +
			"   \"_claim_sources\": {\n" +
			"     \"src1\": {\"endpoint\":\n" +
			"                \"https://bank.example.com/claim_source\"},\n" +
			"     \"src2\": {\"endpoint\":\n" +
			"                \"https://creditagency.example.com/claims_here\",\n" +
			"              \"access_token\": \"ksj3n283dke\"}\n" +
			"   }\n" +
			"  }";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		Set<String> names = ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "src1");
		assertTrue(names.contains("payment_info"));
		assertTrue(names.contains("shipping_address"));
		assertEquals(2, names.size());
		
		names = ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "src2");
		assertTrue(names.contains("credit_score"));
		assertEquals(1, names.size());

		// Source not present
		assertTrue(ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "no-such-source").isEmpty());
	}
	
	
	public void testGetExternalClaimNamesForSource_none() {
		
		assertTrue(ExternalClaimsUtils.getExternalClaimNamesForSource(new JSONObject(), "src1").isEmpty());
	}
	
	
	public void testGetExternalClaimNamesForSource_ignoreNullSourceID() {
		
		JSONObject claims = new JSONObject();
		JSONObject extClaimNames = new JSONObject();
		extClaimNames.put("payment_info", null);
		claims.put("_claim_names", extClaimNames);
		
		assertTrue(ExternalClaimsUtils.getExternalClaimNamesForSource(claims, "src1").isEmpty());
	}
	
	
	public void testGetExternalClaimNamesForSource_ignoreNonStringSourceID() {
		
		JSONObject claims = new JSONObject();
		JSONObject extClaimNames = new JSONObject();
		extClaimNames.put("payment_info", 100);
		claims.put("_claim_names", extClaimNames);
		
		assertTrue(ExternalClaimsUtils.getExternalClaimNamesForSource(claims, "src1").isEmpty());
	}
}
