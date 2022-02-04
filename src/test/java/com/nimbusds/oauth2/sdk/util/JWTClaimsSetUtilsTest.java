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


import java.util.Collections;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;


public class JWTClaimsSetUtilsTest extends TestCase {
	
	
	public void testToMultiValueParameters_roundTrip() {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("123")
			.audience("https://c2id.com")
			.claim("scope", "openid email")
			.claim("redirect_uri", "https://example.com/cb")
			.build();
		
		Map<String, List<String>> params = JWTClaimsSetUtils.toMultiValuedParameters(claimsSet);
		assertEquals("openid email", MultivaluedMapUtils.getFirstValue(params, "scope"));
		assertEquals("https://example.com/cb", MultivaluedMapUtils.getFirstValue(params, "redirect_uri"));
		assertEquals(2, params.size());
		
		// Claims iss and aud were skipped
		claimsSet = new JWTClaimsSet.Builder(claimsSet)
			.issuer(null)
			.audience((String)null)
			.build();
		assertEquals(claimsSet.toJSONObject(), JWTClaimsSetUtils.toJWTClaimsSet(params).toJSONObject());
	}
	
	
	public void testToMultiValueParameters_skipNullClaim() {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("xyz", null)
			.build();
		
		Map<String, List<String>> params = JWTClaimsSetUtils.toMultiValuedParameters(claimsSet);
		assertTrue(params.isEmpty());
	}
	
	
	// http://openid.net/specs/openid-connect-core-1_0.html#RequestObject
	public void testToMultiValueParameters_OIDC_requestObjectExample()
		throws Exception {
		
		String json =
			"{" +
			"   \"iss\": \"s6BhdRkqt3\"," +
			"   \"aud\": \"https://server.example.com\"," +
			"   \"response_type\": \"code id_token\"," +
			"   \"client_id\": \"s6BhdRkqt3\"," +
			"   \"redirect_uri\": \"https://client.example.org/cb\"," +
			"   \"scope\": \"openid\"," +
			"   \"state\": \"af0ifjsldkj\"," +
			"   \"nonce\": \"n-0S6_WzA2Mj\"," +
			"   \"max_age\": 86400," +
			"   \"claims\":" +
			"    {" +
			"     \"userinfo\":" +
			"      {" +
			"       \"given_name\": {\"essential\": true}," +
			"       \"nickname\": null," +
			"       \"email\": {\"essential\": true}," +
			"       \"email_verified\": {\"essential\": true}," +
			"       \"picture\": null" +
			"      }," +
			"     \"id_token\":" +
			"      {" +
			"       \"gender\": null," +
			"       \"birthdate\": {\"essential\": true}," +
			"       \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"]}" +
			"      }" +
			"    }" +
			"}";
		
		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);
		
		Map<String,List<String>> params = JWTClaimsSetUtils.toMultiValuedParameters(claimsSet);
		
		assertNull(params.get("iss")); // skipped
		assertNull(params.get("aud"));
		assertEquals(Collections.singletonList("code id_token"), params.get("response_type"));
		assertEquals(Collections.singletonList("s6BhdRkqt3"), params.get("client_id"));
		assertEquals(Collections.singletonList("https://client.example.org/cb"), params.get("redirect_uri"));
		assertEquals(Collections.singletonList("openid"), params.get("scope"));
		assertEquals(Collections.singletonList("af0ifjsldkj"), params.get("state"));
		assertEquals(Collections.singletonList("n-0S6_WzA2Mj"), params.get("nonce"));
		assertEquals(Collections.singletonList("86400"), params.get("max_age"));
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(MultivaluedMapUtils.getFirstValue(params, "claims"));
		
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(true).contains("given_name"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(true).contains("nickname"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(true).contains("email"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(true).contains("email_verified"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(true).contains("picture"));
		assertEquals(5, claimsRequest.getUserInfoClaimsRequest().getEntries().size());
		
		assertTrue(claimsRequest.getIDTokenClaimsRequest().getClaimNames(true).contains("gender"));
		assertTrue(claimsRequest.getIDTokenClaimsRequest().getClaimNames(true).contains("birthdate"));
		assertTrue(claimsRequest.getIDTokenClaimsRequest().getClaimNames(true).contains("acr"));
		assertEquals(3, claimsRequest.getIDTokenClaimsRequest().getEntries().size());
	}
}
