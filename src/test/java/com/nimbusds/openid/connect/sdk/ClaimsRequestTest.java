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

package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.*;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the claims request class.
 */
public class ClaimsRequestTest extends TestCase {
	
	
	private static boolean containsVoluntaryClaimsRequestEntry(final Collection<ClaimsRequest.Entry> entries, 
		                                                   final String claimName) {
		
		for (ClaimsRequest.Entry en: entries) {
			
			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.VOLUNTARY) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)
				
				return true;
		}
		
		return false;
	}
	
	
	private static boolean containsEssentialClaimsRequestEntry(final Collection<ClaimsRequest.Entry> entries, 
		                                                   final String claimName) {
		
		for (ClaimsRequest.Entry en: entries) {
			
			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)
				
				return true;
		}
		
		return false;
	}


	public void testResolveSimple()
		throws Exception {

		Scope scope = Scope.parse("openid");

		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

		System.out.println("Claims request for scope openid: " + cr.toJSONObject());

		assertTrue(cr.getIDTokenClaims().isEmpty());
		assertTrue(cr.getUserInfoClaims().isEmpty());
	}
	
	
	public void testResolveToUserInfo()
		throws Exception {
		
		Scope scope = Scope.parse("openid email profile phone address");
		
		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);
		
		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());
		
		assertTrue(cr.getIDTokenClaims().isEmpty());
		
		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "address"));
		
		assertEquals(19, userInfoClaims.size());
		
		Set<String> claimNames = cr.getIDTokenClaimNames(false);
		assertTrue(claimNames.isEmpty());
		
		claimNames = cr.getUserInfoClaimNames(false);
		
		assertTrue(claimNames.contains("email"));
		assertTrue(claimNames.contains("email_verified"));
		assertTrue(claimNames.contains("name"));
		assertTrue(claimNames.contains("given_name"));
		assertTrue(claimNames.contains("family_name"));
		assertTrue(claimNames.contains("middle_name"));
		assertTrue(claimNames.contains("nickname"));
		assertTrue(claimNames.contains("preferred_username"));
		assertTrue(claimNames.contains("profile"));
		assertTrue(claimNames.contains("picture"));
		assertTrue(claimNames.contains("website"));
		assertTrue(claimNames.contains("gender"));
		assertTrue(claimNames.contains("birthdate"));
		assertTrue(claimNames.contains("zoneinfo"));
		assertTrue(claimNames.contains("locale"));
		assertTrue(claimNames.contains("updated_at"));
		assertTrue(claimNames.contains("phone_number"));
		assertTrue(claimNames.contains("phone_number_verified"));
		assertTrue(claimNames.contains("address"));
		
		assertEquals(19, claimNames.size());
	}


	public void testResolveToIDToken()
		throws Exception {

		Scope scope = Scope.parse("openid email profile phone address");

		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("id_token"), scope);

		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());

		assertTrue(cr.getUserInfoClaims().isEmpty());

		Collection<ClaimsRequest.Entry> idTokenClaims = cr.getIDTokenClaims();

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "email_verified"));

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "updated_at"));

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "phone_number"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "phone_number_verified"));

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "address"));

		assertEquals(19, idTokenClaims.size());

		Set<String> claimNames = cr.getUserInfoClaimNames(false);
		assertTrue(claimNames.isEmpty());

		claimNames = cr.getIDTokenClaimNames(false);

		assertTrue(claimNames.contains("email"));
		assertTrue(claimNames.contains("email_verified"));
		assertTrue(claimNames.contains("name"));
		assertTrue(claimNames.contains("given_name"));
		assertTrue(claimNames.contains("family_name"));
		assertTrue(claimNames.contains("middle_name"));
		assertTrue(claimNames.contains("nickname"));
		assertTrue(claimNames.contains("preferred_username"));
		assertTrue(claimNames.contains("profile"));
		assertTrue(claimNames.contains("picture"));
		assertTrue(claimNames.contains("website"));
		assertTrue(claimNames.contains("gender"));
		assertTrue(claimNames.contains("birthdate"));
		assertTrue(claimNames.contains("zoneinfo"));
		assertTrue(claimNames.contains("locale"));
		assertTrue(claimNames.contains("updated_at"));
		assertTrue(claimNames.contains("phone_number"));
		assertTrue(claimNames.contains("phone_number_verified"));
		assertTrue(claimNames.contains("address"));

		assertEquals(19, claimNames.size());
	}


	public void testResolveDependingOnResponseType()
		throws Exception {

		Scope scope = Scope.parse("openid email");

		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("id_token code"), scope);

		assertTrue(cr.getIDTokenClaims().isEmpty());

		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));

		cr = ClaimsRequest.resolve(ResponseType.parse("id_token token"), scope);

		assertTrue(cr.getIDTokenClaims().isEmpty());

		userInfoClaims = cr.getUserInfoClaims();
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));
	}
	
	
	public void testAdd()
		throws Exception {
		
		Scope scope = Scope.parse("openid profile");
		
		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

		System.out.println("Claims request for scope openid profile: " + cr.toJSONObject());
		
		assertTrue(cr.getIDTokenClaims().isEmpty());
		
		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertEquals(14, userInfoClaims.size());
		
		
		ClaimsRequest addon = new ClaimsRequest();
		addon.addUserInfoClaim("email", ClaimRequirement.ESSENTIAL);
		addon.addUserInfoClaim("email_verified", ClaimRequirement.ESSENTIAL);
		
		System.out.println("Essential claims request: " + addon.toJSONObject());
		
		cr.add(addon);
		
	
		assertTrue(containsEssentialClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsEssentialClaimsRequestEntry(userInfoClaims, "email_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertEquals(16, userInfoClaims.size());
		
		
		Set<String> claimNames = cr.getIDTokenClaimNames(false);
		assertTrue(claimNames.isEmpty());
		
		claimNames = cr.getUserInfoClaimNames(false);
		
		assertTrue(claimNames.contains("email"));
		assertTrue(claimNames.contains("email_verified"));
		assertTrue(claimNames.contains("name"));
		assertTrue(claimNames.contains("given_name"));
		assertTrue(claimNames.contains("family_name"));
		assertTrue(claimNames.contains("middle_name"));
		assertTrue(claimNames.contains("nickname"));
		assertTrue(claimNames.contains("preferred_username"));
		assertTrue(claimNames.contains("profile"));
		assertTrue(claimNames.contains("picture"));
		assertTrue(claimNames.contains("website"));
		assertTrue(claimNames.contains("gender"));
		assertTrue(claimNames.contains("birthdate"));
		assertTrue(claimNames.contains("zoneinfo"));
		assertTrue(claimNames.contains("locale"));
		assertTrue(claimNames.contains("updated_at"));
		
		assertEquals(16, claimNames.size());
	}


	public void testResolveSimpleOIDCRequest()
		throws Exception {

		AuthenticationRequest authRequest = new AuthenticationRequest(
			new URI("https://c2id.com/login"),
			ResponseType.parse("code"),
			Scope.parse("openid email"),
			new ClientID("123"),
			new URI("https://client.com/cb"),
			new State(),
			new Nonce());

		ClaimsRequest claimsRequest = ClaimsRequest.resolve(authRequest);

		assertTrue(claimsRequest.getIDTokenClaims().isEmpty());

		Set<String> userInfoClaims = claimsRequest.getUserInfoClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());

		Map<String,String> authRequestParams = authRequest.toParameters();

		authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

		claimsRequest = ClaimsRequest.resolve(authRequest);

		assertTrue(claimsRequest.getIDTokenClaims().isEmpty());

		userInfoClaims = claimsRequest.getUserInfoClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());
	}


	public void testResolveSimpleIDTokenRequest()
		throws Exception {

		AuthenticationRequest authRequest = new AuthenticationRequest(
			new URI("https://c2id.com/login"),
			ResponseType.parse("id_token"),
			Scope.parse("openid email"),
			new ClientID("123"),
			new URI("https://client.com/cb"),
			new State(),
			new Nonce());

		ClaimsRequest claimsRequest = ClaimsRequest.resolve(authRequest);

		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());

		Set<String> idTokenClaims = claimsRequest.getIDTokenClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertTrue(idTokenClaims.contains("email_verified"));
		assertEquals(2, idTokenClaims.size());

		Map<String,String> authRequestParams = authRequest.toParameters();

		authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

		claimsRequest = ClaimsRequest.resolve(authRequest);

		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());

		idTokenClaims = claimsRequest.getIDTokenClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertTrue(idTokenClaims.contains("email_verified"));
		assertEquals(2, idTokenClaims.size());
	}


	public void testResolveComplexOIDCRequest()
		throws Exception {

		ClaimsRequest cr = new ClaimsRequest();
		cr.addIDTokenClaim(new ClaimsRequest.Entry("email", ClaimRequirement.ESSENTIAL));

		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).claims(cr).build();

		ClaimsRequest claimsRequest = ClaimsRequest.resolve(authRequest);

		Set<String> idTokenClaims = claimsRequest.getIDTokenClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertEquals(1, idTokenClaims.size());

		Collection<ClaimsRequest.Entry> idTokenEntries = claimsRequest.getIDTokenClaims();
		assertEquals(1, idTokenEntries.size());
		ClaimsRequest.Entry entry = idTokenEntries.iterator().next();
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		Set<String> userInfoClaims = claimsRequest.getUserInfoClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());


		Map<String,String> authRequestParams = authRequest.toParameters();

		authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

		claimsRequest = ClaimsRequest.resolve(authRequest);

		idTokenClaims = claimsRequest.getIDTokenClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertEquals(1, idTokenClaims.size());

		idTokenEntries = claimsRequest.getIDTokenClaims();
		assertEquals(1, idTokenEntries.size());
		entry = idTokenEntries.iterator().next();
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		userInfoClaims = claimsRequest.getUserInfoClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());
	}


	public void testParseCoreSpecExample()
		throws Exception {

		String json = "{\n" +
			"   \"userinfo\":\n" +
			"    {\n" +
			"     \"given_name\": {\"essential\": true},\n" +
			"     \"nickname\": null,\n" +
			"     \"email\": {\"essential\": true},\n" +
			"     \"email_verified\": {\"essential\": true},\n" +
			"     \"picture\": null,\n" +
			"     \"http://example.info/claims/groups\": null\n" +
			"    },\n" +
			"   \"id_token\":\n" +
			"    {\n" +
			"     \"auth_time\": {\"essential\": true},\n" +
			"     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }\n" +
			"    }\n" +
			"  }";

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		ClaimsRequest claimsRequest = ClaimsRequest.parse(jsonObject);

		Set<String> idTokenClaimNames = claimsRequest.getIDTokenClaimNames(false);
		assertTrue(idTokenClaimNames.contains("auth_time"));
		assertTrue(idTokenClaimNames.contains("acr"));
		assertEquals(2, idTokenClaimNames.size());

		ClaimsRequest.Entry entry = claimsRequest.removeIDTokenClaim("auth_time", null);
		assertEquals("auth_time", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.removeIDTokenClaim("acr", null);
		assertEquals("acr", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertTrue(entry.getValues().contains("urn:mace:incommon:iap:silver"));
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		assertTrue(claimsRequest.getIDTokenClaims().isEmpty());


		Set<String> userInfoClaimNames = claimsRequest.getUserInfoClaimNames(false);
		assertTrue(userInfoClaimNames.contains("given_name"));
		assertTrue(userInfoClaimNames.contains("nickname"));
		assertTrue(userInfoClaimNames.contains("email"));
		assertTrue(userInfoClaimNames.contains("email_verified"));
		assertTrue(userInfoClaimNames.contains("picture"));
		assertTrue(userInfoClaimNames.contains("http://example.info/claims/groups"));
		assertEquals(6, userInfoClaimNames.size());

		entry = claimsRequest.removeUserInfoClaim("given_name", null);
		assertEquals("given_name", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.removeUserInfoClaim("nickname", null);
		assertEquals("nickname", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.removeUserInfoClaim("email", null);
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.removeUserInfoClaim("email_verified", null);
		assertEquals("email_verified", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.removeUserInfoClaim("picture", null);
		assertEquals("picture", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.removeUserInfoClaim("http://example.info/claims/groups", null);
		assertEquals("http://example.info/claims/groups", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
	}


	public void testAddAndRemoveIDTokenClaims()
		throws Exception {

		ClaimsRequest r = new ClaimsRequest();

		r.addIDTokenClaim("email");
		r.addIDTokenClaim("name");

		assertTrue(r.getIDTokenClaimNames(false).contains("email"));
		assertTrue(r.getIDTokenClaimNames(false).contains("name"));
		assertEquals(2, r.getIDTokenClaims().size());

		JSONObject object = r.toJSONObject();
		assertEquals(1, object.size());

		JSONObject idTokenObject = (JSONObject)object.get("id_token");
		assertTrue(idTokenObject.containsKey("email"));
		assertNull(idTokenObject.get("email"));
		assertTrue(idTokenObject.containsKey("name"));
		assertNull(idTokenObject.get("name"));
		assertEquals(2, idTokenObject.size());

		r.removeIDTokenClaims("email");
		r.removeIDTokenClaims("name");

		assertFalse(r.getIDTokenClaimNames(false).contains("email"));
		assertFalse(r.getIDTokenClaimNames(false).contains("name"));
		assertEquals(0, r.getIDTokenClaims().size());

		object = r.toJSONObject();
		assertTrue(object.isEmpty());
	}


	public void testAddAndRemoveUserInfoClaims()
		throws Exception {

		ClaimsRequest r = new ClaimsRequest();

		r.addUserInfoClaim("email");
		r.addUserInfoClaim("name");

		assertTrue(r.getUserInfoClaimNames(false).contains("email"));
		assertTrue(r.getUserInfoClaimNames(false).contains("name"));
		assertEquals(2, r.getUserInfoClaims().size());

		JSONObject object = r.toJSONObject();
		assertEquals(1, object.size());

		JSONObject userInfoObject = (JSONObject)object.get("userinfo");
		assertTrue(userInfoObject.containsKey("email"));
		assertNull(userInfoObject.get("email"));
		assertTrue(userInfoObject.containsKey("name"));
		assertNull(userInfoObject.get("name"));
		assertEquals(2, userInfoObject.size());

		r.removeUserInfoClaims("email");
		r.removeUserInfoClaims("name");

		assertFalse(r.getUserInfoClaimNames(false).contains("email"));
		assertFalse(r.getUserInfoClaimNames(false).contains("name"));
		assertEquals(0, r.getUserInfoClaims().size());

		object = r.toJSONObject();
		assertTrue(object.isEmpty());
	}


	public void testParseFromString()
		throws Exception {

		// Example from http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
		String json = "{\n" +
			"   \"userinfo\":\n" +
			"    {\n" +
			"     \"given_name\": {\"essential\": true},\n" +
			"     \"nickname\": null,\n" +
			"     \"email\": {\"essential\": true},\n" +
			"     \"email_verified\": {\"essential\": true},\n" +
			"     \"picture\": null,\n" +
			"     \"http://example.info/claims/groups\": null\n" +
			"    },\n" +
			"   \"id_token\":\n" +
			"    {\n" +
			"     \"auth_time\": {\"essential\": true},\n" +
			"     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }\n" +
			"    }\n" +
			"  }";

		ClaimsRequest claimsRequest = ClaimsRequest.parse(json);

		assertTrue(claimsRequest.getUserInfoClaimNames(false).contains("given_name"));
		assertTrue(claimsRequest.getUserInfoClaimNames(false).contains("nickname"));
		assertTrue(claimsRequest.getUserInfoClaimNames(false).contains("email"));
		assertTrue(claimsRequest.getUserInfoClaimNames(false).contains("email_verified"));
		assertTrue(claimsRequest.getUserInfoClaimNames(false).contains("picture"));
		assertTrue(claimsRequest.getUserInfoClaimNames(false).contains("http://example.info/claims/groups"));
		assertEquals(6, claimsRequest.getUserInfoClaimNames(false).size());

		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("auth_time"));
		assertTrue(claimsRequest.getIDTokenClaimNames(false).contains("acr"));
		assertEquals(2, claimsRequest.getIDTokenClaimNames(false).size());

		for (ClaimsRequest.Entry entry: claimsRequest.getUserInfoClaims()) {

			if (entry.getClaimName().equals("given_name")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else if (entry.getClaimName().equals("nickname")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else if (entry.getClaimName().equals("email")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else if (entry.getClaimName().equals("email_verified")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else if (entry.getClaimName().equals("picture")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else if (entry.getClaimName().equals("http://example.info/claims/groups")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else {
				fail("Unexpected userinfo claim name: " + entry.getClaimName());
			}
		}

		for (ClaimsRequest.Entry entry: claimsRequest.getIDTokenClaims()) {

			if (entry.getClaimName().equals("auth_time")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertNull(entry.getValues());

			} else if (entry.getClaimName().equals("acr")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValue());
				assertTrue(entry.getValues().contains("urn:mace:incommon:iap:silver"));
				assertEquals(1, entry.getValues().size());

			} else {
				fail("Unexpected id_token claim name: " + entry.getClaimName());
			}
		}
	}
	
	
	public void testResolveCustomClaims_UserInfo() {
		
		ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
		
		Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, customClaims);
		
		for (ClaimsRequest.Entry en: claimsRequest.getUserInfoClaims()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
		
		assertTrue(claimsRequest.getIDTokenClaims().isEmpty());
	}
	
	
	public void testResolveCustomClaims_IDToken() {
		
		ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);
		
		Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, customClaims);
		
		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
		
		for (ClaimsRequest.Entry en: claimsRequest.getIDTokenClaims()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
	}
	
	
	public void testResolveCustomClaims_UserInfo_withNullClaimsRequest() {
		
		ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
		
		Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, null, customClaims);
		
		for (ClaimsRequest.Entry en: claimsRequest.getUserInfoClaims()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
		
		assertTrue(claimsRequest.getIDTokenClaims().isEmpty());
	}
	
	
	public void testResolveCustomClaims_IDToken_withNullClaimsRequest() {
		
		ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);
		
		Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		ClaimsRequest claimsRequest = ClaimsRequest.resolve(responseType, scope, null, customClaims);
		
		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
		
		for (ClaimsRequest.Entry en: claimsRequest.getIDTokenClaims()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
	}
	
	
	public void testResolveCustomClaims_UserInfo_withClaimsRequest() {
		
		ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
		
		Scope scope = new Scope("openid", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addUserInfoClaim("email");
		claimsRequest.addUserInfoClaim("email_verified");
		
		ClaimsRequest resolvedClaimsRequest = ClaimsRequest.resolve(responseType, scope, claimsRequest, customClaims);
		
		for (ClaimsRequest.Entry en: resolvedClaimsRequest.getUserInfoClaims()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
		
		assertTrue(resolvedClaimsRequest.getIDTokenClaims().isEmpty());
	}
	
	
	public void testResolveCustomClaims_IDToken_withClaimsRequest() {
		
		ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);
		
		Scope scope = new Scope("openid", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim("email");
		claimsRequest.addIDTokenClaim("email_verified");
		
		ClaimsRequest resolvedClaimsRequest = ClaimsRequest.resolve(responseType, scope, claimsRequest, customClaims);
		
		assertTrue(resolvedClaimsRequest.getUserInfoClaims().isEmpty());
		
		for (ClaimsRequest.Entry en: resolvedClaimsRequest.getIDTokenClaims()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
	}
}