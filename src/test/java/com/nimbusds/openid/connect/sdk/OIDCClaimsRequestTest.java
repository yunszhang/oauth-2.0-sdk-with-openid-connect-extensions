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

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;


public class OIDCClaimsRequestTest extends TestCase {


	private static boolean containsVoluntaryClaimsRequestEntry(final Collection<ClaimsSetRequest.Entry> entries,
		                                                   final String claimName) {

		for (ClaimsSetRequest.Entry en: entries) {

			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.VOLUNTARY) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)

				return true;
		}

		return false;
	}


	private static boolean containsEssentialClaimsRequestEntry(final Collection<ClaimsSetRequest.Entry> entries,
		                                                   final String claimName) {

		for (ClaimsSetRequest.Entry en: entries) {

			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)

				return true;
		}

		return false;
	}


	public void testResolveOAuthAuthorizationRequestWithNoScope() {

		OIDCClaimsRequest cr = OIDCClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null);
		assertNull(cr.getIDTokenClaimsRequest());
		assertNull(cr.getUserInfoClaimsRequest());

		cr = OIDCClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, (Map)null);
		assertNull(cr.getIDTokenClaimsRequest());
		assertNull(cr.getUserInfoClaimsRequest());

		cr = OIDCClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, (OIDCClaimsRequest) null);
		assertNull(cr.getIDTokenClaimsRequest());
		assertNull(cr.getUserInfoClaimsRequest());

		cr = OIDCClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, null, null);
		assertNull(cr.getIDTokenClaimsRequest());
		assertNull(cr.getUserInfoClaimsRequest());
	}


	public void testResolveSimple()
		throws Exception {

		Scope scope = Scope.parse("openid");

		OIDCClaimsRequest cr = OIDCClaimsRequest.resolve(ResponseType.parse("code"), scope);

		assertEquals("{}", cr.toJSONObject().toJSONString());
		
		assertNull(cr.getIDTokenClaimsRequest());
		assertNull(cr.getUserInfoClaimsRequest());
	}


	public void testResolveToUserInfo()
		throws Exception {

		Scope scope = Scope.parse("openid email profile phone address");

		OIDCClaimsRequest cr = OIDCClaimsRequest.resolve(ResponseType.parse("code"), scope);

		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());

		assertNull(cr.getIDTokenClaimsRequest());

		Collection<ClaimsSetRequest.Entry> userInfoClaims = cr.getUserInfoClaimsRequest().getEntries();

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

		assertNull(cr.getIDTokenClaimsRequest());
		
		Set<String> claimNames = cr.getUserInfoClaimsRequest().getClaimNames(false);

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

		OIDCClaimsRequest cr = OIDCClaimsRequest.resolve(ResponseType.parse("id_token"), scope);

		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());
		assertNull(cr.getUserInfoClaimsRequest());

		Collection<ClaimsSetRequest.Entry> idTokenClaims = cr.getIDTokenClaimsRequest().getEntries();

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

		assertNull(cr.getUserInfoClaimsRequest());
		
		Set<String> claimNames = cr.getIDTokenClaimsRequest().getClaimNames(false);

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

		OIDCClaimsRequest cr = OIDCClaimsRequest.resolve(ResponseType.parse("id_token code"), scope);

		assertNull(cr.getIDTokenClaimsRequest());

		Collection<ClaimsSetRequest.Entry> userInfoClaims = cr.getUserInfoClaimsRequest().getEntries();
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));

		cr = OIDCClaimsRequest.resolve(ResponseType.parse("id_token token"), scope);

		assertNull(cr.getIDTokenClaimsRequest());

		userInfoClaims = cr.getUserInfoClaimsRequest().getEntries();
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));
	}


	public void testAdd()
		throws Exception {

		Scope scope = Scope.parse("openid profile");

		OIDCClaimsRequest cr = OIDCClaimsRequest.resolve(ResponseType.parse("code"), scope);

		System.out.println("Claims request for scope openid profile: " + cr.toJSONObject());

		assertNull(cr.getIDTokenClaimsRequest());

		Collection<ClaimsSetRequest.Entry> userInfoClaims = cr.getUserInfoClaimsRequest().getEntries();

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


		OIDCClaimsRequest addon = new OIDCClaimsRequest().withUserInfoClaimsRequest(
			new ClaimsSetRequest()
				.add(new ClaimsSetRequest.Entry("email").withClaimRequirement(ClaimRequirement.ESSENTIAL))
				.add(new ClaimsSetRequest.Entry("email_verified").withClaimRequirement(ClaimRequirement.ESSENTIAL)));

		System.out.println("Essential claims request: " + addon.toJSONObject());

		cr = cr.add(addon);
		
		userInfoClaims = cr.getUserInfoClaimsRequest().getEntries();

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


		assertNull(cr.getIDTokenClaimsRequest());

		Set<String> claimNames = cr.getUserInfoClaimsRequest().getClaimNames(false);

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

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(authRequest);

		assertNull(claimsRequest.getIDTokenClaimsRequest());

		Set<String> userInfoClaims = claimsRequest.getUserInfoClaimsRequest().getClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());

		Map<String,List<String>> authRequestParams = authRequest.toParameters();

		authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

		claimsRequest = OIDCClaimsRequest.resolve(authRequest);

		assertNull(claimsRequest.getIDTokenClaimsRequest());

		userInfoClaims = claimsRequest.getUserInfoClaimsRequest().getClaimNames(false);
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

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(authRequest);

		assertNull(claimsRequest.getUserInfoClaimsRequest());

		Set<String> idTokenClaims = claimsRequest.getIDTokenClaimsRequest().getClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertTrue(idTokenClaims.contains("email_verified"));
		assertEquals(2, idTokenClaims.size());

		Map<String,List<String>> authRequestParams = authRequest.toParameters();

		authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

		claimsRequest = OIDCClaimsRequest.resolve(authRequest);

		assertNull(claimsRequest.getUserInfoClaimsRequest());

		idTokenClaims = claimsRequest.getIDTokenClaimsRequest().getClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertTrue(idTokenClaims.contains("email_verified"));
		assertEquals(2, idTokenClaims.size());
	}


	public void testResolveComplexOIDCRequest()
		throws Exception {

		OIDCClaimsRequest cr = new OIDCClaimsRequest()
			.withIDTokenClaimsRequest(
				new ClaimsSetRequest()
					.add(new ClaimsSetRequest.Entry("email")
						.withClaimRequirement(ClaimRequirement.ESSENTIAL)));

		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb"))
			.claims(cr)
			.build();

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(authRequest);

		Set<String> idTokenClaims = claimsRequest.getIDTokenClaimsRequest().getClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertEquals(1, idTokenClaims.size());

		Collection<ClaimsSetRequest.Entry> idTokenEntries = claimsRequest.getIDTokenClaimsRequest().getEntries();
		assertEquals(1, idTokenEntries.size());
		ClaimsSetRequest.Entry entry = idTokenEntries.iterator().next();
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		Set<String> userInfoClaims = claimsRequest.getUserInfoClaimsRequest().getClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());


		Map<String,List<String>> authRequestParams = authRequest.toParameters();

		authRequest = AuthenticationRequest.parse(new URI("https://c2id.com/login"), authRequestParams);

		claimsRequest = OIDCClaimsRequest.resolve(authRequest);

		idTokenClaims = claimsRequest.getIDTokenClaimsRequest().getClaimNames(false);
		assertTrue(idTokenClaims.contains("email"));
		assertEquals(1, idTokenClaims.size());

		idTokenEntries = claimsRequest.getIDTokenClaimsRequest().getEntries();
		assertEquals(1, idTokenEntries.size());
		entry = idTokenEntries.iterator().next();
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		userInfoClaims = claimsRequest.getUserInfoClaimsRequest().getClaimNames(false);
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
		

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());

		for (boolean withLangTag: Arrays.asList(false, true)) {
			Set<String> idTokenClaimNames = claimsRequest.getIDTokenClaimsRequest().getClaimNames(withLangTag);
			assertTrue(idTokenClaimNames.contains("auth_time"));
			assertTrue(idTokenClaimNames.contains("acr"));
			assertEquals(2, idTokenClaimNames.size());
		}

		ClaimsSetRequest.Entry entry = claimsRequest.getIDTokenClaimsRequest().get("auth_time", null);
		assertEquals("auth_time", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getIDTokenClaimsRequest().get("acr", null);
		assertEquals("acr", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertEquals(Collections.singletonList("urn:mace:incommon:iap:silver"), entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		for (boolean withLangTag: Arrays.asList(false, true)) {
			Set<String> userInfoClaimNames = claimsRequest.getUserInfoClaimsRequest().getClaimNames(withLangTag);
			assertTrue(userInfoClaimNames.contains("given_name"));
			assertTrue(userInfoClaimNames.contains("nickname"));
			assertTrue(userInfoClaimNames.contains("email"));
			assertTrue(userInfoClaimNames.contains("email_verified"));
			assertTrue(userInfoClaimNames.contains("picture"));
			assertTrue(userInfoClaimNames.contains("http://example.info/claims/groups"));
			assertEquals(6, userInfoClaimNames.size());
		}

		entry = claimsRequest.getUserInfoClaimsRequest().get("given_name", null);
		assertEquals("given_name", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("nickname", null);
		assertEquals("nickname", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email", null);
		assertEquals("email", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email_verified", null);
		assertEquals("email_verified", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("picture", null);
		assertEquals("picture", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("http://example.info/claims/groups", null);
		assertEquals("http://example.info/claims/groups", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}

	public void testParseIndividualClaimRequestWithAdditionalInformationExample()
		throws Exception {

		String json = "{\n" +
			"   \"userinfo\":\n" +
			"    {\n" +
			"     \"given_name\": {\"essential\": true},\n" +
			"     \"nickname\": null,\n" +
			"     \"email\": {\"essential\": true},\n" +
			"     \"email_verified\": {\"essential\": true},\n" +
			"     \"picture\": null,\n" +
			"     \"http://example.info/claims/groups\": null,\n" +
			"     \"http://example.info/claims/additionalInfo#de\": {\"info\" : \"custom information\"}\n" +
			"    },\n" +
			"   \"id_token\":\n" +
			"    {\n" +
			"     \"auth_time\": {\"essential\": true},\n" +
			"     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }\n" +
			"    }\n" +
			"  }";

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(jsonObject);

		Set<String> idTokenClaimNames = claimsRequest.getIDTokenClaimsRequest().getClaimNames(false);
		assertTrue(idTokenClaimNames.contains("auth_time"));
		assertTrue(idTokenClaimNames.contains("acr"));
		assertEquals(2, idTokenClaimNames.size());

		ClaimsSetRequest.Entry entry = claimsRequest.getIDTokenClaimsRequest().get("auth_time", null);
		assertEquals("auth_time", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getIDTokenClaimsRequest().get("acr", null);
		assertEquals("acr", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertTrue(entry.getValues().contains("urn:mace:incommon:iap:silver"));
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		assertEquals(2, claimsRequest.getIDTokenClaimsRequest().getEntries().size());


		Set<String> userInfoClaimNames = claimsRequest.getUserInfoClaimsRequest().getClaimNames(false);
		assertTrue(userInfoClaimNames.contains("given_name"));
		assertTrue(userInfoClaimNames.contains("nickname"));
		assertTrue(userInfoClaimNames.contains("email"));
		assertTrue(userInfoClaimNames.contains("email_verified"));
		assertTrue(userInfoClaimNames.contains("picture"));
		assertTrue(userInfoClaimNames.contains("http://example.info/claims/groups"));
		assertTrue(userInfoClaimNames.contains("http://example.info/claims/additionalInfo"));
		assertEquals(7, userInfoClaimNames.size());

		entry = claimsRequest.getUserInfoClaimsRequest().get("given_name", null);
		assertEquals("given_name", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("nickname", null);
		assertEquals("nickname", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email", null);
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email_verified", null);
		assertEquals("email_verified", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("picture", null);
		assertEquals("picture", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("http://example.info/claims/groups", null);
		assertEquals("http://example.info/claims/groups", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("http://example.info/claims/additionalInfo", LangTag.parse("de"));
		assertEquals("http://example.info/claims/additionalInfo", entry.getClaimName());
		assertEquals(LangTag.parse("de"),entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		Map<String, Object> additionalInformation = entry.getAdditionalInformation();
		assertNotNull(additionalInformation);
		assertTrue( additionalInformation.containsKey("info"));
		assertEquals("custom information", additionalInformation.get("info"));
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		
		assertEquals(7, claimsRequest.getUserInfoClaimsRequest().getEntries().size());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/333/support-json-object-values-in-individual
	public void testParseWithJSONObjectClaimValue()
		throws ParseException {
		
		String json = "{" +
			"  \"id_token\": {" +
			"    \"transaction\": {" +
			"      \"value\": {" +
			"          \"display_data\": \"abc\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		ClaimsSetRequest idTokenClaimsRequest = claimsRequest.getIDTokenClaimsRequest();
		assertEquals(1, idTokenClaimsRequest.getEntries().size());
		
		ClaimsSetRequest.Entry txEntry = idTokenClaimsRequest.get("transaction", null);
		
		// JSON object getter
		JSONObject jsonObject = txEntry.getValueAsJSONObject();
		assertEquals("abc", jsonObject.get("display_data"));
		assertEquals(1, jsonObject.size());
		
		// Raw getter
		jsonObject = (JSONObject) txEntry.getRawValue();
		assertEquals("abc", jsonObject.get("display_data"));
		assertEquals(1, jsonObject.size());
	}


	public void testAddIDTokenClaims() {
		
		Map<String, Object> additionalInformationClaimA1 = new HashMap<>();
		additionalInformationClaimA1.put("info", "custom information");
		
		OIDCClaimsRequest r = new OIDCClaimsRequest()
			.withIDTokenClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
				.add("name")
				.add(new ClaimsSetRequest.Entry("a-1")
					.withClaimRequirement(ClaimRequirement.ESSENTIAL)
					.withValue("a1")
					.withAdditionalInformation(additionalInformationClaimA1)
				)
			);


		assertTrue(r.getIDTokenClaimsRequest().getClaimNames(false).contains("email"));
		assertTrue(r.getIDTokenClaimsRequest().getClaimNames(false).contains("name"));
		assertTrue(r.getIDTokenClaimsRequest().getClaimNames(false).contains("a-1"));
		assertEquals(3, r.getIDTokenClaimsRequest().getEntries().size());

		JSONObject object = r.toJSONObject();
		assertEquals(1, object.size());

		JSONObject idTokenObject = (JSONObject)object.get("id_token");
		assertTrue(idTokenObject.containsKey("email"));
		assertNull(idTokenObject.get("email"));
		assertTrue(idTokenObject.containsKey("name"));
		assertNull(idTokenObject.get("name"));
		assertTrue(idTokenObject.containsKey("a-1"));
		assertNotNull(idTokenObject.get("a-1"));
		assertEquals(3, idTokenObject.size());
	}


	public void testAddUserInfoClaims() {
		
		Map<String, Object> additionalInformationClaimA1 = new HashMap<>();
		additionalInformationClaimA1.put("info", "custom information");
		
		OIDCClaimsRequest r = new OIDCClaimsRequest()
			.withUserInfoClaimsRequest(
				new ClaimsSetRequest()
					.add("email")
					.add("name")
					.add(new ClaimsSetRequest.Entry("a-1")
						.withClaimRequirement(ClaimRequirement.ESSENTIAL)
						.withValue("a1")
						.withAdditionalInformation(additionalInformationClaimA1)
					)
			);
		
		
		assertTrue(r.getUserInfoClaimsRequest().getClaimNames(false).contains("email"));
		assertTrue(r.getUserInfoClaimsRequest().getClaimNames(false).contains("name"));
		assertTrue(r.getUserInfoClaimsRequest().getClaimNames(false).contains("a-1"));
		assertEquals(3, r.getUserInfoClaimsRequest().getEntries().size());
		
		JSONObject object = r.toJSONObject();
		assertEquals(1, object.size());
		
		JSONObject userInfoObject = (JSONObject)object.get("userinfo");
		assertTrue(userInfoObject.containsKey("email"));
		assertNull(userInfoObject.get("email"));
		assertTrue(userInfoObject.containsKey("name"));
		assertNull(userInfoObject.get("name"));
		assertTrue(userInfoObject.containsKey("a-1"));
		assertNotNull(userInfoObject.get("a-1"));
		assertEquals(3, userInfoObject.size());
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

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);

		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).contains("given_name"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).contains("nickname"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).contains("email"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).contains("email_verified"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).contains("picture"));
		assertTrue(claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).contains("http://example.info/claims/groups"));
		assertEquals(6, claimsRequest.getUserInfoClaimsRequest().getClaimNames(false).size());

		assertTrue(claimsRequest.getIDTokenClaimsRequest().getClaimNames(false).contains("auth_time"));
		assertTrue(claimsRequest.getIDTokenClaimsRequest().getClaimNames(false).contains("acr"));
		assertEquals(2, claimsRequest.getIDTokenClaimsRequest().getClaimNames(false).size());

		for (ClaimsSetRequest.Entry entry: claimsRequest.getUserInfoClaimsRequest().getEntries()) {

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

		for (ClaimsSetRequest.Entry entry: claimsRequest.getIDTokenClaimsRequest().getEntries()) {

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
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(responseType, scope, customClaims);
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoClaimsRequest().getEntries()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
		
		assertNull(claimsRequest.getIDTokenClaimsRequest());
	}


	public void testResolveCustomClaims_IDToken() {
		
		ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);
		
		Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(responseType, scope, customClaims);
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getIDTokenClaimsRequest().getEntries()) {
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
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(responseType, scope, null, customClaims);
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoClaimsRequest().getEntries()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
		
		assertNull(claimsRequest.getIDTokenClaimsRequest());
	}


	public void testResolveCustomClaims_IDToken_withNullClaimsRequest() {
		
		ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);
		
		Scope scope = new Scope("openid", "email", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.resolve(responseType, scope, null, customClaims);
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getIDTokenClaimsRequest().getEntries()) {
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
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
				.add("email_verified")
			);
		
		OIDCClaimsRequest resolvedClaimsRequest = OIDCClaimsRequest.resolve(responseType, scope, claimsRequest, customClaims);
		
		for (ClaimsSetRequest.Entry en: resolvedClaimsRequest.getUserInfoClaimsRequest().getEntries()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
		
		assertNull(resolvedClaimsRequest.getIDTokenClaimsRequest());
	}

	
	public void testResolveCustomClaims_IDToken_withClaimsRequest() {
		
		ResponseType responseType = new ResponseType(OIDCResponseTypeValue.ID_TOKEN);
		
		Scope scope = new Scope("openid", "custom-scope-a", "custom-scope-b");
		
		Map<Scope.Value,Set<String>> customClaims = new HashMap<>();
		customClaims.put(new Scope.Value("custom-scope-a"), new HashSet<>(Arrays.asList("a-1", "a-2", "a-3")));
		customClaims.put(new Scope.Value("custom-scope-b"), new HashSet<>(Arrays.asList("b-1", "b-2")));
		customClaims.put(new Scope.Value("custom-scope-c"), new HashSet<>(Collections.singletonList("c-1")));
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withIDTokenClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
				.add("email_verified")
			);
		
		OIDCClaimsRequest resolvedClaimsRequest = OIDCClaimsRequest.resolve(responseType, scope, claimsRequest, customClaims);
		
		assertNull(resolvedClaimsRequest.getUserInfoClaimsRequest());
		
		for (ClaimsSetRequest.Entry en: resolvedClaimsRequest.getIDTokenClaimsRequest().getEntries()) {
			assertTrue(Arrays.asList("email", "email_verified", "a-1", "a-2", "a-3", "b-1", "b-2").contains(en.getClaimName()));
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
		}
	}
	
	
	// Identity assurance
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/request/claims.json
	public void testAssurance_simpleExample()
		throws ParseException {
		
		String json = "{" +
			"   \"userinfo\":{" +
			"      \"verified_claims\":{" +
			"         \"verification\": {" +
			"            \"trust_framework\": null" +
			"         }," +
			"         \"claims\":{" +
			"            \"given_name\":null," +
			"            \"family_name\":null," +
			"            \"birthdate\":null" +
			"         }" +
			"      }" +
			"   }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequestList().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries().size());
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getValue());
			assertNull(en.getValues());
			assertNull(en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());
	}
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/request/essential.json
	public void testAssurance_essentialExample()
		throws ParseException {
		
		String json = "{\n" +
			"   \"userinfo\":{\n" +
			"      \"verified_claims\":{\n" +
			"         \"verification\": {\n" +
			"            \"trust_framework\": null\n" +
			"         },\n" +
			"         \"claims\":{\n" +
			"            \"given_name\":{\"essential\": true},\n" +
			"            \"family_name\":{\"essential\": true},\n" +
			"            \"birthdate\":null\n" +
			"         }\n" +
			"      }\n" +
			"   }\n" +
			"}\n";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequestList().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries().size());
		
		Map<String,ClaimRequirement> claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(claimReq.get(en.getClaimName()), en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getValue());
			assertNull(en.getValues());
			assertNull(en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());
	}
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/request/purpose.json
	public void testAssurance_exampleWithPurpose()
		throws ParseException {
		
		String json = "{" +
			"   \"userinfo\":{" +
			"      \"verified_claims\":{" +
			"         \"verification\": {" +
			"            \"trust_framework\": null" +
			"         }," +
			"         \"claims\":{" +
			"            \"given_name\":{" +
			"               \"essential\":true," +
			"               \"purpose\":\"To make communication look more personal\"" +
			"            }," +
			"            \"family_name\":{" +
			"               \"essential\":true" +
			"            }," +
			"            \"birthdate\":{" +
			"               \"purpose\":\"To send you best wishes on your birthday\"" +
			"            }" +
			"         }" +
			"      }" +
			"   }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequestList().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries().size());
		
		Map<String,ClaimRequirement> claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		Map<String,String> purposes = new HashMap<>();
		purposes.put("given_name", "To make communication look more personal");
		purposes.put("family_name", null);
		purposes.put("birthdate", "To send you best wishes on your birthday");
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(claimReq.get(en.getClaimName()), en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getValue());
			assertNull(en.getValues());
			assertEquals(purposes.get(en.getClaimName()), en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());
	}
	
	
	public void testAssurance_rejectEmptyClaimsElement() {
	
		String json = "{" +
			"   \"userinfo\":{" +
			"      \"verified_claims\":{" +
			"         \"verification\": {" +
			"            \"trust_framework\": null" +
			"         }," +
			"         \"claims\":{}" +
			"      }" +
			"   }" +
			"}";
		
		try {
			OIDCClaimsRequest.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid verified claims request: Empty verified claims object", e.getMessage());
		}
	}
	
	
	public void testEntry() throws LangTagException, ParseException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name");
		
		assertEquals("name", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		LangTag langTag = new LangTag("en");
		entry = entry.withLangTag(langTag);
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		entry = entry.withClaimRequirement(ClaimRequirement.ESSENTIAL);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		String value = "Alice";
		entry = entry.withValue(value);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertEquals(value, entry.getValue());
		assertNull(entry.getValues());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		String purpose = "Contract formation";
		entry = entry.withPurpose(purpose);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertEquals(value, entry.getValue());
		assertNull(entry.getValues());
		assertEquals(purpose, entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map<String,Object> otherInfo = new HashMap<>();
		otherInfo.put("patientId", "p123");
		entry = entry.withAdditionalInformation(otherInfo);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertEquals(value, entry.getValue());
		assertNull(entry.getValues());
		assertEquals(purpose, entry.getPurpose());
		assertEquals(otherInfo, entry.getAdditionalInformation());
		
		List<String> values = Arrays.asList("Alice", "Alice Adams");
		entry = entry.withValues(values);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getValue());
		assertEquals(values, entry.getValues());
		assertEquals(purpose, entry.getPurpose());
		assertEquals(otherInfo, entry.getAdditionalInformation());
	}
	
	
	public void testVerifiedIDTokenClaims()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withIDTokenVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"name\":null,\"address\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		assertNull(claimsRequest.getIDTokenClaimsRequest());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testPlainAndVerifiedIDTokenClaims()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withIDTokenClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
			)
			.withIDTokenVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null}},\"email\":null}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		assertEquals("email", claimsRequest.getIDTokenClaimsRequest().getEntries().iterator().next().getClaimName());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testVerifiedUserInfoClaims()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"verified_claims\":{\"claims\":{\"name\":null,\"address\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testPlainAndVerifiedUserInfoClaims()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
			)
			.withUserInfoVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null}},\"email\":null}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		assertEquals("email", claimsRequest.getUserInfoClaimsRequest().getEntries().iterator().next().getClaimName());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testVerificationElements()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest();
		
		// Getters and setters with null
		assertTrue(claimsRequest.getIDTokenVerifiedClaimsRequestList().isEmpty());
		assertTrue(claimsRequest.getUserInfoVerifiedClaimsRequestList().isEmpty());
		
		// Add claims with verification to id_token and userinfo top-level members
		JSONObject idTokenVerification = new JSONObject();
		idTokenVerification.put("time", null);
		
		JSONObject userInfoVerification = new JSONObject();
		userInfoVerification.put("trust_framework", IdentityTrustFramework.EIDAS_IAL_HIGH.getValue());
		
		
		claimsRequest = claimsRequest
			.withIDTokenVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
					.withVerificationJSONObject(idTokenVerification)
					.add("email"))
			.withUserInfoVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
					.withVerificationJSONObject(userInfoVerification)
					.add("name")
					.add("address")
		);
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		
		// JSON output
		JSONObject jsonObject = claimsRequest.toJSONObject();
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"email\":null},\"verification\":{\"time\":null}}},\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":\"eidas_ial_high\"}}}}";
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), jsonObject);
		
		// Parse
		claimsRequest = OIDCClaimsRequest.parse(jsonObject.toJSONString());
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		
		// Copy
		OIDCClaimsRequest copy = new OIDCClaimsRequest()
			.add(claimsRequest);
		
		assertEquals(idTokenVerification, copy.getIDTokenVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		assertEquals(userInfoVerification, copy.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
	}
	
	
	public void testVerifiedParseExampleFromDocs()
		throws Exception {
		
		String json = "{" +
			"  \"userinfo\" : {" +
			"    \"email\" : null," +
			"    \"verified_claims\" : {" +
			"      \"verification\" : {" +
			"        \"trust_framework\" : \"eidas_ial_high\"" +
			"      }," +
			"      \"claims\" : {" +
			"        \"name\" : {" +
			"          \"essential\" : true," +
			"          \"purpose\"   : \"Name required for contract\"" +
			"        }," +
			"        \"address\" : {" +
			"          \"essential\" : true," +
			"          \"purpose\"   : \"Address required for contract\"" +
			"        }" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		// Get UserInfo verification element if any
		System.out.println(claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		
		// Get requested verified claims at UserInfo endpoint if any
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries()) {
			System.out.println("verified claim name: " + en.getClaimName());
			System.out.println("requirement: " + en.getClaimRequirement());
			System.out.println("optional language tag: " + en.getLangTag());
			System.out.println("optional purpose message: " + en.getPurpose());
		}
		
		// Get requested plain claims at UserInfo endpoint if any
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoClaimsRequest().getEntries()) {
			System.out.println("claim name: " + en.getClaimName());
			System.out.println("requirement: " + en.getClaimRequirement());
			System.out.println("optional language tag: " + en.getLangTag());
		}
		
		// Repeat for claims delivered with ID token if any
		assertTrue(claimsRequest.getIDTokenVerifiedClaimsRequestList().isEmpty());
		assertNull(claimsRequest.getIDTokenClaimsRequest());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/287/claimsrequestparse-jsonobject-modifies-the
	public void testSourceJSONObjectMustNotBeModified()
		throws Exception {
		
		JSONObject claims = JSONObjectUtils.parse("{\"id_token\":{\"email\":{\"essential\":true}},\"userinfo\":{\"name\":{\"essential\":true}}}");
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.subject("joe")
			.claim("claims", claims)
			.build();
		
		String before = jwtClaimsSet.toString();
		
		OIDCClaimsRequest cr = OIDCClaimsRequest.parse(claims);
		assertEquals(claims, cr.toJSONObject());
		
		String after = jwtClaimsSet.toString();
		
		assertEquals(before, after);
	}
	
	
	// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-6.3.3
	public void testVerified_multipleVerifiedClaimsElements()
		throws Exception {
		
		String json = "{" +
			"  \"id_token\": {" +
			"    \"verified_claims\": [" +
			"      {" +
			"        \"verification\": {" +
			"          \"trust_framework\": {" +
			"            \"value\": \"eidas_ial_substantial\"" +
			"          }" +
			"        }," +
			"        \"claims\": {" +
			"          \"email\": null," +
			"          \"email_verified\": null" +
			"        }" +
			"      }," +
			"      {" +
			"        \"verification\": {" +
			"          \"trust_framework\": {" +
			"            \"values\": [\"eidas_ial_high\", \"eidas_ial_substantial\"]" +
			"          }" +
			"        }," +
			"        \"claims\": {" +
			"          \"birthdate\": null" +
			"        }" +
			"      }" +
			"    ]" +
			"  }," +
			"  \"userinfo\": {" +
			"    \"verified_claims\": [" +
			"      {" +
			"        \"verification\": {" +
			"          \"trust_framework\": {" +
			"            \"value\": \"eidas_ial_high\"" +
			"          }" +
			"        }," +
			"        \"claims\": {" +
			"          \"given_name\": null," +
			"          \"family_name\": null" +
			"        }" +
			"      }," +
			"      {" +
			"        \"verification\": {" +
			"          \"trust_framework\": {" +
			"            \"values\": [\"eidas_ial_high\", \"eidas_ial_substantial\"]" +
			"          }" +
			"        }," +
			"        \"claims\": {" +
			"          \"birthdate\": null" +
			"        }" +
			"      }" +
			"    ]" +
			"  }" +
			"}";
		
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		// ID token
		assertEquals(2, claimsRequest.getIDTokenVerifiedClaimsRequestList().size());
		
		// ID token 0
		JSONObject idTokenClaimsVerification = claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getVerificationJSONObject();
		assertEquals(1, idTokenClaimsVerification.size());
		JSONObject trustFramework = JSONObjectUtils.getJSONObject(idTokenClaimsVerification, "trust_framework");
		assertEquals("eidas_ial_substantial", trustFramework.get("value"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(new HashSet<>(Arrays.asList("email", "email_verified")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		
		// ID token 1
		idTokenClaimsVerification = claimsRequest.getIDTokenVerifiedClaimsRequestList().get(1).getVerificationJSONObject();
		assertEquals(1, idTokenClaimsVerification.size());
		trustFramework = JSONObjectUtils.getJSONObject(idTokenClaimsVerification, "trust_framework");
		assertEquals(Arrays.asList("eidas_ial_high", "eidas_ial_substantial"), JSONObjectUtils.getStringList(trustFramework, "values"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(Collections.singleton("birthdate"), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(1).getClaimNames(false));
		
		// UserInfo
		assertEquals(2, claimsRequest.getIDTokenVerifiedClaimsRequestList().size());
		
		// UserInfo 0
		JSONObject userInfoClaimsVerification = claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject();
		assertEquals(1, userInfoClaimsVerification.size());
		trustFramework = JSONObjectUtils.getJSONObject(userInfoClaimsVerification, "trust_framework");
		assertEquals("eidas_ial_high", trustFramework.get("value"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(new HashSet<>(Arrays.asList("given_name", "family_name")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		
		// UserInfo 1
		userInfoClaimsVerification = claimsRequest.getUserInfoVerifiedClaimsRequestList().get(1).getVerificationJSONObject();
		assertEquals(1, userInfoClaimsVerification.size());
		trustFramework = JSONObjectUtils.getJSONObject(userInfoClaimsVerification, "trust_framework");
		assertEquals(Arrays.asList("eidas_ial_high", "eidas_ial_substantial"), JSONObjectUtils.getStringList(trustFramework, "values"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(Collections.singleton("birthdate"), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(1).getClaimNames(false));
	}
}