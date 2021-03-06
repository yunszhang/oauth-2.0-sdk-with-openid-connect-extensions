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
import com.nimbusds.openid.connect.sdk.assurance.request.MinimalVerificationSpec;
import com.nimbusds.openid.connect.sdk.assurance.request.VerificationSpec;
import com.nimbusds.openid.connect.sdk.assurance.request.VerifiedClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;


public class OIDCClaimsRequestTest extends TestCase {


	private static boolean containsVoluntaryClaimsRequestEntry(final Collection<ClaimsSetRequest.Entry> entries,
		                                                   final String claimName) {

		for (ClaimsSetRequest.Entry en: entries) {

			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.VOLUNTARY) &&
			    en.getLangTag() == null &&
			    en.getRawValue() == null)

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
			    en.getRawValue() == null)

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

//		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());

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

//		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());
		
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

//		System.out.println("Claims request for scope openid profile: " + cr.toJSONObject());

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
		assertNull(entry.getRawValue());
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
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		userInfoClaims = claimsRequest.getUserInfoClaimsRequest().getClaimNames(false);
		assertTrue(userInfoClaims.contains("email"));
		assertTrue(userInfoClaims.contains("email_verified"));
		assertEquals(2, userInfoClaims.size());
	}


	public void testParseCoreSpecExample()
		throws Exception {

		String json = "{" +
			"   \"userinfo\":" +
			"    {" +
			"     \"given_name\": {\"essential\": true}," +
			"     \"nickname\": null," +
			"     \"email\": {\"essential\": true}," +
			"     \"email_verified\": {\"essential\": true}," +
			"     \"picture\": null," +
			"     \"http://example.info/claims/groups\": null" +
			"    }," +
			"   \"id_token\":" +
			"    {" +
			"     \"auth_time\": {\"essential\": true}," +
			"     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }" +
			"    }" +
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
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getIDTokenClaimsRequest().get("acr");
		assertEquals("acr", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertEquals(Collections.singletonList("urn:mace:incommon:iap:silver"), entry.getValuesAsListOfStrings());
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

		entry = claimsRequest.getUserInfoClaimsRequest().get("given_name");
		assertEquals("given_name", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("nickname");
		assertEquals("nickname", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email");
		assertEquals("email", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email_verified");
		assertEquals("email_verified", entry.getClaimName());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("picture");
		assertEquals("picture", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());

		entry = claimsRequest.getUserInfoClaimsRequest().get("http://example.info/claims/groups");
		assertEquals("http://example.info/claims/groups", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
	}

	public void testParseIndividualClaimRequestWithAdditionalInformationExample()
		throws Exception {

		String json = "{" +
			"   \"userinfo\":" +
			"    {" +
			"     \"given_name\": {\"essential\": true}," +
			"     \"nickname\": null," +
			"     \"email\": {\"essential\": true}," +
			"     \"email_verified\": {\"essential\": true}," +
			"     \"picture\": null," +
			"     \"http://example.info/claims/groups\": null," +
			"     \"http://example.info/claims/additionalInfo#de\": {\"info\" : \"custom information\"}" +
			"    }," +
			"   \"id_token\":" +
			"    {" +
			"     \"auth_time\": {\"essential\": true}," +
			"     \"acr\": {\"values\": [\"urn:mace:incommon:iap:silver\"] }" +
			"    }" +
			"  }";

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(jsonObject);

		Set<String> idTokenClaimNames = claimsRequest.getIDTokenClaimsRequest().getClaimNames(false);
		assertTrue(idTokenClaimNames.contains("auth_time"));
		assertTrue(idTokenClaimNames.contains("acr"));
		assertEquals(2, idTokenClaimNames.size());

		ClaimsSetRequest.Entry entry = claimsRequest.getIDTokenClaimsRequest().get("auth_time");
		assertEquals("auth_time", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getIDTokenClaimsRequest().get("acr");
		assertEquals("acr", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertEquals(Collections.singletonList("urn:mace:incommon:iap:silver"), entry.getValuesAsListOfStrings());
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

		entry = claimsRequest.getUserInfoClaimsRequest().get("given_name");
		assertEquals("given_name", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("nickname");
		assertEquals("nickname", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email");
		assertEquals("email", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("email_verified");
		assertEquals("email_verified", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("picture");
		assertEquals("picture", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("http://example.info/claims/groups");
		assertEquals("http://example.info/claims/groups", entry.getClaimName());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		entry = claimsRequest.getUserInfoClaimsRequest().get("http://example.info/claims/additionalInfo", LangTag.parse("de"));
		assertEquals("http://example.info/claims/additionalInfo", entry.getClaimName());
		assertEquals(LangTag.parse("de"),entry.getLangTag());
		assertNull(entry.getRawValue());
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
		
		ClaimsSetRequest.Entry txEntry = idTokenClaimsRequest.get("transaction");
		
		// JSON object getter
		JSONObject jsonObject = txEntry.getValueAsJSONObject();
		assertEquals("abc", jsonObject.get("display_data"));
		assertEquals(1, jsonObject.size());
		
		// Raw getter
		jsonObject = (JSONObject) txEntry.getRawValue();
		assertEquals("abc", jsonObject.get("display_data"));
		assertEquals(1, jsonObject.size());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/333/support-json-object-values-in-individual
	public void testParseWithJSONArrayOfObjectsClaimValue()
		throws ParseException {
		
		String json = "{" +
			"  \"id_token\": {" +
			"    \"transaction\": {" +
			"      \"essential\": false," +
			"      \"values\": [" +
			"        {" +
			"          \"display_data\": \"abc\"," +
			"          \"additional_data\" : \"def\"" +
			"        }," +
			"        {" +
			"          \"display_data\": \"ghi\"," +
			"          \"additional_data\" : \"jkl\"" +
			"        }" +
			"      ]" +
			"    }" +
			"  }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		ClaimsSetRequest idTokenClaimsRequest = claimsRequest.getIDTokenClaimsRequest();
		assertEquals(1, idTokenClaimsRequest.getEntries().size());
		
		ClaimsSetRequest.Entry txEntry = idTokenClaimsRequest.get("transaction");
		
		// List of JSON objects getter
		List<JSONObject> jsonObjects = txEntry.getValuesAsListOfJSONObjects();
		assertEquals(2, jsonObjects.size());
		
		JSONObject o1 = jsonObjects.get(0);
		assertEquals("abc", o1.get("display_data"));
		assertEquals("def", o1.get("additional_data"));
		assertEquals(2, o1.size());
		
		JSONObject o2 = jsonObjects.get(1);
		assertEquals("ghi", o2.get("display_data"));
		assertEquals("jkl", o2.get("additional_data"));
		assertEquals(2, o2.size());
		
		// List of untyped values getter
		List<?> wildcardList = txEntry.getValuesAsRawList();
		assertEquals(2, wildcardList.size());
		
		o1 = (JSONObject) wildcardList.get(0);
		assertEquals("abc", o1.get("display_data"));
		assertEquals("def", o1.get("additional_data"));
		assertEquals(2, o1.size());
		
		o2 = (JSONObject) wildcardList.get(1);
		assertEquals("ghi", o2.get("display_data"));
		assertEquals("jkl", o2.get("additional_data"));
		assertEquals(2, o2.size());
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
				assertNull(entry.getRawValue());

			} else if (entry.getClaimName().equals("nickname")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getRawValue());

			} else if (entry.getClaimName().equals("email")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getRawValue());

			} else if (entry.getClaimName().equals("email_verified")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getRawValue());

			} else if (entry.getClaimName().equals("picture")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getRawValue());

			} else if (entry.getClaimName().equals("http://example.info/claims/groups")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getRawValue());

			} else {
				fail("Unexpected userinfo claim name: " + entry.getClaimName());
			}
		}

		for (ClaimsSetRequest.Entry entry: claimsRequest.getIDTokenClaimsRequest().getEntries()) {

			if (entry.getClaimName().equals("auth_time")) {

				assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getRawValue());

			} else if (entry.getClaimName().equals("acr")) {

				assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
				assertNull(entry.getLangTag());
				assertNull(entry.getValueAsString());
				assertEquals(Collections.singletonList("urn:mace:incommon:iap:silver"), entry.getValuesAsListOfStrings());

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
		
		// New API
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequests().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries().size());
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getRawValue());
			assertNull(en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		// Deprecated API
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequestList().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries().size());
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getRawValue());
			assertNull(en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());
	}
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/request/essential.json
	public void testAssurance_essentialExample()
		throws ParseException {
		
		String json = 
			"{" +
			"   \"userinfo\":{" +
			"      \"verified_claims\":{" +
			"         \"verification\": {" +
			"            \"trust_framework\": null" +
			"         }," +
			"         \"claims\":{" +
			"            \"given_name\":{\"essential\": true}," +
			"            \"family_name\":{\"essential\": true}," +
			"            \"birthdate\":null" +
			"         }" +
			"      }" +
			"   }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		// New API
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequests().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries().size());
		
		Map<String,ClaimRequirement> claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(claimReq.get(en.getClaimName()), en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getRawValue());
			assertNull(en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		// Deprecated API
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequestList().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries().size());
		
		claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(claimReq.get(en.getClaimName()), en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getRawValue());
			assertNull(en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());
	}
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/request/userinfo.json
	public void testAssurance_exampleWithUserInfo()
		throws ParseException {
		
		String json =
			"{" +
			"  \"userinfo\": {" +
			"    \"verified_claims\": {" +
			"      \"verification\": {" +
			"        \"trust_framework\": null" +
			"      }," +
			"      \"claims\": {" +
			"        \"given_name\": null," +
			"        \"family_name\": null," +
			"        \"birthdate\": null" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		assertNull(claimsRequest.getIDTokenClaimsRequest());
		assertTrue(claimsRequest.getIDTokenVerifiedClaimsRequests().isEmpty());
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequests().size());
		
		VerifiedClaimsSetRequest verifiedClaimsSetRequest = claimsRequest.getUserInfoVerifiedClaimsRequests().get(0);
		
		JSONObject expectedVerificationJSONObject = new JSONObject();
		expectedVerificationJSONObject.put("trust_framework", null);
		assertEquals(expectedVerificationJSONObject, verifiedClaimsSetRequest.getVerification().toJSONObject());
		
		ClaimsSetRequest.Entry givenName = verifiedClaimsSetRequest.get("given_name");
		assertEquals("given_name", givenName.getClaimName());
		
		ClaimsSetRequest.Entry familyName = verifiedClaimsSetRequest.get("family_name");
		assertEquals("family_name", familyName.getClaimName());
		
		ClaimsSetRequest.Entry birthdate = verifiedClaimsSetRequest.get("birthdate");
		assertEquals("birthdate", birthdate.getClaimName());
		
		for (ClaimsSetRequest.Entry en: Arrays.asList(givenName, familyName, birthdate)) {
			assertNull(en.getLangTag());
			assertEquals(ClaimRequirement.VOLUNTARY, en.getClaimRequirement());
			assertNull(en.getRawValue());
		}
	}
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/request/purpose.json
	public void testAssurance_exampleWithPurpose()
		throws ParseException {
		
		String json =
			"{" +
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
		
		assertEquals(1, claimsRequest.getUserInfoVerifiedClaimsRequests().size());
		assertEquals(3, claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries().size());
		
		Map<String,ClaimRequirement> claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		Map<String,String> purposes = new HashMap<>();
		purposes.put("given_name", "To make communication look more personal");
		purposes.put("family_name", null);
		purposes.put("birthdate", "To send you best wishes on your birthday");
		
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries()) {
			
			assertTrue(Arrays.asList("given_name", "family_name", "birthdate").contains(en.getClaimName()));
			
			assertEquals(claimReq.get(en.getClaimName()), en.getClaimRequirement());
			assertNull(en.getLangTag());
			assertNull(en.getRawValue());
			assertEquals(purposes.get(en.getClaimName()), en.getPurpose());
			assertNull(en.getAdditionalInformation());
		}
		
		assertEquals(JSONObjectUtils.parse(json), claimsRequest.toJSONObject());
	}
	
	
	public void testAssurance_rejectEmptyClaimsElement() {
	
		String json =
			"{" +
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
	
	
	public void testEntry() throws LangTagException {
		
		ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry("name");
		
		assertEquals("name", entry.getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertNull(entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		LangTag langTag = new LangTag("en");
		entry = entry.withLangTag(langTag);
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		entry = entry.withClaimRequirement(ClaimRequirement.ESSENTIAL);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getRawValue());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		String value = "Alice";
		entry = entry.withValue(value);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertEquals(value, entry.getValueAsString());
		assertNull(entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		String purpose = "Contract formation";
		entry = entry.withPurpose(purpose);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertEquals(value, entry.getValueAsString());
		assertEquals(purpose, entry.getPurpose());
		assertNull(entry.getAdditionalInformation());
		
		Map<String,Object> otherInfo = new HashMap<>();
		otherInfo.put("patientId", "p123");
		entry = entry.withAdditionalInformation(otherInfo);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertEquals(value, entry.getValueAsString());
		assertEquals(purpose, entry.getPurpose());
		assertEquals(otherInfo, entry.getAdditionalInformation());
		
		List<String> values = Arrays.asList("Alice", "Alice Adams");
		entry = entry.withValues(values);
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getValueAsString());
		assertEquals(values, entry.getValuesAsListOfStrings());
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
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		assertNull(claimsRequest.getIDTokenClaimsRequest());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testVerifiedIDTokenClaims_deprecatedAPI()
		throws Exception {
		
		JSONObject verification = new JSONObject();
		verification.put("trust_framework", null);
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withIDTokenVerifiedClaimsRequest(
				new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
				.withVerificationJSONObject(verification)
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
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
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"email\":null,\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		assertEquals("email", claimsRequest.getIDTokenClaimsRequest().getEntries().iterator().next().getClaimName());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testPlainAndVerifiedIDTokenClaims_deprecatedAPI()
		throws Exception {
		
		JSONObject verification = new JSONObject();
		verification.put("trust_framework", null);
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withIDTokenClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
			)
			.withIDTokenVerifiedClaimsRequest(
				new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
				.withVerificationJSONObject(verification)
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"email\":null,\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
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
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		assertNull(claimsRequest.getUserInfoClaimsRequest());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testVerifiedUserInfoClaims_deprecatedAPI()
		throws Exception {
		
		JSONObject verification = new JSONObject();
		verification.put("trust_framework", null);
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoVerifiedClaimsRequest(
				new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
				.withVerificationJSONObject(verification)
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
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
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"email\":null,\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = OIDCClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(true));
		
		assertEquals("email", claimsRequest.getUserInfoClaimsRequest().getEntries().iterator().next().getClaimName());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testPlainAndVerifiedUserInfoClaims_deprecatedAPI()
		throws Exception {
		
		JSONObject verification = new JSONObject();
		verification.put("trust_framework", null);
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoClaimsRequest(
				new ClaimsSetRequest()
				.add("email")
			)
			.withUserInfoVerifiedClaimsRequest(
				new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
				.add("name")
				.add("address")
				.withVerificationJSONObject(verification)
			);
		
		Collection<ClaimsSetRequest.Entry> entries = claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getEntries();
		ClaimsSetRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"email\":null,\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":null}}}}";
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
		assertTrue(claimsRequest.getIDTokenVerifiedClaimsRequests().isEmpty());
		assertTrue(claimsRequest.getUserInfoVerifiedClaimsRequests().isEmpty());
		
		// Add claims with verification to id_token and userinfo top-level members
		final JSONObject idTokenVerification = new JSONObject();
		idTokenVerification.put("trust_framework", null);
		idTokenVerification.put("time", null);
		
		VerificationSpec idTokenVerificationSpec = new VerificationSpec() {
			@Override
			public JSONObject toJSONObject() {
				return idTokenVerification;
			}
		};
		
		final JSONObject userInfoVerification = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("value", IdentityTrustFramework.EIDAS.getValue());
		userInfoVerification.put("trust_framework", tfSpec);
		
		VerificationSpec userInfoVerificationSpec = new VerificationSpec() {
			@Override
			public JSONObject toJSONObject() {
				return userInfoVerification;
			}
		};
		
		
		claimsRequest = claimsRequest
			.withIDTokenVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
					.withVerification(idTokenVerificationSpec)
					.add("email"))
			.withUserInfoVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
					.withVerification(userInfoVerificationSpec)
					.add("name")
					.add("address")
		);
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
		
		// JSON output
		JSONObject jsonObject = claimsRequest.toJSONObject();
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"email\":null},\"verification\":{\"trust_framework\":null,\"time\":null}}},\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":{\"value\":\"eidas\"}}}}}";
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), jsonObject);
		
		// Parse
		claimsRequest = OIDCClaimsRequest.parse(jsonObject.toJSONString());
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
		
		// Copy
		OIDCClaimsRequest copy = new OIDCClaimsRequest()
			.add(claimsRequest);
		
		assertEquals(idTokenVerification, copy.getIDTokenVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
		assertEquals(userInfoVerification, copy.getUserInfoVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
	}
	
	
	public void testVerificationElements_deprecatedAPI()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest();
		
		// Getters and setters with null
		assertTrue(claimsRequest.getIDTokenVerifiedClaimsRequestList().isEmpty());
		assertTrue(claimsRequest.getUserInfoVerifiedClaimsRequestList().isEmpty());
		
		// Add claims with verification to id_token and userinfo top-level members
		JSONObject idTokenVerification = new JSONObject();
		idTokenVerification.put("trust_framework", null);
		idTokenVerification.put("time", null);
		
		JSONObject userInfoVerification = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("value", IdentityTrustFramework.EIDAS_IAL_HIGH.getValue());
		userInfoVerification.put("trust_framework", tfSpec);
		
		
		claimsRequest = claimsRequest
			.withIDTokenVerifiedClaimsRequest(
				new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
					.withVerificationJSONObject(idTokenVerification)
					.add("email"))
			.withUserInfoVerifiedClaimsRequest(
				 new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
					.withVerificationJSONObject(userInfoVerification)
					.add("name")
					.add("address")
		);
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
		
		// JSON output
		JSONObject jsonObject = claimsRequest.toJSONObject();
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"email\":null},\"verification\":{\"trust_framework\":null,\"time\":null}}},\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":{\"value\":\"eidas_ial_high\"}}}}}";
		
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
			"        \"trust_framework\" : {" +
			"          \"value\": \"eidas\"" +
			"         }" +
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
		
		// Get UserInfo verification element
		MinimalVerificationSpec expectedVerification = new MinimalVerificationSpec(IdentityTrustFramework.EIDAS);
		assertEquals(expectedVerification.toJSONObject(), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getVerification().toJSONObject());
		
		// Get requested verified claims at UserInfo endpoint if any
		for (ClaimsSetRequest.Entry en: claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getEntries()) {
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
		assertTrue(claimsRequest.getIDTokenVerifiedClaimsRequests().isEmpty());
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
		assertEquals(2, claimsRequest.getIDTokenVerifiedClaimsRequests().size());
		
		// ID token 0
		JSONObject idTokenClaimsVerification = claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getVerification().toJSONObject();
		assertEquals(1, idTokenClaimsVerification.size());
		JSONObject trustFramework = JSONObjectUtils.getJSONObject(idTokenClaimsVerification, "trust_framework");
		assertEquals("eidas_ial_substantial", trustFramework.get("value"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(new HashSet<>(Arrays.asList("email", "email_verified")), claimsRequest.getIDTokenVerifiedClaimsRequests().get(0).getClaimNames(false));
		
		// ID token 1
		idTokenClaimsVerification = claimsRequest.getIDTokenVerifiedClaimsRequests().get(1).getVerification().toJSONObject();
		assertEquals(1, idTokenClaimsVerification.size());
		trustFramework = JSONObjectUtils.getJSONObject(idTokenClaimsVerification, "trust_framework");
		assertEquals(Arrays.asList("eidas_ial_high", "eidas_ial_substantial"), JSONObjectUtils.getStringList(trustFramework, "values"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(Collections.singleton("birthdate"), claimsRequest.getIDTokenVerifiedClaimsRequests().get(1).getClaimNames(false));
		
		// UserInfo
		assertEquals(2, claimsRequest.getIDTokenVerifiedClaimsRequests().size());
		
		// UserInfo 0
		JSONObject userInfoClaimsVerification = claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getVerification().toJSONObject();
		assertEquals(1, userInfoClaimsVerification.size());
		trustFramework = JSONObjectUtils.getJSONObject(userInfoClaimsVerification, "trust_framework");
		assertEquals("eidas_ial_high", trustFramework.get("value"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(new HashSet<>(Arrays.asList("given_name", "family_name")), claimsRequest.getUserInfoVerifiedClaimsRequests().get(0).getClaimNames(false));
		
		// UserInfo 1
		userInfoClaimsVerification = claimsRequest.getUserInfoVerifiedClaimsRequests().get(1).getVerification().toJSONObject();
		assertEquals(1, userInfoClaimsVerification.size());
		trustFramework = JSONObjectUtils.getJSONObject(userInfoClaimsVerification, "trust_framework");
		assertEquals(Arrays.asList("eidas_ial_high", "eidas_ial_substantial"), JSONObjectUtils.getStringList(trustFramework, "values"));
		assertEquals(1, trustFramework.size());
		
		assertEquals(Collections.singleton("birthdate"), claimsRequest.getUserInfoVerifiedClaimsRequests().get(1).getClaimNames(false));
	}
	
	
	// https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-6.3.3
	public void testVerified_multipleVerifiedClaimsElements_deprecatedAPI()
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
	
	
	// https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/examples/openid-connect/identity-assurance#claims-process
	public void _testVerified_genericParseAlgorithm()
		throws ParseException {
		
		String json =
			"{" +
			"  \"id_token\" : {" +
			"    \"email\" : null," +
			"    \"verified_claims\" : {" +
			"      \"verification\" : {" +
			"        \"trust_framework\" : {" +
			"          \"value\" : \"eidas\"" +
			"        }" +
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
		
		print(claimsRequest);
	}
	
	
	private static void print(OIDCClaimsRequest claimsRequest) {
		
		int num = 1;
		for (VerifiedClaimsSetRequest claimsSetRequest: claimsRequest.getUserInfoVerifiedClaimsRequests()) {
			System.out.println("UserInfo set #" + num++ + ":");
			print(claimsSetRequest);
		}
		
		num = 1;
		for (VerifiedClaimsSetRequest claimsSetRequest: claimsRequest.getIDTokenVerifiedClaimsRequests()) {
			System.out.println("UserInfo set #" + num++ + ":");
			print(claimsSetRequest);
		}
	}
	
	
	private static void print(VerifiedClaimsSetRequest verifiedClaimsSetRequest) {
		
		VerificationSpec verification = verifiedClaimsSetRequest.getVerification();
		System.out.println("\tVerification: " + verification.toJSONObject());
		
		System.out.println("\tRequested claims: ");
		for (ClaimsSetRequest.Entry en: verifiedClaimsSetRequest.getEntries()) {
			System.out.println("\t\tname: " + en.getClaimName());
			System.out.println("\t\t\trequirement: " + en.getClaimRequirement());
			if (en.getRawValue() != null) {
				// Use claim specific typed value getter
				System.out.println("\t\t\tvalue: " + en.getValueAsString());
			}
			if (en.getLangTag() != null) {
				System.out.println("\t\t\tlanguage tag: " + en.getLangTag());
			}
			if (en.getPurpose() != null) {
				System.out.println("\t\t\tpurpose message: " + en.getPurpose());
			}
		}
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/385/
	public void testAcceptEmptyIdASpecs() throws ParseException {
		
		String json = 
			"{" +
			"    \"id_token\": {" +
			"        \"email\": {" +
			"            \"essential\": false" +
			"        }," +
			"        \"email_verified\": {" +
			"            \"essential\": false" +
			"        }," +
			"        \"verified_claims\": {" +
			"            \"verification\": {" +
			"                \"trust_framework\": {}" +
			"            }," +
			"            \"claims\": {" +
			"                \"given_name\": {}" +
			"            }" +
			"        }" +
			"    }," +
			"    \"userinfo\": {" +
			"        \"email\": {" +
			"            \"essential\": false" +
			"        }," +
			"        \"email_verified\": {" +
			"            \"essential\": false" +
			"        }," +
			"        \"verified_claims\": {" +
			"            \"verification\": {" +
			"                \"trust_framework\": {}" +
			"            }," +
			"            \"claims\": {" +
			"                \"given_name\": {}" +
			"            }" +
			"        }" +
			"    }" +
			"}";
		
		OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse(json);
		
		VerifiedClaimsSetRequest idTokenVerifiedSpec = claimsRequest.getIDTokenVerifiedClaimsRequests().get(0);
		
		assertEquals("{\"trust_framework\":{}}", idTokenVerifiedSpec.getVerification().toJSONObject().toJSONString());
		
		assertEquals(Collections.singleton("given_name"), idTokenVerifiedSpec.getClaimNames(false));
		assertEquals(ClaimRequirement.VOLUNTARY, idTokenVerifiedSpec.get("given_name").getClaimRequirement());
		assertNull(idTokenVerifiedSpec.get("given_name").getRawValue());
		
		VerifiedClaimsSetRequest userInfoVerifiedSpec = claimsRequest.getUserInfoVerifiedClaimsRequests().get(0);
		
		assertEquals("{\"trust_framework\":{}}", userInfoVerifiedSpec.getVerification().toJSONObject().toJSONString());
		
		assertEquals(Collections.singleton("given_name"), userInfoVerifiedSpec.getClaimNames(false));
		assertEquals("given_name", userInfoVerifiedSpec.get("given_name").getClaimName());
		assertEquals(ClaimRequirement.VOLUNTARY, userInfoVerifiedSpec.get("given_name").getClaimRequirement());
		assertNull(userInfoVerifiedSpec.get("given_name").getRawValue());
	}
}