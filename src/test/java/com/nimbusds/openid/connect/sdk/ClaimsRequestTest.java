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
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


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


	public void testResolveOAuthAuthorizationRequestWithNoScope() {

		ClaimsRequest cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null);
		assertTrue(cr.getIDTokenClaims().isEmpty());
		assertTrue(cr.getUserInfoClaims().isEmpty());

		cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, (Map)null);
		assertTrue(cr.getIDTokenClaims().isEmpty());
		assertTrue(cr.getUserInfoClaims().isEmpty());

		cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, (ClaimsRequest) null);
		assertTrue(cr.getIDTokenClaims().isEmpty());
		assertTrue(cr.getUserInfoClaims().isEmpty());

		cr = ClaimsRequest.resolve(new ResponseType(ResponseType.Value.CODE), null, null, null);
		assertTrue(cr.getIDTokenClaims().isEmpty());
		assertTrue(cr.getUserInfoClaims().isEmpty());
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

		Map<String,List<String>> authRequestParams = authRequest.toParameters();

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

		Map<String,List<String>> authRequestParams = authRequest.toParameters();

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


		Map<String,List<String>> authRequestParams = authRequest.toParameters();

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
		assertTrue(userInfoClaimNames.contains("http://example.info/claims/additionalInfo"));
		assertEquals(7, userInfoClaimNames.size());

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

		entry = claimsRequest.removeUserInfoClaim("http://example.info/claims/additionalInfo", LangTag.parse("de"));
		assertEquals("http://example.info/claims/additionalInfo", entry.getClaimName());
		assertEquals(LangTag.parse("de"),entry.getLangTag());
		assertNull(entry.getValue());
		assertNull(entry.getValues());
		Map<String, Object> additionalInformation = entry.getAdditionalInformation();
		assertNotNull(additionalInformation);
		assertTrue( additionalInformation.containsKey("info"));
		assertEquals("custom information", additionalInformation.get("info"));
		assertEquals(ClaimRequirement.VOLUNTARY, entry.getClaimRequirement());

		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
	}


	public void testAddAndRemoveIDTokenClaims()
		throws Exception {

		ClaimsRequest r = new ClaimsRequest();

		r.addIDTokenClaim("email");
		r.addIDTokenClaim("name");
		Map<String, Object> additionalInformationClaimA1 = new HashMap<>();
		additionalInformationClaimA1.put("info", "custom information");
		r.addIDTokenClaim("a-1", ClaimRequirement.ESSENTIAL, null , "a1", additionalInformationClaimA1);


		assertTrue(r.getIDTokenClaimNames(false).contains("email"));
		assertTrue(r.getIDTokenClaimNames(false).contains("name"));
		assertTrue(r.getIDTokenClaimNames(false).contains("a-1"));
		assertEquals(3, r.getIDTokenClaims().size());

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

		r.removeIDTokenClaims("email");
		r.removeIDTokenClaims("name");
		r.removeIDTokenClaims("a-1");

		assertFalse(r.getIDTokenClaimNames(false).contains("email"));
		assertFalse(r.getIDTokenClaimNames(false).contains("name"));
		assertFalse(r.getIDTokenClaimNames(false).contains("a-1"));
		assertEquals(0, r.getIDTokenClaims().size());

		object = r.toJSONObject();
		assertTrue(object.isEmpty());
	}


	public void testAddAndRemoveUserInfoClaims()
		throws Exception {

		ClaimsRequest r = new ClaimsRequest();

		r.addUserInfoClaim("email");
		r.addUserInfoClaim("name");
		Map<String, Object> additionalInformationClaimA1 = new HashMap<>();
		additionalInformationClaimA1.put("info", "custom information");
		r.addUserInfoClaim("a-1", ClaimRequirement.ESSENTIAL, null , "a1", additionalInformationClaimA1);

		assertTrue(r.getUserInfoClaimNames(false).contains("email"));
		assertTrue(r.getUserInfoClaimNames(false).contains("name"));
		assertTrue(r.getUserInfoClaimNames(false).contains("a-1"));
		assertEquals(3, r.getUserInfoClaims().size());

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

		r.removeUserInfoClaims("email");
		r.removeUserInfoClaims("name");
		r.removeUserInfoClaims("a-1");

		assertFalse(r.getUserInfoClaimNames(false).contains("email"));
		assertFalse(r.getUserInfoClaimNames(false).contains("name"));
		assertFalse(r.getUserInfoClaimNames(false).contains("a-1"));
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

	
	public void testResolveCustomClaims_IDToken_withClaimsRequest() throws LangTagException {
		
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
		
		ClaimsRequest claimsRequest = ClaimsRequest.parse(json);
		
		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
		
		assertEquals(3, claimsRequest.getVerifiedUserInfoClaims().size());
		
		for (ClaimsRequest.Entry en: claimsRequest.getVerifiedUserInfoClaims()) {
			
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
		
		ClaimsRequest claimsRequest = ClaimsRequest.parse(json);
		
		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
		
		assertEquals(3, claimsRequest.getVerifiedUserInfoClaims().size());
		
		Map<String,ClaimRequirement> claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		for (ClaimsRequest.Entry en: claimsRequest.getVerifiedUserInfoClaims()) {
			
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
		
		ClaimsRequest claimsRequest = ClaimsRequest.parse(json);
		
		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
		
		assertEquals(3, claimsRequest.getVerifiedUserInfoClaims().size());
		
		Map<String,ClaimRequirement> claimReq = new HashMap<>();
		claimReq.put("given_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("family_name", ClaimRequirement.ESSENTIAL);
		claimReq.put("birthdate", ClaimRequirement.VOLUNTARY);
		
		Map<String,String> purposes = new HashMap<>();
		purposes.put("given_name", "To make communication look more personal");
		purposes.put("family_name", null);
		purposes.put("birthdate", "To send you best wishes on your birthday");
		
		for (ClaimsRequest.Entry en: claimsRequest.getVerifiedUserInfoClaims()) {
			
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
			ClaimsRequest.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid claims object: Empty verification claims object", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Invalid claims object: Empty verification claims object", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testEntry() throws LangTagException, ParseException {
		
		ClaimsRequest.Entry entry = new ClaimsRequest.Entry("name");
		
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
		
		JSONObject jsonObject = ClaimsRequest.Entry.toJSONObject(Collections.singleton(entry));
		
		JSONObject nameObject = JSONObjectUtils.getJSONObject(jsonObject, "name#en");
		assertTrue(JSONObjectUtils.getBoolean(nameObject, "essential"));
		assertEquals(values, JSONObjectUtils.getStringList(nameObject, "values"));
		assertEquals("p123", JSONObjectUtils.getString(nameObject, "patientId"));
		assertEquals(purpose, JSONObjectUtils.getString(nameObject, "purpose"));
		assertEquals(4, nameObject.size());
		assertEquals(1, jsonObject.size());
		
		Collection<ClaimsRequest.Entry> entries = ClaimsRequest.Entry.parseEntries(jsonObject);
		entry = entries.iterator().next();
		assertEquals(ClaimRequirement.ESSENTIAL, entry.getClaimRequirement());
		assertEquals(langTag, entry.getLangTag());
		assertNull(entry.getValue());
		assertEquals(values, entry.getValues());
		assertEquals(purpose, entry.getPurpose());
		assertEquals(otherInfo, entry.getAdditionalInformation());
		assertEquals(1, entries.size());
	}
	
	
	public void testVerifiedIDTokenClaims()
		throws Exception {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("name"));
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("address"));
		
		Collection<ClaimsRequest.Entry> entries = claimsRequest.getVerifiedIDTokenClaims();
		ClaimsRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"name\":null,\"address\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = ClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(true));
		
		assertTrue(claimsRequest.getIDTokenClaims().isEmpty());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testPlainAndVerifiedIDTokenClaims()
		throws Exception {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim(new ClaimsRequest.Entry("email"));
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("name"));
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("address"));
		
		Collection<ClaimsRequest.Entry> entries = claimsRequest.getVerifiedIDTokenClaims();
		ClaimsRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(true));
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null}},\"email\":null}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = ClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedIDTokenClaimNames(true));
		
		assertEquals("email", claimsRequest.getIDTokenClaims().iterator().next().getClaimName());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testVerifiedUserInfoClaims()
		throws Exception {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("name"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("address"));
		
		Collection<ClaimsRequest.Entry> entries = claimsRequest.getVerifiedUserInfoClaims();
		ClaimsRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"verified_claims\":{\"claims\":{\"name\":null,\"address\":null}}}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = ClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(true));
		
		assertTrue(claimsRequest.getUserInfoClaims().isEmpty());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testPlainAndVerifiedUserInfoClaims()
		throws Exception {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addUserInfoClaim(new ClaimsRequest.Entry("email"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("name"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("address"));
		
		Collection<ClaimsRequest.Entry> entries = claimsRequest.getVerifiedUserInfoClaims();
		ClaimsRequest.Entry en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		en = entries.iterator().next();
		assertTrue(en.getClaimName().equals("name") || en.getClaimName().equals("address"));
		assertEquals(2, entries.size());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(true));
		
		String expectedJSON = "{\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null}},\"email\":null}}";
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
		
		claimsRequest = ClaimsRequest.parse(claimsRequest.toJSONString());
		
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(false));
		assertEquals(new HashSet<>(Arrays.asList("name", "address")), claimsRequest.getVerifiedUserInfoClaimNames(true));
		
		assertEquals("email", claimsRequest.getUserInfoClaims().iterator().next().getClaimName());
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), claimsRequest.toJSONObject());
	}
	
	
	public void testVerificationElements()
		throws Exception {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		
		// Getters and setters with null
		assertNull(claimsRequest.getIDTokenClaimsVerificationJSONObject());
		assertNull(claimsRequest.getUserInfoClaimsVerificationJSONObject());
		
		claimsRequest.setIDTokenClaimsVerificationJSONObject(null);
		claimsRequest.setUserInfoClaimsVerificationJSONObject(null);
		
		assertNull(claimsRequest.getIDTokenClaimsVerificationJSONObject());
		assertNull(claimsRequest.getUserInfoClaimsVerificationJSONObject());
		
		// Add claims with verification to id_token and userinfo top-level members
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("email"));
		
		JSONObject idTokenVerification = new JSONObject();
		idTokenVerification.put("time", null);
		
		claimsRequest.setIDTokenClaimsVerificationJSONObject(idTokenVerification);
		
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("name"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("address"));
		
		JSONObject userInfoVerification = new JSONObject();
		userInfoVerification.put("trust_framework", IdentityTrustFramework.EIDAS_IAL_HIGH.getValue());
		
		claimsRequest.setUserInfoClaimsVerificationJSONObject(userInfoVerification);
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenClaimsVerificationJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoClaimsVerificationJSONObject());
		
		// JSON output
		JSONObject jsonObject = claimsRequest.toJSONObject();
		
		String expectedJSON = "{\"id_token\":{\"verified_claims\":{\"claims\":{\"email\":null},\"verification\":{\"time\":null}}},\"userinfo\":{\"verified_claims\":{\"claims\":{\"address\":null,\"name\":null},\"verification\":{\"trust_framework\":\"eidas_ial_high\"}}}}";
		
		assertEquals(JSONObjectUtils.parse(expectedJSON), jsonObject);
		
		// Parse
		claimsRequest = ClaimsRequest.parse(jsonObject.toJSONString());
		
		// Getters
		assertEquals(idTokenVerification, claimsRequest.getIDTokenClaimsVerificationJSONObject());
		assertEquals(userInfoVerification, claimsRequest.getUserInfoClaimsVerificationJSONObject());
		
		// Copy
		ClaimsRequest copy = new ClaimsRequest();
		copy.add(claimsRequest);
		
		assertEquals(idTokenVerification, copy.getIDTokenClaimsVerificationJSONObject());
		assertEquals(userInfoVerification, copy.getUserInfoClaimsVerificationJSONObject());
	}
	
	
	public void testRemoveMethods_forIDToken() {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim(new ClaimsRequest.Entry("email"));
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("name"));
		
		assertEquals(Collections.singleton("email"), claimsRequest.getIDTokenClaimNames(true));
		assertEquals(Collections.singleton("name"), claimsRequest.getVerifiedIDTokenClaimNames(true));
		
		assertEquals("email", claimsRequest.removeIDTokenClaim("email", null).getClaimName());
		assertEquals("name", claimsRequest.removeVerifiedIDTokenClaim("name", null).getClaimName());
		
		assertTrue(claimsRequest.getIDTokenClaimNames(true).isEmpty());
		assertTrue(claimsRequest.getVerifiedIDTokenClaimNames(true).isEmpty());
	}
	
	
	public void testRemoveMethods_forUserInfo() {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addUserInfoClaim(new ClaimsRequest.Entry("email"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("name"));
		
		assertEquals(Collections.singleton("email"), claimsRequest.getUserInfoClaimNames(true));
		assertEquals(Collections.singleton("name"), claimsRequest.getVerifiedUserInfoClaimNames(true));
		
		assertEquals("email", claimsRequest.removeUserInfoClaim("email", null).getClaimName());
		assertEquals("name", claimsRequest.removeVerifiedUserInfoClaim("name", null).getClaimName());
		
		assertTrue(claimsRequest.getUserInfoClaimNames(true).isEmpty());
		assertTrue(claimsRequest.getVerifiedUserInfoClaimNames(true).isEmpty());
	}
	
	
	public void testRemoveMethods_collection_forIDToken() {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addIDTokenClaim(new ClaimsRequest.Entry("email"));
		claimsRequest.addVerifiedIDTokenClaim(new ClaimsRequest.Entry("name"));
		
		assertEquals("email", claimsRequest.removeIDTokenClaims("email").iterator().next().getClaimName());
		assertEquals("name", claimsRequest.removeVerifiedIDTokenClaims("name").iterator().next().getClaimName());
		
		assertTrue(claimsRequest.getIDTokenClaimNames(true).isEmpty());
		assertTrue(claimsRequest.getVerifiedIDTokenClaimNames(true).isEmpty());
	}
	
	
	public void testRemoveMethods_collection_forUserInfo() {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addUserInfoClaim(new ClaimsRequest.Entry("email"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("name"));
		
		assertEquals("email", claimsRequest.removeUserInfoClaims("email").iterator().next().getClaimName());
		assertEquals("name", claimsRequest.removeVerifiedUserInfoClaims("name").iterator().next().getClaimName());
		
		assertTrue(claimsRequest.getUserInfoClaimNames(true).isEmpty());
		assertTrue(claimsRequest.getVerifiedUserInfoClaimNames(true).isEmpty());
	}
	
	
	public void testParseExampleFromDocs()
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
		
		ClaimsRequest claimsRequest = ClaimsRequest.parse(json);
		
		// Get UserInfo verification element if any
		System.out.println(claimsRequest.getUserInfoClaimsVerificationJSONObject());
		
		// Get requested verified claims at UserInfo endpoint if any
		for (ClaimsRequest.Entry en: claimsRequest.getVerifiedUserInfoClaims()) {
			System.out.println("verified claim name: " + en.getClaimName());
			System.out.println("requirement: " + en.getClaimRequirement());
			System.out.println("optional language tag: " + en.getLangTag());
			System.out.println("optional purpose message: " + en.getPurpose());
		}
		
		// Get requested plain claims at UserInfo endpoint if any
		for (ClaimsRequest.Entry en: claimsRequest.getUserInfoClaims()) {
			System.out.println("claim name: " + en.getClaimName());
			System.out.println("requirement: " + en.getClaimRequirement());
			System.out.println("optional language tag: " + en.getLangTag());
		}
		
		// Repeat for claims delivered with ID token if any
		System.out.println(claimsRequest.getIDTokenClaimsVerificationJSONObject());
		
		for (ClaimsRequest.Entry en: claimsRequest.getVerifiedIDTokenClaims()) {
			System.out.println("verified claim name: " + en.getClaimName());
			System.out.println("requirement: " + en.getClaimRequirement());
			System.out.println("optional language tag: " + en.getLangTag());
			System.out.println("optional purpose message: " + en.getPurpose());
		}
		
		for (ClaimsRequest.Entry en: claimsRequest.getIDTokenClaims()) {
			System.out.println("claim name: " + en.getClaimName());
			System.out.println("requirement: " + en.getClaimRequirement());
			System.out.println("optional language tag: " + en.getLangTag());
		}
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
		
		ClaimsRequest cr = ClaimsRequest.parse(claims);
		assertEquals(claims, cr.toJSONObject());
		
		String after = jwtClaimsSet.toString();
		
		assertEquals(before, after);
	}
}