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


import java.net.URI;
import java.util.*;
import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.DateUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.IdentityVerification;
import com.nimbusds.openid.connect.sdk.assurance.VerificationProcess;
import com.nimbusds.openid.connect.sdk.assurance.claims.Birthplace;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSet;
import com.nimbusds.openid.connect.sdk.assurance.evidences.*;


public class UserInfoTest extends TestCase {
	
	
	public void testClaimNameConstants() {
		
		// Basic
		assertTrue(UserInfo.getStandardClaimNames().contains("iss"));
		assertTrue(UserInfo.getStandardClaimNames().contains("aud"));
		
		// Person
		assertTrue(UserInfo.getStandardClaimNames().contains("name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("given_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("family_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("middle_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("nickname"));
		assertTrue(UserInfo.getStandardClaimNames().contains("preferred_username"));
		assertTrue(UserInfo.getStandardClaimNames().contains("profile"));
		assertTrue(UserInfo.getStandardClaimNames().contains("picture"));
		assertTrue(UserInfo.getStandardClaimNames().contains("website"));
		assertTrue(UserInfo.getStandardClaimNames().contains("email"));
		assertTrue(UserInfo.getStandardClaimNames().contains("email_verified"));
		assertTrue(UserInfo.getStandardClaimNames().contains("gender"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birthdate"));
		assertTrue(UserInfo.getStandardClaimNames().contains("zoneinfo"));
		assertTrue(UserInfo.getStandardClaimNames().contains("locale"));
		assertTrue(UserInfo.getStandardClaimNames().contains("phone_number"));
		assertTrue(UserInfo.getStandardClaimNames().contains("phone_number_verified"));
		assertTrue(UserInfo.getStandardClaimNames().contains("address"));
		assertTrue(UserInfo.getStandardClaimNames().contains("updated_at"));
		assertTrue(UserInfo.getStandardClaimNames().contains("updated_at"));
		
		// UserInfo
		assertTrue(UserInfo.getStandardClaimNames().contains("sub"));
		
		// Assurance
		assertTrue(UserInfo.getStandardClaimNames().contains("birthplace"));
		assertTrue(UserInfo.getStandardClaimNames().contains("nationalities"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birth_family_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birth_given_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birth_middle_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("salutation"));
		assertTrue(UserInfo.getStandardClaimNames().contains("title"));
		assertTrue(UserInfo.getStandardClaimNames().contains("verified_claims"));
		
		assertEquals(30, UserInfo.getStandardClaimNames().size());
	}


	public void testParseRoundTrip()
		throws Exception {

		// Example JSON from messages spec
		String json = "{\n" +
			"   \"sub\"                : \"248289761001\",\n" +
			"   \"name\"               : \"Jane Doe\",\n" +
			"   \"given_name\"         : \"Jane\",\n" +
			"   \"family_name\"        : \"Doe\",\n" +
			"   \"preferred_username\" : \"j.doe\",\n" +
			"   \"email\"              : \"janedoe@example.com\",\n" +
			"   \"picture\"            : \"http://example.com/janedoe/me.jpg\"\n" +
			" }";

		UserInfo userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("Jane", userInfo.getGivenName());
		assertEquals("Doe", userInfo.getFamilyName());
		assertEquals("j.doe", userInfo.getPreferredUsername());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());
		assertEquals("http://example.com/janedoe/me.jpg", userInfo.getPicture().toString());

		json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("Jane", userInfo.getGivenName());
		assertEquals("Doe", userInfo.getFamilyName());
		assertEquals("j.doe", userInfo.getPreferredUsername());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());
		assertEquals("http://example.com/janedoe/me.jpg", userInfo.getPicture().toString());
		
		// No external claims
		assertNull(userInfo.getAggregatedClaims());
		assertNull(userInfo.getDistributedClaims());
	}


	public void testWithAddress()
		throws Exception {

		String json = "{\n" +
			"\"sub\": \"248289761001\",\n" +
			"\"name\": \"Jane Doe\",\n" +
			"\"email\": \"janedoe@example.com\",\n" +
			"\"address\": {\n" +
			"\"formatted\":\"Some formatted\",\n" +
			"\"street_address\":\"Some street\",\n" +
			"\"locality\":\"Some locality\",\n" +
			"\"region\":\"Some region\",\n" +
			"\"postal_code\":\"1000\",\n" +
			"\"country\":\"Some country\"\n" +
			"}   \n" +
			"}";

		UserInfo userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());

		Address address = userInfo.getAddress();

		assertEquals("Some formatted", address.getFormatted());
		assertEquals("Some street", address.getStreetAddress());
		assertEquals("Some locality", address.getLocality());
		assertEquals("Some region", address.getRegion());
		assertEquals("1000", address.getPostalCode());
		assertEquals("Some country", address.getCountry());

		json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("janedoe@example.com", userInfo.getEmail().getAddress());

		address = userInfo.getAddress();

		assertEquals("Some formatted", address.getFormatted());
		assertEquals("Some street", address.getStreetAddress());
		assertEquals("Some locality", address.getLocality());
		assertEquals("Some region", address.getRegion());
		assertEquals("1000", address.getPostalCode());
		assertEquals("Some country", address.getCountry());
	}


	public void testConstructor() {

		Subject subject = new Subject("alice");

		UserInfo userInfo = new UserInfo(subject);

		assertEquals(subject.getValue(), userInfo.getSubject().getValue());
		assertNull(userInfo.getName());
		assertNull(userInfo.getGivenName());
		assertNull(userInfo.getFamilyName());
		assertNull(userInfo.getMiddleName());
		assertNull(userInfo.getNickname());
		assertNull(userInfo.getPreferredUsername());
		assertNull(userInfo.getProfile());
		assertNull(userInfo.getPicture());
		assertNull(userInfo.getWebsite());
		assertNull(userInfo.getEmail());
		assertNull(userInfo.getEmailAddress());
		assertNull(userInfo.getEmailVerified());
		assertNull(userInfo.getGender());
		assertNull(userInfo.getBirthdate());
		assertNull(userInfo.getZoneinfo());
		assertNull(userInfo.getLocale());
		assertNull(userInfo.getPhoneNumber());
		assertNull(userInfo.getPhoneNumberVerified());
		assertNull(userInfo.getAddress());
		assertNull(userInfo.getUpdatedTime());
		
		// Assurance
		assertNull(userInfo.getBirthplace());
		assertNull(userInfo.getNationalities());
		assertNull(userInfo.getBirthFamilyName());
		assertNull(userInfo.getBirthGivenName());
		assertNull(userInfo.getBirthMiddleName());
		assertNull(userInfo.getSalutation());
		assertNull(userInfo.getTitle());
		assertNull(userInfo.getVerifiedClaims());
		
		// No external claims
		assertNull(userInfo.getAggregatedClaims());
		assertNull(userInfo.getDistributedClaims());
	}


	public void testGettersAndSetters()
		throws Exception {

		UserInfo userInfo = new UserInfo(new Subject("sub"));

		userInfo.setName("name");
		userInfo.setGivenName("given_name");
		userInfo.setFamilyName("family_name");
		userInfo.setMiddleName("middle_name");
		userInfo.setNickname("nickname");
		userInfo.setPreferredUsername("preferred_username");
		userInfo.setProfile(new URI("https://profile.com"));
		userInfo.setPicture(new URI("https://picture.com"));
		userInfo.setWebsite(new URI("https://website.com"));
		userInfo.setEmailAddress("name@domain.com");
		userInfo.setEmailVerified(true);
		userInfo.setGender(Gender.FEMALE);
		userInfo.setBirthdate("1992-01-31");
		userInfo.setZoneinfo("Europe/Paris");
		userInfo.setLocale("en-GB");
		userInfo.setPhoneNumber("phone_number");
		userInfo.setPhoneNumberVerified(true);

		Address address = new Address();
		address.setFormatted("formatted");
		address.setStreetAddress("street_address");
		address.setLocality("locality");
		address.setRegion("region");
		address.setPostalCode("postal_code");
		address.setCountry("country");

		userInfo.setAddress(address);

		userInfo.setUpdatedTime(DateUtils.fromSecondsSinceEpoch(100000l));

		assertEquals("sub", userInfo.getSubject().getValue());
		assertEquals("given_name", userInfo.getGivenName());
		assertEquals("family_name", userInfo.getFamilyName());
		assertEquals("middle_name", userInfo.getMiddleName());
		assertEquals("nickname", userInfo.getNickname());
		assertEquals("preferred_username", userInfo.getPreferredUsername());
		assertEquals("https://profile.com", userInfo.getProfile().toString());
		assertEquals("https://picture.com", userInfo.getPicture().toString());
		assertEquals("https://website.com", userInfo.getWebsite().toString());
		assertEquals("name@domain.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		assertEquals(Gender.FEMALE, userInfo.getGender());
		assertEquals("1992-01-31", userInfo.getBirthdate());
		assertEquals("Europe/Paris", userInfo.getZoneinfo());
		assertEquals("en-GB", userInfo.getLocale());
		assertEquals("phone_number", userInfo.getPhoneNumber());
		assertTrue(userInfo.getPhoneNumberVerified());

		address = userInfo.getAddress();
		assertEquals("formatted", address.getFormatted());
		assertEquals("street_address", address.getStreetAddress());
		assertEquals("locality", address.getLocality());
		assertEquals("region", address.getRegion());
		assertEquals("postal_code", address.getPostalCode());
		assertEquals("country", address.getCountry());

		String json = userInfo.toJSONObject().toString();

		userInfo = UserInfo.parse(json);

		assertEquals("sub", userInfo.getSubject().getValue());
		assertEquals("given_name", userInfo.getGivenName());
		assertEquals("family_name", userInfo.getFamilyName());
		assertEquals("middle_name", userInfo.getMiddleName());
		assertEquals("nickname", userInfo.getNickname());
		assertEquals("preferred_username", userInfo.getPreferredUsername());
		assertEquals("https://profile.com", userInfo.getProfile().toString());
		assertEquals("https://picture.com", userInfo.getPicture().toString());
		assertEquals("https://website.com", userInfo.getWebsite().toString());
		assertEquals("name@domain.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		assertEquals(Gender.FEMALE, userInfo.getGender());
		assertEquals("1992-01-31", userInfo.getBirthdate());
		assertEquals("Europe/Paris", userInfo.getZoneinfo());
		assertEquals("en-GB", userInfo.getLocale());
		assertEquals("phone_number", userInfo.getPhoneNumber());
		assertTrue(userInfo.getPhoneNumberVerified());

		address = userInfo.getAddress();
		assertEquals("formatted", address.getFormatted());
		assertEquals("street_address", address.getStreetAddress());
		assertEquals("locality", address.getLocality());
		assertEquals("region", address.getRegion());
		assertEquals("postal_code", address.getPostalCode());
		assertEquals("country", address.getCountry());
	}

	
	public void testGettersAndSetters_withDeprecatedEmail()
		throws Exception {

		UserInfo userInfo = new UserInfo(new Subject("sub"));

		userInfo.setName("name");
		userInfo.setGivenName("given_name");
		userInfo.setFamilyName("family_name");
		userInfo.setMiddleName("middle_name");
		userInfo.setNickname("nickname");
		userInfo.setPreferredUsername("preferred_username");
		userInfo.setProfile(new URI("https://profile.com"));
		userInfo.setPicture(new URI("https://picture.com"));
		userInfo.setWebsite(new URI("https://website.com"));
		userInfo.setEmail(new InternetAddress("name@domain.com"));
		userInfo.setEmailVerified(true);
		userInfo.setGender(Gender.FEMALE);
		userInfo.setBirthdate("1992-01-31");
		userInfo.setZoneinfo("Europe/Paris");
		userInfo.setLocale("en-GB");
		userInfo.setPhoneNumber("phone_number");
		userInfo.setPhoneNumberVerified(true);

		Address address = new Address();
		address.setFormatted("formatted");
		address.setStreetAddress("street_address");
		address.setLocality("locality");
		address.setRegion("region");
		address.setPostalCode("postal_code");
		address.setCountry("country");

		userInfo.setAddress(address);

		userInfo.setUpdatedTime(DateUtils.fromSecondsSinceEpoch(100000l));

		assertEquals("sub", userInfo.getSubject().getValue());
		assertEquals("given_name", userInfo.getGivenName());
		assertEquals("family_name", userInfo.getFamilyName());
		assertEquals("middle_name", userInfo.getMiddleName());
		assertEquals("nickname", userInfo.getNickname());
		assertEquals("preferred_username", userInfo.getPreferredUsername());
		assertEquals("https://profile.com", userInfo.getProfile().toString());
		assertEquals("https://picture.com", userInfo.getPicture().toString());
		assertEquals("https://website.com", userInfo.getWebsite().toString());
		assertEquals("name@domain.com", userInfo.getEmail().getAddress());
		assertTrue(userInfo.getEmailVerified());
		assertEquals(Gender.FEMALE, userInfo.getGender());
		assertEquals("1992-01-31", userInfo.getBirthdate());
		assertEquals("Europe/Paris", userInfo.getZoneinfo());
		assertEquals("en-GB", userInfo.getLocale());
		assertEquals("phone_number", userInfo.getPhoneNumber());
		assertTrue(userInfo.getPhoneNumberVerified());

		address = userInfo.getAddress();
		assertEquals("formatted", address.getFormatted());
		assertEquals("street_address", address.getStreetAddress());
		assertEquals("locality", address.getLocality());
		assertEquals("region", address.getRegion());
		assertEquals("postal_code", address.getPostalCode());
		assertEquals("country", address.getCountry());

		String json = userInfo.toJSONObject().toString();

		userInfo = UserInfo.parse(json);

		assertEquals("sub", userInfo.getSubject().getValue());
		assertEquals("given_name", userInfo.getGivenName());
		assertEquals("family_name", userInfo.getFamilyName());
		assertEquals("middle_name", userInfo.getMiddleName());
		assertEquals("nickname", userInfo.getNickname());
		assertEquals("preferred_username", userInfo.getPreferredUsername());
		assertEquals("https://profile.com", userInfo.getProfile().toString());
		assertEquals("https://picture.com", userInfo.getPicture().toString());
		assertEquals("https://website.com", userInfo.getWebsite().toString());
		assertEquals("name@domain.com", userInfo.getEmail().getAddress());
		assertTrue(userInfo.getEmailVerified());
		assertEquals(Gender.FEMALE, userInfo.getGender());
		assertEquals("1992-01-31", userInfo.getBirthdate());
		assertEquals("Europe/Paris", userInfo.getZoneinfo());
		assertEquals("en-GB", userInfo.getLocale());
		assertEquals("phone_number", userInfo.getPhoneNumber());
		assertTrue(userInfo.getPhoneNumberVerified());

		address = userInfo.getAddress();
		assertEquals("formatted", address.getFormatted());
		assertEquals("street_address", address.getStreetAddress());
		assertEquals("locality", address.getLocality());
		assertEquals("region", address.getRegion());
		assertEquals("postal_code", address.getPostalCode());
		assertEquals("country", address.getCountry());
	}


	public void testLanguageTaggedGettersAndSetters()
		throws Exception {

		UserInfo userInfo = new UserInfo(new Subject("sub"));

		userInfo.setName("name#en", LangTag.parse("en"));
		userInfo.setName("name#bg", LangTag.parse("bg"));

		userInfo.setGivenName("given_name#en", LangTag.parse("en"));
		userInfo.setGivenName("given_name#bg", LangTag.parse("bg"));

		userInfo.setFamilyName("family_name#en", LangTag.parse("en"));
		userInfo.setFamilyName("family_name#bg", LangTag.parse("bg"));

		userInfo.setMiddleName("middle_name#en", LangTag.parse("en"));
		userInfo.setMiddleName("middle_name#bg", LangTag.parse("bg"));

		userInfo.setNickname("nickname#en", LangTag.parse("en"));
		userInfo.setNickname("nickname#bg", LangTag.parse("bg"));

		Address address = new Address();
		address.setFormatted("formatted#en");

		userInfo.setAddress(address, LangTag.parse("en"));

		address = new Address();
		address.setFormatted("formatted#bg");

		userInfo.setAddress(address, LangTag.parse("bg"));

		assertEquals("name#en", userInfo.getName(LangTag.parse("en")));
		assertEquals("name#bg", userInfo.getName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNameEntries().size());

		assertEquals("given_name#en", userInfo.getGivenName(LangTag.parse("en")));
		assertEquals("given_name#bg", userInfo.getGivenName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getGivenNameEntries().size());

		assertEquals("family_name#en", userInfo.getFamilyName(LangTag.parse("en")));
		assertEquals("family_name#bg", userInfo.getFamilyName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getFamilyNameEntries().size());

		assertEquals("middle_name#en", userInfo.getMiddleName(LangTag.parse("en")));
		assertEquals("middle_name#bg", userInfo.getMiddleName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getMiddleNameEntries().size());

		assertEquals("nickname#en", userInfo.getNickname(LangTag.parse("en")));
		assertEquals("nickname#bg", userInfo.getNickname(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNicknameEntries().size());

		assertEquals("formatted#en", userInfo.getAddress(LangTag.parse("en")).getFormatted());
		assertEquals("formatted#bg", userInfo.getAddress(LangTag.parse("bg")).getFormatted());
		assertEquals(2, userInfo.getAddressEntries().size());

		String json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("name#en", userInfo.getName(LangTag.parse("en")));
		assertEquals("name#bg", userInfo.getName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNameEntries().size());

		assertEquals("given_name#en", userInfo.getGivenName(LangTag.parse("en")));
		assertEquals("given_name#bg", userInfo.getGivenName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getGivenNameEntries().size());

		assertEquals("family_name#en", userInfo.getFamilyName(LangTag.parse("en")));
		assertEquals("family_name#bg", userInfo.getFamilyName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getFamilyNameEntries().size());

		assertEquals("middle_name#en", userInfo.getMiddleName(LangTag.parse("en")));
		assertEquals("middle_name#bg", userInfo.getMiddleName(LangTag.parse("bg")));
		assertEquals(2, userInfo.getMiddleNameEntries().size());

		assertEquals("nickname#en", userInfo.getNickname(LangTag.parse("en")));
		assertEquals("nickname#bg", userInfo.getNickname(LangTag.parse("bg")));
		assertEquals(2, userInfo.getNicknameEntries().size());

		assertEquals("formatted#en", userInfo.getAddress(LangTag.parse("en")).getFormatted());
		assertEquals("formatted#bg", userInfo.getAddress(LangTag.parse("bg")).getFormatted());
		assertEquals(2, userInfo.getAddressEntries().size());
	}


	public void testPutAll() {

		Subject alice = new Subject("alice");

		UserInfo userInfo = new UserInfo(alice);
		userInfo.setGivenName("Alice");

		UserInfo other = new UserInfo(alice);
		other.setFamilyName("Adams");

		userInfo.putAll(other);
		assertEquals(alice, userInfo.getSubject());
		assertEquals("Alice", userInfo.getGivenName());
		assertEquals("Adams", userInfo.getFamilyName());
		assertEquals(3, userInfo.toJSONObject().size());
	}


	public void testPullAllSubjectMismatch() {

		Subject alice = new Subject("alice");
		Subject bob = new Subject("bob");

		UserInfo userInfoAlice = new UserInfo(alice);
		userInfoAlice.setGivenName("Alice");

		UserInfo userInfoBob = new UserInfo(bob);
		userInfoBob.setGivenName("Bob");

		try {
			userInfoAlice.putAll(userInfoBob);

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testPutAllMap() {

		UserInfo userInfo = new UserInfo(new Subject("alice"));
		userInfo.setName("Alice");
		assertEquals("Alice", userInfo.getStringClaim("name"));

		Map<String,Object> claims = new HashMap<>();
		claims.put("name", "Alice Wonderland");
		claims.put("given_name", "Alice");

		userInfo.putAll(claims);
		assertEquals("Alice Wonderland", userInfo.getName());
		assertEquals("Alice", userInfo.getGivenName());
	}
	
	
	public void testParseInvalidEmailAddress_ignore()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		o.put("sub", "alice");
		o.put("email", "invalid-email");
		
		UserInfo userInfo = UserInfo.parse(o.toJSONString());
		
		assertEquals("invalid-email", userInfo.getEmailAddress());
		
		assertNull(userInfo.getEmail()); // exception swallowed
	}
	
	
	public void testAggregatedClaims_addAndGet() {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		JSONObject c1 = new JSONObject();
		c1.put("email", "alice@wonderland.net");
		c1.put("email_verified", true);
		
		JWT jwt1 = AggregatedClaimsTest.createClaimsJWT(c1);
		
		AggregatedClaims a1 = new AggregatedClaims("src1", c1.keySet(), jwt1);
		userInfo.addAggregatedClaims(a1);
		
		JSONObject c2 = new JSONObject();
		c2.put("score", "100");
		
		JWT jwt2 = AggregatedClaimsTest.createClaimsJWT(c2);
		
		AggregatedClaims a2 = new AggregatedClaims("src2", c2.keySet(), jwt2);
		userInfo.addAggregatedClaims(a2);
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		assertEquals("alice", jsonObject.get("sub"));
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals("src2", ((JSONObject)jsonObject.get("_claim_names")).get("score"));
		assertEquals(3, ((JSONObject)jsonObject.get("_claim_names")).size());
		assertEquals(jwt1.serialize(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).get("JWT"));
		assertEquals(jwt2.serialize(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).get("JWT"));
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_sources")).size());
		assertEquals(3, jsonObject.size());
		
		Set<AggregatedClaims> set = userInfo.getAggregatedClaims();
		
		for(AggregatedClaims c: set) {
			
			AggregatedClaims ref = null;
			
			if (a1.getSourceID().equals(c.getSourceID())) {
				
				ref = a1;
				
			} else if (a2.getSourceID().equals(c.getSourceID())) {
				
				ref = a2;
				
			} else {
				fail();
			}
			
			assertEquals(ref.getNames(), c.getNames());
			assertEquals(ref.getClaimsJWT().serialize(), c.getClaimsJWT().serialize());
		}
		
		assertEquals(2, set.size());
	}
	
	
	public void testDistributedClaims_addAndGet()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		DistributedClaims d1 = new DistributedClaims(
			"src1",
			new HashSet<>(Arrays.asList("email", "email_verified")),
			new URI("https://claims-provider.com"),
			new BearerAccessToken()
		);
		userInfo.addDistributedClaims(d1);
		
		DistributedClaims d2 = new DistributedClaims(
			"src2",
			Collections.singleton("score"),
			new URI("https://other-provider.com"),
			null
		);
		userInfo.addDistributedClaims(d2);
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		assertEquals("alice", jsonObject.get("sub"));
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals("src2", ((JSONObject)jsonObject.get("_claim_names")).get("score"));
		assertEquals(3, ((JSONObject)jsonObject.get("_claim_names")).size());
		assertEquals(d1.getSourceEndpoint().toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).get("endpoint"));
		assertEquals(d1.getAccessToken().getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).size());
		assertEquals(d2.getSourceEndpoint().toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).get("endpoint"));
		assertEquals(1, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).size());
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_sources")).size());
		assertEquals(3, jsonObject.size());
		
		Set<DistributedClaims> set = userInfo.getDistributedClaims();
		
		for(DistributedClaims c: set) {
			
			DistributedClaims ref = null;
			
			if (d1.getSourceID().equals(c.getSourceID())) {
				
				ref = d1;
				
			} else if (d2.getSourceID().equals(c.getSourceID())) {
				
				ref = d2;
				
			} else {
				fail();
			}
			
			assertEquals(ref.getNames(), c.getNames());
			assertEquals(ref.getSourceEndpoint(), c.getSourceEndpoint());
			if (ref.getAccessToken() != null) {
				assertEquals(ref.getAccessToken().getValue(), c.getAccessToken().getValue());
			}
		}
		
		assertEquals(2, set.size());
	}
	
	
	public void testParseDistributedClaimsExample()
		throws Exception {
	
		String json = 
			"{" +
			"   \"sub\":\"jd\"," + // fix example, missing 'sub'
			"   \"name\": \"Jane Doe\"," +
			"   \"given_name\": \"Jane\"," +
			"   \"family_name\": \"Doe\"," +
			"   \"email\": \"janedoe@example.com\"," +
			"   \"birthdate\": \"0000-03-22\"," +
			"   \"eye_color\": \"blue\"," +
			"   \"_claim_names\": {" +
			"     \"payment_info\": \"src1\"," +
			"     \"shipping_address\": \"src1\"," +
			"     \"credit_score\": \"src2\"" +
			"    }," +
			"   \"_claim_sources\": {" +
			"     \"src1\": {\"endpoint\":" +
			"                \"https://bank.example.com/claim_source\"}," +
			"     \"src2\": {\"endpoint\":" +
			"                \"https://creditagency.example.com/claims_here\"," +
			"              \"access_token\": \"ksj3n283dke\"}" +
			"   }" +
			"  }";
		
		UserInfo userInfo = UserInfo.parse(json);
	
		Set<DistributedClaims> dcSet = userInfo.getDistributedClaims();
		
		for (DistributedClaims dc: dcSet) {
			
			if ("src1".equals(dc.getSourceID())) {
				
				assertTrue(dc.getNames().contains("payment_info"));
				assertTrue(dc.getNames().contains("shipping_address"));
				assertEquals(2, dc.getNames().size());
				
				assertEquals("https://bank.example.com/claim_source", dc.getSourceEndpoint().toString());
				assertNull(dc.getAccessToken());
				
			} else if ("src2".equals(dc.getSourceID())) {
				
				assertTrue(dc.getNames().contains("credit_score"));
				assertEquals(1, dc.getNames().size());
				
				assertEquals("https://creditagency.example.com/claims_here", dc.getSourceEndpoint().toString());
				assertEquals("ksj3n283dke", dc.getAccessToken().getValue());
				assertTrue(dc.getAccessToken() instanceof TypelessAccessToken);
				
			} else {
				fail();
			}
		}
		
		assertEquals(2, dcSet.size());
	}
	
	
	public void testPutAll_mergeAggregatedAndDistributedClaims()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		AggregatedClaims ac = new AggregatedClaims(
			"src1",
			new HashSet<>(Arrays.asList("email", "email_verified")),
			AggregatedClaimsTest.createClaimsJWT()
			);
		
		userInfo.addAggregatedClaims(ac);
		
		assertEquals(1, userInfo.getAggregatedClaims().size());
		
		UserInfo other = new UserInfo(new Subject("alice"));
		
		DistributedClaims dc = new DistributedClaims(
			"src2",
			Collections.singleton("score"),
			new URI("https://claims-source.com"),
			new BearerAccessToken());
		
		other.addDistributedClaims(dc);
		
		assertEquals(1, other.getDistributedClaims().size());
		
		userInfo.putAll(other);
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		// Check merge
		assertEquals(new Subject("alice"), userInfo.getSubject());
		
		assertEquals(ac.getSourceID(), userInfo.getAggregatedClaims().iterator().next().getSourceID());
		assertEquals(ac.getNames(), userInfo.getAggregatedClaims().iterator().next().getNames());
		assertEquals(ac.getClaimsJWT().serialize(), userInfo.getAggregatedClaims().iterator().next().getClaimsJWT().serialize());
		
		assertEquals(dc.getSourceID(), userInfo.getDistributedClaims().iterator().next().getSourceID());
		assertEquals(dc.getNames(), userInfo.getDistributedClaims().iterator().next().getNames());
		assertEquals(dc.getSourceEndpoint(), userInfo.getDistributedClaims().iterator().next().getSourceEndpoint());
		assertEquals(dc.getAccessToken().getValue(), userInfo.getDistributedClaims().iterator().next().getAccessToken().getValue());
		
		assertEquals("alice", jsonObject.get("sub"));
		
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals("src2", ((JSONObject)jsonObject.get("_claim_names")).get("score"));
		assertEquals(3, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(ac.getClaimsJWT().serialize(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).get("JWT"));
		assertEquals(1, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).size());
		
		assertEquals(dc.getSourceEndpoint().toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).get("endpoint"));
		assertEquals(dc.getAccessToken().getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).size());
		
		assertEquals(3, jsonObject.size());
	}
	
	
	public void testPutAll_mergeDistributedClaims()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		DistributedClaims dc1 = new DistributedClaims(
			"src1",
			new HashSet<>(Arrays.asList("email", "email_verified")),
			new URI("https://claims-source.com"),
			new BearerAccessToken()
			);
		
		userInfo.addDistributedClaims(dc1);
		
		assertEquals(1, userInfo.getDistributedClaims().size());
		
		UserInfo other = new UserInfo(new Subject("alice"));
		
		DistributedClaims dc2 = new DistributedClaims(
			"src2",
			Collections.singleton("score"),
			new URI("https://other-claims-source.com"),
			new BearerAccessToken());
		
		other.addDistributedClaims(dc2);
		
		assertEquals(1, other.getDistributedClaims().size());
		
		userInfo.putAll(other);
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		// Check merge
		assertEquals(new Subject("alice"), userInfo.getSubject());
		
		for (DistributedClaims dc: userInfo.getDistributedClaims()) {
			
			DistributedClaims ref = null;
			
			if (dc.getSourceID().equals(dc1.getSourceID())) {
				ref = dc1;
			} else if (dc.getSourceID().equals(dc2.getSourceID())) {
				ref = dc2;
			} else {
				fail();
			}
			
			assertEquals(ref.getSourceID(), dc.getSourceID());
			assertEquals(ref.getSourceEndpoint(), dc.getSourceEndpoint());
			assertEquals(ref.getAccessToken().getValue(), dc.getAccessToken().getValue());
		}
		
		assertEquals("alice", jsonObject.get("sub"));
		
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals("src1", ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals("src2", ((JSONObject)jsonObject.get("_claim_names")).get("score"));
		assertEquals(3, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(dc1.getSourceEndpoint().toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).get("endpoint"));
		assertEquals(dc1.getAccessToken().getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src1")).size());
		
		assertEquals(dc2.getSourceEndpoint().toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).get("endpoint"));
		assertEquals(dc2.getAccessToken().getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get("src2")).size());
		
		assertEquals(3, jsonObject.size());
	}
	
	
	public void testPutAll_withExternalClaims_preventSourceIDConflict()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		AggregatedClaims ac = new AggregatedClaims(
			"src1",
			new HashSet<>(Arrays.asList("email", "email_verified")),
			AggregatedClaimsTest.createClaimsJWT()
			);
		
		userInfo.addAggregatedClaims(ac);
		
		assertEquals(1, userInfo.getAggregatedClaims().size());
		
		UserInfo other = new UserInfo(new Subject("alice"));
		
		DistributedClaims dc = new DistributedClaims(
			"src1", // same!!!
			Collections.singleton("score"),
			new URI("https://claims-source.com"),
			new BearerAccessToken());
		
		other.addDistributedClaims(dc);
		
		assertEquals(1, other.getDistributedClaims().size());
		
		try {
			userInfo.putAll(other);
		} catch (IllegalArgumentException e) {
			assertEquals("Distributed claims source ID conflict: src1", e.getMessage());
		}
	}
	
	
	public void testIssuerClaim()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		assertNull(userInfo.getIssuer());
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		userInfo.setIssuer(issuer);
		
		assertEquals(issuer, userInfo.getIssuer());
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		assertEquals(userInfo.getSubject().getValue(), jsonObject.get("sub"));
		assertEquals(issuer.getValue(), jsonObject.get("iss"));
		assertEquals(2, jsonObject.size());
		
		userInfo = UserInfo.parse(jsonObject.toJSONString());
		
		assertEquals(issuer, userInfo.getIssuer());
		
		userInfo.setIssuer(null);
		
		assertNull(userInfo.getIssuer());
	}
	
	
	
	public void testAudienceClaim_single()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		assertNull(userInfo.getAudience());
		
		Audience aud = new Audience("123");
		
		userInfo.setAudience(aud);
		
		assertEquals(aud.toSingleAudienceList(), userInfo.getAudience());
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		assertEquals(Audience.toStringList(aud), JSONObjectUtils.getStringList(jsonObject, "aud"));
		
		userInfo = UserInfo.parse(jsonObject.toJSONString());
		
		assertEquals(aud.toSingleAudienceList(), userInfo.getAudience());
		
		userInfo.setAudience((Audience) null);
		
		assertNull(userInfo.getAudience());
	}
	
	
	
	public void testAudienceClaim_list()
		throws Exception {
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		
		assertNull(userInfo.getAudience());
		
		List<Audience> audList = Arrays.asList(new Audience("123"), new Audience("456"));
		
		userInfo.setAudience(audList);
		
		assertEquals(audList, userInfo.getAudience());
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		assertEquals(Audience.toStringList(audList), JSONObjectUtils.getStringList(jsonObject, "aud"));
		
		userInfo = UserInfo.parse(jsonObject.toJSONString());
		
		assertEquals(audList, userInfo.getAudience());
		
		userInfo.setAudience((List<Audience>)null);
		
		assertNull(userInfo.getAudience());
	}
	
	
	// Identity assurance
	public void testParseExample_1() throws ParseException {
		
		String json = "{  " +
			"   \"sub\":\"248289761001\"," +
			"   \"email\":\"janedoe@example.com\"," +
			"   \"email_verified\":true," +
			"   \"verified_claims\":{  " +
			"      \"verification\":{  " +
			"         \"trust_framework\":\"de_aml\"," +
			"         \"time\":\"2012-04-23T18:25:43.511+01\"," +
			"         \"verification_process\":\"676q3636461467647q8498785747q487\"," +
			"         \"evidence\":[  " +
			"            {  " +
			"               \"type\":\"id_document\"," +
			"               \"method\":\"pipp\"," +
			"               \"document\":{  " +
			"                  \"type\":\"idcard\"," +
			"                  \"issuer\":{  " +
			"                     \"name\":\"Stadt Augsburg\"," +
			"                     \"country\":\"DE\"" +
			"                  }," +
			"                  \"number\":\"53554554\"," +
			"                  \"date_of_issuance\":\"2012-04-23\"," +
			"                  \"date_of_expiry\":\"2022-04-22\"" +
			"               }" +
			"            }" +
			"         ]" +
			"      }," +
			"      \"claims\":{  " +
			"         \"given_name\":\"Max\"," +
			"         \"family_name\":\"Meier\"," +
			"         \"birthdate\":\"1956-01-28\"" +
			"      }" +
			"   }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("248289761001"), userInfo.getSubject());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		
		Map<String,Object> verifiedClaimsMap = (Map<String,Object>)userInfo.getClaim("verified_claims", Map.class);
		System.out.println(verifiedClaimsMap);
	}
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/response/userinfo.json
	public void testAssurance_basicUserInfo()
		throws Exception {
		
		String json = "{" +
			"  \"sub\": \"248289761001\"," +
			"  \"email\": \"janedoe@example.com\"," +
			"  \"email_verified\": true," +
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25:43Z\"," +
			"      \"verification_process\": \"f24c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"id_document\"," +
			"          \"method\": \"pipp\"," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document\": {" +
			"            \"type\": \"idcard\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Stadt Augsburg\"," +
			"              \"country\": \"DE\"" +
			"            }," +
			"            \"number\": \"53554554\"," +
			"            \"date_of_issuance\": \"2010-03-23\"," +
			"            \"date_of_expiry\": \"2020-03-22\"" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		
		VerifiedClaimsSet verifiedClaims = userInfo.getVerifiedClaims().get(0);
		
		IdentityVerification verification = verifiedClaims.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals("2012-04-23T18:25:43Z", verification.getVerificationTime().toISO8601String());
		assertEquals(new VerificationProcess("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"), verification.getVerificationProcess());
		
		IDDocumentEvidence evidence = verification.getEvidence().get(0).toIDDocumentEvidence();
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, evidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getVerificationMethod());
		IDDocumentDescription idDoc = evidence.getIdentityDocument();
		assertEquals(IDDocumentType.IDCARD, idDoc.getType());
		assertEquals("Stadt Augsburg", idDoc.getIssuerName());
		assertEquals("DE", idDoc.getIssuerCountry().getValue());
		assertEquals("53554554", idDoc.getNumber());
		assertEquals("2010-03-23", idDoc.getDateOfIssuance().toISO8601String());
		assertEquals("2020-03-22", idDoc.getDateOfExpiry().toISO8601String());
		
		PersonClaims verifiedPersonClaims = verifiedClaims.getClaimsSet();
		assertEquals("Max", verifiedPersonClaims.getGivenName());
		assertEquals("Meier", verifiedPersonClaims.getFamilyName());
		assertEquals("1956-01-28", verifiedPersonClaims.getBirthdate());
	}
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/response/aggregated_claims.json
	public void testAssurance_aggregatedExample() throws Exception {
	
		String json = "{" +
			"  \"iss\": \"https://server.example.com\"," +
			"  \"sub\": \"248289761001\"," +
			"  \"email\": \"janedoe@example.com\"," +
			"  \"email_verified\": true," +
			"  \"_claim_names\": {" +
			"    \"verified_claims\": \"src1\"" +
			"  }," +
			"  \"_claim_sources\": {" +
			"    \"src1\": {" +
			"      \"JWT\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwcz" +
			"ovL3NlcnZlci5vdGhlcm9wLmNvbSIsInN1YiI6ImU4MTQ4NjAzLTg5MzQtNDI0N" +
			"S04MjViLWMxMDhiOGI2Yjk0NSIsInZlcmlmaWVkX2NsYWltcyI6eyJ2ZXJpZmlj" +
			"YXRpb24iOnsidHJ1c3RfZnJhbWV3b3JrIjoiaWFsX2V4YW1wbGVfZ29sZCJ9LCJ" +
			"jbGFpbXMiOnsiZ2l2ZW5fbmFtZSI6Ik1heCIsImZhbWlseV9uYW1lIjoiTWVpZX" +
			"IiLCJiaXJ0aGRhdGUiOiIxOTU2LTAxLTI4In19fQ.FArlPUtUVn95HCExePlWJQ" +
			"6ctVfVpQyeSbe3xkH9MH1QJjnk5GVbBW0qe1b7R3lE-8iVv__0mhRTUI5lcFhLj" +
			"oGjDS8zgWSarVsEEjwBK7WD3r9cEw6ZAhfEkhHL9eqAaED2rhhDbHD5dZWXkJCu" +
			"XIcn65g6rryiBanxlXK0ZmcK4fD9HV9MFduk0LRG_p4yocMaFvVkqawat5NV9QQ" +
			"3ij7UBr3G7A4FojcKEkoJKScdGoozir8m5XD83Sn45_79nCcgWSnCX2QTukL8Ny" +
			"wIItu_K48cjHiAGXXSzydDm_ccGCe0sY-Ai2-iFFuQo2PtfuK2SqPPmAZJxEFrF" +
			"oLY4g\"" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		assertEquals(new Issuer("https://server.example.com"), userInfo.getIssuer());
		assertEquals(new Subject("248289761001"), userInfo.getSubject());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		
		Set<AggregatedClaims> aggregatedClaimsSet = userInfo.getAggregatedClaims();
		assertEquals(1, aggregatedClaimsSet.size());
		AggregatedClaims claims = aggregatedClaimsSet.iterator().next();
		assertEquals("src1", claims.getSourceID());
		JWT jwt = claims.getClaimsJWT();
		assertEquals(JOSEObjectType.JWT, jwt.getHeader().getType());
		assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
		UserInfo aggregatedUserInfo = UserInfo.parse(jwt.getJWTClaimsSet().toString());
		// {"sub":"e8148603-8934-4245-825b-c108b8b6b945",
		// "verified_claims":{
		// 	"claims":{"birthdate":"1956-01-28","given_name":"Max","family_name":"Meier"},
		// 	"verification":{"trust_framework":"ial_example_gold"}},
		// "iss":"https:\/\/server.otherop.com"}
		assertEquals(new Subject("e8148603-8934-4245-825b-c108b8b6b945"), aggregatedUserInfo.getSubject());
		assertEquals(new Issuer("https://server.otherop.com"), aggregatedUserInfo.getIssuer());
		VerifiedClaimsSet verifiedClaimsSet = aggregatedUserInfo.getVerifiedClaims().get(0);
		assertEquals(new IdentityTrustFramework("ial_example_gold"), verifiedClaimsSet.getVerification().getTrustFramework());
		assertEquals("1956-01-28", verifiedClaimsSet.getClaimsSet().getBirthdate());
		assertEquals("Max", verifiedClaimsSet.getClaimsSet().getGivenName());
		assertEquals("Meier", verifiedClaimsSet.getClaimsSet().getFamilyName());
		assertEquals(3, verifiedClaimsSet.getClaimsSet().toJSONObject().size());
	}
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/response/all_in_one.json
	public void testAssurance_allInOneExample() throws Exception {
		
		String json = "{" +
			"  \"iss\": \"https://server.example.com\"," +
			"  \"sub\": \"248289761001\"," +
			"  \"email\": \"janedoe@example.com\"," +
			"  \"email_verified\": true," +
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"ial_example_gold\"" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"" +
			"    }" +
			"  }," +
			"  \"_claim_names\": {" +
			"    \"verified_claims\": [" +
			"      \"src1\"," +
			"      \"src2\"" +
			"    ]" +
			"  }," +
			"  \"_claim_sources\": {" +
			"    \"src1\": {" +
			"      \"JWT\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwcz" +
			"ovL3NlcnZlci5vdGhlcm9wLmNvbSIsInN1YiI6ImU4MTQ4NjAzLTg5MzQtNDI0N" +
			"S04MjViLWMxMDhiOGI2Yjk0NSIsInZlcmlmaWVkX2NsYWltcyI6eyJ2ZXJpZmlj" +
			"YXRpb24iOnsidHJ1c3RfZnJhbWV3b3JrIjoiaWFsX2V4YW1wbGVfZ29sZCJ9LCJ" +
			"jbGFpbXMiOnsiZ2l2ZW5fbmFtZSI6Ik1heCIsImZhbWlseV9uYW1lIjoiTWVpZX" +
			"IiLCJiaXJ0aGRhdGUiOiIxOTU2LTAxLTI4In19fQ.FArlPUtUVn95HCExePlWJQ" +
			"6ctVfVpQyeSbe3xkH9MH1QJjnk5GVbBW0qe1b7R3lE-8iVv__0mhRTUI5lcFhLj" +
			"oGjDS8zgWSarVsEEjwBK7WD3r9cEw6ZAhfEkhHL9eqAaED2rhhDbHD5dZWXkJCu" +
			"XIcn65g6rryiBanxlXK0ZmcK4fD9HV9MFduk0LRG_p4yocMaFvVkqawat5NV9QQ" +
			"3ij7UBr3G7A4FojcKEkoJKScdGoozir8m5XD83Sn45_79nCcgWSnCX2QTukL8Ny" +
			"wIItu_K48cjHiAGXXSzydDm_ccGCe0sY-Ai2-iFFuQo2PtfuK2SqPPmAZJxEFrF" +
			"oLY4g\"" +
			"    }," +
			"    \"src2\": {" +
			"      \"endpoint\": \"https://server.yetanotherop.com/claim_source\"," +
			"      \"access_token\": \"ksj3n283dkeafb76cdef\"" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		assertEquals(new Issuer("https://server.example.com"), userInfo.getIssuer());
		assertEquals(new Subject("248289761001"), userInfo.getSubject());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		
		VerifiedClaimsSet topLevelVerifiedClaimsSet = userInfo.getVerifiedClaims().get(0);
		assertEquals(new IdentityTrustFramework("ial_example_gold"), topLevelVerifiedClaimsSet.getVerification().getTrustFramework());
		assertEquals("Max", topLevelVerifiedClaimsSet.getClaimsSet().getGivenName());
		assertEquals("Meier", topLevelVerifiedClaimsSet.getClaimsSet().getFamilyName());
		assertEquals(2, topLevelVerifiedClaimsSet.getClaimsSet().toJSONObject().size());
		
		Set<AggregatedClaims> aggregatedClaimsSet = userInfo.getAggregatedClaims();
		assertEquals(1, aggregatedClaimsSet.size());
		AggregatedClaims aggregatedClaims = aggregatedClaimsSet.iterator().next();
		assertEquals("src1", aggregatedClaims.getSourceID());
		JWT jwt = aggregatedClaims.getClaimsJWT();
		assertEquals(JOSEObjectType.JWT, jwt.getHeader().getType());
		assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
		UserInfo aggregatedUserInfo = UserInfo.parse(jwt.getJWTClaimsSet().toString());
		// {"sub":"e8148603-8934-4245-825b-c108b8b6b945",
		// "verified_claims":{
		// 	"claims":{"birthdate":"1956-01-28","given_name":"Max","family_name":"Meier"},
		// 	"verification":{"trust_framework":"ial_example_gold"}},
		// "iss":"https:\/\/server.otherop.com"}
		assertEquals(new Subject("e8148603-8934-4245-825b-c108b8b6b945"), aggregatedUserInfo.getSubject());
		assertEquals(new Issuer("https://server.otherop.com"), aggregatedUserInfo.getIssuer());
		VerifiedClaimsSet verifiedClaimsSet = aggregatedUserInfo.getVerifiedClaims().get(0);
		assertEquals(new IdentityTrustFramework("ial_example_gold"), verifiedClaimsSet.getVerification().getTrustFramework());
		assertEquals("1956-01-28", verifiedClaimsSet.getClaimsSet().getBirthdate());
		assertEquals("Max", verifiedClaimsSet.getClaimsSet().getGivenName());
		assertEquals("Meier", verifiedClaimsSet.getClaimsSet().getFamilyName());
		assertEquals(3, verifiedClaimsSet.getClaimsSet().toJSONObject().size());
		
		Set<DistributedClaims> distributedClaimsSet = userInfo.getDistributedClaims();
		assertEquals(1, distributedClaimsSet.size());
		DistributedClaims dClaims = distributedClaimsSet.iterator().next();
		assertEquals("src2", dClaims.getSourceID());
		assertEquals(new URI("https://server.yetanotherop.com/claim_source"), dClaims.getSourceEndpoint());
		assertEquals("ksj3n283dkeafb76cdef", dClaims.getAccessToken().getValue());
	}
	
	
	public void testAssurance_distributedExample() throws Exception {
		
		String json = "{" +
			"  \"iss\": \"https://server.example.com\"," +
			"  \"sub\": \"248289761001\"," +
			"  \"email\": \"janedoe@example.com\"," +
			"  \"email_verified\": true," +
			"  \"_claim_names\": {" +
			"    \"verified_claims\": \"src1\"" +
			"  }," +
			"  \"_claim_sources\": {" +
			"    \"src1\": {" +
			"      \"endpoint\": \"https://server.yetanotherop.com/claim_source\"," +
			"      \"access_token\": \"ksj3n283dkeafb76cdef\"" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		assertEquals(new Issuer("https://server.example.com"), userInfo.getIssuer());
		assertEquals(new Subject("248289761001"), userInfo.getSubject());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertTrue(userInfo.getEmailVerified());
		
		Set<DistributedClaims> distributedClaimsSet = userInfo.getDistributedClaims();
		assertEquals(1, distributedClaimsSet.size());
		DistributedClaims dClaims = distributedClaimsSet.iterator().next();
		assertEquals("src1", dClaims.getSourceID());
		assertEquals(new URI("https://server.yetanotherop.com/claim_source"), dClaims.getSourceEndpoint());
		assertEquals("ksj3n283dkeafb76cdef", dClaims.getAccessToken().getValue());
	}
	
	
	public void testAssurance_basicGettersAndSetters() throws ParseException {
		
		Subject subject = new Subject("alice");
		UserInfo userInfo = new UserInfo(subject);
		
		assertNull(userInfo.getBirthplace());
		Birthplace birthplace = new Birthplace(new ISO3166_1Alpha2CountryCode("DE"), "Muster Region", "Musterstadt");
		userInfo.setBirthplace(birthplace);
		assertEquals(birthplace.getCountry(), userInfo.getBirthplace().getCountry());
		assertEquals(birthplace.getRegion(), userInfo.getBirthplace().getRegion());
		assertEquals(birthplace.getLocality(), userInfo.getBirthplace().getLocality());
		
		assertNull(userInfo.getNationalities());
		List<CountryCode> nats = Collections.singletonList((CountryCode) new ISO3166_1Alpha2CountryCode("DE"));
		userInfo.setNationalities(nats);
		assertEquals(nats, userInfo.getNationalities());
		
		assertNull(userInfo.getBirthFamilyName());
		String birthFamilyName = "birth family name";
		userInfo.setBirthFamilyName(birthFamilyName);
		assertEquals(birthFamilyName, userInfo.getBirthFamilyName());
		
		assertNull(userInfo.getBirthGivenName());
		String birthGivenName = "birth given name";
		userInfo.setBirthGivenName(birthGivenName);
		assertEquals(birthGivenName, userInfo.getBirthGivenName());
		
		assertNull(userInfo.getBirthMiddleName());
		String birthMiddleName = "birth middle name";
		userInfo.setBirthMiddleName(birthMiddleName);
		assertEquals(birthMiddleName, userInfo.getBirthMiddleName());
		
		assertNull(userInfo.getSalutation());
		String salutation = "dear";
		userInfo.setSalutation(salutation);
		assertEquals(salutation, userInfo.getSalutation());
		
		assertNull(userInfo.getTitle());
		String title = "Mrs.";		userInfo.setTitle(title);
		assertEquals(title, userInfo.getTitle());
		
		String json = userInfo.toJSONString();
		
		userInfo = UserInfo.parse(json);
		
		assertEquals(birthplace.getCountry(), userInfo.getBirthplace().getCountry());
		assertEquals(birthplace.getRegion(), userInfo.getBirthplace().getRegion());
		assertEquals(birthplace.getLocality(), userInfo.getBirthplace().getLocality());
		assertEquals(nats, userInfo.getNationalities());
		assertEquals(birthFamilyName, userInfo.getBirthFamilyName());
		assertEquals(birthGivenName, userInfo.getBirthGivenName());
		assertEquals(birthMiddleName, userInfo.getBirthMiddleName());
		assertEquals(salutation, userInfo.getSalutation());
		assertEquals(title, userInfo.getTitle());
	}
	
	
	public void testAssurance_langTaggedGettersAndSetters() throws ParseException, LangTagException {
		
		Subject subject = new Subject("alice");
		UserInfo userInfo = new UserInfo(subject);
		
		LangTag en = LangTag.parse("en");
		LangTag de = LangTag.parse("de");
		
		assertNull(userInfo.getBirthFamilyName(en));
		assertNull(userInfo.getBirthFamilyName(de));
		String birthFamilyName = "birth_family_name";
		userInfo.setBirthFamilyName(birthFamilyName + "#en", en);
		userInfo.setBirthFamilyName(birthFamilyName + "#de", de);
		assertEquals(birthFamilyName + "#en", userInfo.getBirthFamilyName(en));
		assertEquals(birthFamilyName + "#de", userInfo.getBirthFamilyName(de));
		
		assertNull(userInfo.getBirthGivenName(en));
		assertNull(userInfo.getBirthGivenName(de));
		String birthGivenName = "birth_given_name";
		userInfo.setBirthGivenName(birthGivenName + "#en", en);
		userInfo.setBirthGivenName(birthGivenName + "#de", de);
		assertEquals(birthGivenName + "#en", userInfo.getBirthGivenName(en));
		assertEquals(birthGivenName + "#de", userInfo.getBirthGivenName(de));
		
		assertNull(userInfo.getBirthMiddleName(en));
		assertNull(userInfo.getBirthMiddleName(de));
		String birthMiddleName = "birth_middle_name";
		userInfo.setBirthMiddleName(birthMiddleName + "#en", en);
		userInfo.setBirthMiddleName(birthMiddleName + "#de", de);
		assertEquals(birthMiddleName + "#en", userInfo.getBirthMiddleName(en));
		assertEquals(birthMiddleName + "#de", userInfo.getBirthMiddleName(de));
		
		assertNull(userInfo.getSalutation(en));
		assertNull(userInfo.getSalutation(de));
		String salutation = "dear";
		userInfo.setSalutation(salutation + "#en", en);
		userInfo.setSalutation(salutation + "#de", de);
		assertEquals(salutation + "#en", userInfo.getSalutation(en));
		assertEquals(salutation + "#de", userInfo.getSalutation(de));
		
		assertNull(userInfo.getTitle(en));
		assertNull(userInfo.getTitle(de));
		String title = "Mrs.";
		userInfo.setTitle(title + "#en", en);
		userInfo.setTitle(title + "#de", de);
		assertEquals(title + "#en", userInfo.getTitle(en));
		assertEquals(title + "#de", userInfo.getTitle(de));
		
		Map<LangTag, String> map = userInfo.getBirthFamilyNameEntries();
		assertEquals(birthFamilyName + "#en", map.get(en));
		assertEquals(birthFamilyName + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getBirthGivenNameEntries();
		assertEquals(birthGivenName + "#en", map.get(en));
		assertEquals(birthGivenName + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getBirthMiddleNameEntries();
		assertEquals(birthMiddleName + "#en", map.get(en));
		assertEquals(birthMiddleName + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getSalutationEntries();
		assertEquals(salutation + "#en", map.get(en));
		assertEquals(salutation + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getTitleEntries();
		assertEquals(title + "#en", map.get(en));
		assertEquals(title + "#de", map.get(de));
		assertEquals(2, map.size());
		
		String json = userInfo.toJSONString();
		
		userInfo = UserInfo.parse(json);
		
		assertEquals(birthFamilyName + "#en", userInfo.getBirthFamilyName(en));
		assertEquals(birthFamilyName + "#de", userInfo.getBirthFamilyName(de));
		assertEquals(birthGivenName + "#en", userInfo.getBirthGivenName(en));
		assertEquals(birthGivenName + "#de", userInfo.getBirthGivenName(de));
		assertEquals(birthMiddleName + "#en", userInfo.getBirthMiddleName(en));
		assertEquals(birthMiddleName + "#de", userInfo.getBirthMiddleName(de));
		assertEquals(salutation + "#en", userInfo.getSalutation(en));
		assertEquals(salutation + "#de", userInfo.getSalutation(de));
		assertEquals(title + "#en", userInfo.getTitle(en));
		assertEquals(title + "#de", userInfo.getTitle(de));
		
		map = userInfo.getBirthFamilyNameEntries();
		assertEquals(birthFamilyName + "#en", map.get(en));
		assertEquals(birthFamilyName + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getBirthGivenNameEntries();
		assertEquals(birthGivenName + "#en", map.get(en));
		assertEquals(birthGivenName + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getBirthMiddleNameEntries();
		assertEquals(birthMiddleName + "#en", map.get(en));
		assertEquals(birthMiddleName + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getSalutationEntries();
		assertEquals(salutation + "#en", map.get(en));
		assertEquals(salutation + "#de", map.get(de));
		assertEquals(2, map.size());
		
		map = userInfo.getTitleEntries();
		assertEquals(title + "#en", map.get(en));
		assertEquals(title + "#de", map.get(de));
		assertEquals(2, map.size());
	}
	
	
	public void testAssurance_verifiedClaimsGetterAndSetter() throws ParseException {
		
		Subject subject = new Subject("alice");
		UserInfo userInfo = new UserInfo(subject);
		
		assertNull(userInfo.getVerifiedClaims());
		
		PersonClaims claims = new PersonClaims();
		claims.setName("Alice Adams");
		
		Date now = new Date(new Date().getTime() / 1000 * 1000); // second precision
		
		VerificationProcess verificationProcess = new VerificationProcess("f3ae0ee3-bcda-4e4b-bf84-3b35eb0a1bc3");
		
		QESEvidence qesEvidence = new QESEvidence(
			new Issuer("issuer"),
			"001",
			new DateWithTimeZoneOffset(now, 0));
		
		IdentityVerification verification = new IdentityVerification(
			IdentityTrustFramework.DE_AML,
			new DateWithTimeZoneOffset(now, 0),
			verificationProcess,
			Collections.singletonList((IdentityEvidence) qesEvidence));
		
		VerifiedClaimsSet verifiedClaimsSet = new VerifiedClaimsSet(verification, claims);
		
		userInfo.setVerifiedClaims(verifiedClaimsSet);
		
		VerifiedClaimsSet out = userInfo.getVerifiedClaims().get(0);
		
		assertEquals(IdentityTrustFramework.DE_AML, out.getVerification().getTrustFramework());
		assertEquals(verification.getVerificationTime().toISO8601String(), out.getVerification().getVerificationTime().toISO8601String());
		assertEquals(verificationProcess, out.getVerification().getVerificationProcess());
		assertEquals(IdentityEvidenceType.QES, out.getVerification().getEvidence().get(0).getEvidenceType());
		assertEquals(qesEvidence.getQESIssuer(), out.getVerification().getEvidence().get(0).toQESEvidence().getQESIssuer());
		assertEquals(qesEvidence.getQESSerialNumberString(), out.getVerification().getEvidence().get(0).toQESEvidence().getQESSerialNumberString());
		assertEquals(qesEvidence.getQESCreationTime().toISO8601String(), out.getVerification().getEvidence().get(0).toQESEvidence().getQESCreationTime().toISO8601String());
		
		assertEquals(claims.getName(), out.getClaimsSet().getName());
		
		String json = userInfo.toJSONString();
		
		// Parse from JSON
		
		userInfo = UserInfo.parse(json);
		
		out = userInfo.getVerifiedClaims().get(0);
		
		assertEquals(IdentityTrustFramework.DE_AML, out.getVerification().getTrustFramework());
		assertEquals(verification.getVerificationTime().toISO8601String(), out.getVerification().getVerificationTime().toISO8601String());
		assertEquals(verificationProcess, out.getVerification().getVerificationProcess());
		assertEquals(IdentityEvidenceType.QES, out.getVerification().getEvidence().get(0).getEvidenceType());
		assertEquals(qesEvidence.getQESIssuer(), out.getVerification().getEvidence().get(0).toQESEvidence().getQESIssuer());
		assertEquals(qesEvidence.getQESSerialNumberString(), out.getVerification().getEvidence().get(0).toQESEvidence().getQESSerialNumberString());
		assertEquals(qesEvidence.getQESCreationTime().toISO8601String(), out.getVerification().getEvidence().get(0).toQESEvidence().getQESCreationTime().toISO8601String());
		
		assertEquals(claims.getName(), out.getClaimsSet().getName());
	}
	
	
	public void testAssurance_verifiedClaimsListGetterAndSetter() throws ParseException {
		
		PersonClaims claimsSet1 = new PersonClaims();
		claimsSet1.setGivenName("Alice");
		claimsSet1.setFamilyName("Adams");
		VerifiedClaimsSet v1 = new VerifiedClaimsSet(
			new IdentityVerification(IdentityTrustFramework.DE_AML, null, null, (IdentityEvidence) null),
			claimsSet1);
		
		PersonClaims claimsSet2 = new PersonClaims();
		claimsSet2.setEmailAddress("alice@wonderland.com");
		VerifiedClaimsSet v2 = new VerifiedClaimsSet(
			new IdentityVerification(IdentityTrustFramework.EIDAS_IAL_HIGH, null, null, (IdentityEvidence) null),
			claimsSet2);
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		List<VerifiedClaimsSet> vList = Arrays.asList(v1, v2);
		userInfo.setVerifiedClaims(vList);
		
		assertEquals(vList.get(0).toJSONObject(), userInfo.getVerifiedClaims().get(0).toJSONObject());
		assertEquals(vList.get(1).toJSONObject(), userInfo.getVerifiedClaims().get(1).toJSONObject());
		assertEquals(2, userInfo.getVerifiedClaims().size());
		
		JSONObject jsonObject = userInfo.toJSONObject();
		
		userInfo = UserInfo.parse(jsonObject.toJSONString());
		
		assertEquals(new Subject("alice"), userInfo.getSubject());
		
		assertEquals(vList.get(0).toJSONObject(), userInfo.getVerifiedClaims().get(0).toJSONObject());
		assertEquals(vList.get(1).toJSONObject(), userInfo.getVerifiedClaims().get(1).toJSONObject());
		assertEquals(2, userInfo.getVerifiedClaims().size());
	}
	
	
	public void testAssurance_onlineExampleWithVerifiedClaims() throws ParseException {
		
		Date now = new Date();
		DateWithTimeZoneOffset timestamp = new DateWithTimeZoneOffset(
			now,
			TimeZone.getDefault());
		VerificationProcess verificationProcess = new VerificationProcess("4ebc8150-1b26-460a-adc1-3e9096ab88f9");
		
		IdentityVerification verification = new IdentityVerification(
			IdentityTrustFramework.EIDAS_IAL_SUBSTANTIAL,
			timestamp,
			verificationProcess,
			new QESEvidence(
				new Issuer("https://qes-provider.org"),
				"cc58176d-6cd4-4d9d-bad9-50981ad3ee1f",
				DateWithTimeZoneOffset.parseISO8601String("2019-12-01T08:00:00Z")));
		
		PersonClaims claims = new PersonClaims();
		claims.setName("Alice Adams");
		claims.setEmailAddress("alice@wonderland.com");
		
		VerifiedClaimsSet verifiedClaims = new VerifiedClaimsSet(
			verification,
			claims);
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		userInfo.setVerifiedClaims(verifiedClaims);
		
		System.out.println(userInfo.toJSONObject());
		
		// {
		//   "sub":"alice",
		//   "verified_claims":{
		//       "claims":{
		//           "name":"Alice Adams",
		//           "email":"alice@wonderland.com"
		//           },
		//       "verification":{
		//           "trust_framework":"eidas_ial_substantial",
		//           "time":"2019-12-04T22:57:16+02:00",
		//           "verification_process":"4ebc8150-1b26-460a-adc1-3e9096ab88f9",
		//           "evidence":[{
		//               "type":"qes",
		//               "issuer":"https:\/\/qes-provider.org",
		//               "serial_number":"cc58176d-6cd4-4d9d-bad9-50981ad3ee1f",
		//               "created_at":"2019-12-01T08:00:00+00:00"
		//           }]
		//       }
		//   }
		// }
		
		UserInfoSuccessResponse userInfoResponse = new UserInfoSuccessResponse(userInfo);
		userInfo = userInfoResponse.getUserInfo();
		
		System.out.println("Subject: " + userInfo.getSubject());
		
		verifiedClaims = userInfo.getVerifiedClaims().get(0);
		
		System.out.println("Trust framework: " + verifiedClaims.getVerification().getTrustFramework());
		System.out.println("Evidence type: " + verifiedClaims.getVerification().getEvidence().get(0).getEvidenceType());
		System.out.println("Verified claims: " + verifiedClaims.getClaimsSet().toJSONObject());
		
		// Subject: alice
		// Trust framework: eidas_ial_substantial
		// Evidence type: qes
		// Verified claims: {"name":"Alice Adams","email":"alice@wonderland.com"}
	}
}
