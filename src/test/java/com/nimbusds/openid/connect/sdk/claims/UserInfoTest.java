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

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
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
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.assurance.*;
import com.nimbusds.openid.connect.sdk.assurance.claims.*;
import com.nimbusds.openid.connect.sdk.assurance.evidences.*;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.EmbeddedAttachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.ExternalAttachment;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.HashAlgorithm;
import com.nimbusds.secevent.sdk.claims.TXN;


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
		assertTrue(UserInfo.getStandardClaimNames().contains("place_of_birth"));
		assertTrue(UserInfo.getStandardClaimNames().contains("nationalities"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birth_family_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birth_given_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("birth_middle_name"));
		assertTrue(UserInfo.getStandardClaimNames().contains("salutation"));
		assertTrue(UserInfo.getStandardClaimNames().contains("title"));
		assertTrue(UserInfo.getStandardClaimNames().contains("msisdn"));
		assertTrue(UserInfo.getStandardClaimNames().contains("also_known_as"));
		assertTrue(UserInfo.getStandardClaimNames().contains("verified_claims"));
		
		assertEquals(33, UserInfo.getStandardClaimNames().size());
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
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertEquals("http://example.com/janedoe/me.jpg", userInfo.getPicture().toString());

		json = userInfo.toJSONObject().toJSONString();

		userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("Jane", userInfo.getGivenName());
		assertEquals("Doe", userInfo.getFamilyName());
		assertEquals("j.doe", userInfo.getPreferredUsername());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());
		assertEquals("http://example.com/janedoe/me.jpg", userInfo.getPicture().toString());
		
		// No external claims
		assertNull(userInfo.getAggregatedClaims());
		assertNull(userInfo.getDistributedClaims());
	}


	public void testWithAddress()
		throws Exception {

		String json = "{" +
			"\"sub\": \"248289761001\"," +
			"\"name\": \"Jane Doe\"," +
			"\"email\": \"janedoe@example.com\"," +
			"\"address\": {" +
			"	\"formatted\":\"Some formatted\"," +
			"	\"street_address\":\"Some street\"," +
			"	\"locality\":\"Some locality\"," +
			"	\"region\":\"Some region\"," +
			"	\"postal_code\":\"1000\"," +
			"	\"country\":\"Some country\"" +
			"	}" +
			"}";

		UserInfo userInfo = UserInfo.parse(json);

		assertEquals("248289761001", userInfo.getSubject().getValue());
		assertEquals("Jane Doe", userInfo.getName());
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());

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
		assertEquals("janedoe@example.com", userInfo.getEmailAddress());

		address = userInfo.getAddress();

		assertEquals("Some formatted", address.getFormatted());
		assertEquals("Some street", address.getStreetAddress());
		assertEquals("Some locality", address.getLocality());
		assertEquals("Some region", address.getRegion());
		assertEquals("1000", address.getPostalCode());
		assertEquals("Some country", address.getCountry());
		assertNull(address.getCountryCode());
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
		assertNull(userInfo.getPlaceOfBirth());
		assertNull(userInfo.getBirthplace());
		assertNull(userInfo.getNationalities());
		assertNull(userInfo.getBirthFamilyName());
		assertNull(userInfo.getBirthGivenName());
		assertNull(userInfo.getBirthMiddleName());
		assertNull(userInfo.getSalutation());
		assertNull(userInfo.getTitle());
		assertNull(userInfo.getMSISDN());
		assertNull(userInfo.getAlsoKnownAs());
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

		userInfo.setUpdatedTime(DateUtils.fromSecondsSinceEpoch(100000L));

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
		
		assertEquals("invalid-email", userInfo.getEmailAddress());
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
			"}";
		
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
	
	// Deprecated id_document
	public void testParseExample_1() throws ParseException {
		
		String json =
			"{" +
			"   \"sub\":\"248289761001\"," +
			"   \"email\":\"janedoe@example.com\"," +
			"   \"email_verified\":true," +
			"   \"verified_claims\":{  " +
			"      \"verification\":{  " +
			"         \"trust_framework\":\"de_aml\"," +
			"         \"time\":\"2012-04-23T18:25:43.511+01\"," +
			"         \"verification_process\":\"676q3636461467647q8498785747q487\"," +
			"         \"evidence\":[  " +
			"            {" +
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
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		assertEquals(IdentityTrustFramework.DE_AML, verifiedClaimsSet.getVerification().getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25:43.511+01"), verifiedClaimsSet.getVerification().getVerificationTime());
		assertEquals(new VerificationProcess("676q3636461467647q8498785747q487"), verifiedClaimsSet.getVerification().getVerificationProcess());
		assertEquals(IdentityEvidenceType.ID_DOCUMENT, verifiedClaimsSet.getVerification().getEvidence().get(0).getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getVerificationMethod());
		assertEquals(IDDocumentType.IDCARD, verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getIdentityDocument().getType());
		assertEquals("Stadt Augsburg", verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getIdentityDocument().getIssuerName());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getIdentityDocument().getIssuerCountry());
		assertEquals("53554554", verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getIdentityDocument().getNumber());
		assertEquals(new SimpleDate(2012, 4, 23), verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getIdentityDocument().getDateOfIssuance());
		assertEquals(new SimpleDate(2022, 4, 22), verifiedClaimsSet.getVerification().getEvidence().get(0).toIDDocumentEvidence().getIdentityDocument().getDateOfExpiry());
		
		assertEquals("Max", verifiedClaimsSet.getClaimsSet().getGivenName());
		assertEquals("Meier", verifiedClaimsSet.getClaimsSet().getFamilyName());
		assertEquals("1956-01-28", verifiedClaimsSet.getClaimsSet().getBirthdate());
		assertEquals(3, verifiedClaimsSet.getClaimsSet().toJSONObject().size());
	}
	
	
	// Deprecated id_document
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
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/response/siop_aggregated_and_distributed_claims.json
	public void testAssurance_selfIssuedExample() throws Exception {
		
		String json = "{" +
			"  \"iss\": \"https://https://self-issued.me\"," +
			"  \"sub\": \"248289761001\"," +
			"  \"preferred_username\": \"superman445\"," +
			"  \"_claim_names\": {" +
			"    \"verified_claims\": [" +
			"      \"src1\"," +
			"      \"src2\"" +
			"    ]" +
			"  }," +
			"  \"_claim_sources\": {" +
			"    \"src1\": {" +
			"      \"JWT\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwcz" +
			"      ovL3NlcnZlci5vdGhlcm9wLmNvbSIsInN1YiI6ImU4MTQ4NjAzLTg5MzQtNDI0N" +
			"      S04MjViLWMxMDhiOGI2Yjk0NSIsInZlcmlmaWVkX2NsYWltcyI6eyJ2ZXJpZmlj" +
			"      YXRpb24iOnsidHJ1c3RfZnJhbWV3b3JrIjoiaWFsX2V4YW1wbGVfZ29sZCJ9LCJ" +
			"      jbGFpbXMiOnsiZ2l2ZW5fbmFtZSI6Ik1heCIsImZhbWlseV9uYW1lIjoiTWVpZX" +
			"      IiLCJiaXJ0aGRhdGUiOiIxOTU2LTAxLTI4In19fQ.FArlPUtUVn95HCExePlWJQ" +
			"      6ctVfVpQyeSbe3xkH9MH1QJjnk5GVbBW0qe1b7R3lE-8iVv__0mhRTUI5lcFhLj" +
			"      oGjDS8zgWSarVsEEjwBK7WD3r9cEw6ZAhfEkhHL9eqAaED2rhhDbHD5dZWXkJCu" +
			"      XIcn65g6rryiBanxlXK0ZmcK4fD9HV9MFduk0LRG_p4yocMaFvVkqawat5NV9QQ" +
			"      3ij7UBr3G7A4FojcKEkoJKScdGoozir8m5XD83Sn45_79nCcgWSnCX2QTukL8Ny" +
			"      wIItu_K48cjHiAGXXSzydDm_ccGCe0sY-Ai2-iFFuQo2PtfuK2SqPPmAZJxEFrF" +
			"      oLY4g\"" +
			"    }," +
			"    \"src2\": {" +
			"      \"endpoint\": \"https://op.mymno.com/claim_source\"," +
			"      \"access_token\": \"ksj3n283dkeafb76cdef\"" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		assertEquals(new Issuer("https://https://self-issued.me"), userInfo.getIssuer());
		assertEquals(new Subject("248289761001"), userInfo.getSubject());
		assertEquals("superman445", userInfo.getPreferredUsername());
		
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
		assertEquals(new URI("https://op.mymno.com/claim_source"), dClaims.getSourceEndpoint());
		assertEquals("ksj3n283dkeafb76cdef", dClaims.getAccessToken().getValue());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-8.1
	public void testAssurance_parseExample_idDocument_deprecatedFormat()
		throws ParseException {
	
		String json =
			"{" +
			"\"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25Z\"," +
			"      \"verification_process\": \"f24c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"method\": \"pipp\"," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document_details\": {" + // TODO fix example
			"            \"type\": \"idcard\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Stadt Augsburg\"," +
			"              \"country\": \"DE\"" +
			"            }," +
			"            \"document_number\": \"53554554\"," + // TODO fix example
			"            \"date_of_issuance\": \"2010-03-23\"," +
			"            \"date_of_expiry\": \"2020-03-22\"" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Maxstadt\"," +
			"        \"postal_code\": \"12344\"," +
			"        \"country\": \"DE\"," +
			"        \"street_address\": \"An der Weide 22\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"), verification.getVerificationProcess());
		
		DocumentEvidence documentEvidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(IdentityEvidenceType.DOCUMENT, documentEvidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, documentEvidence.getMethod());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), documentEvidence.getVerificationTime());
		assertEquals(DocumentType.IDCARD, documentEvidence.getDocumentDetails().getType());
		assertEquals(new Name("Stadt Augsburg"), documentEvidence.getDocumentDetails().getIssuer().getName());
		assertEquals("DE", documentEvidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertEquals(new DocumentNumber("53554554"), documentEvidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SimpleDate(2010, 3, 23), documentEvidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 3, 22), documentEvidence.getDocumentDetails().getDateOfExpiry());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", personClaims.getGivenName());
		assertEquals("Meier", personClaims.getFamilyName());
		assertEquals("1956-01-28", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), personClaims.getNationalities());
		assertEquals("Maxstadt", personClaims.getAddress().getLocality());
		assertEquals("12344", personClaims.getAddress().getPostalCode());
		assertEquals("DE", personClaims.getAddress().getCountry());
		assertEquals("An der Weide 22", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-document
	public void testAssurance_parseExample_document()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"uk_tfida\"," +
			"      \"assurance_level\": \"medium\"," +
			"      \"assurance_process\": {" +
			"          \"policy\": \"gpg45\"," +
			"          \"procedure\": \"m1b\"" +
			"      }," +
			"      \"time\": \"2021-05-11T14:29Z\"," +
			"      \"verification_process\": \"7675D80F-57E0-AB14-9543-26B41FC22\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vpiruv\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_3\"" +
			"          }," +
			"          \"verification_method\": {" +
			"            \"type\": \"pvp\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_3\"" +
			"          }," +
			"          \"time\": \"2021-04-09T14:12Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"driving_permit\"," +
			"            \"personal_number\": \"MORGA753116SM9IJ\"," +
			"            \"document_number\": \"MORGA753116SM9IJ35\"," +
			"            \"serial_number\": \"ZG21000001\"," +
			"            \"date_of_issuance\": \"2021-01-01\"," +
			"            \"date_of_expiry\": \"2030-12-31\"," +
			"            \"issuer\": {" +
			"                \"name\": \"DVLA\"," +
			"                \"country\": \"UK\"," +
			"                \"country_code\": \"GBR\"," +
			"                \"jurisdiction\": \"GB-GBN\"" +
			"            }" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Sarah\"," +
			"      \"family_name\": \"Meredyth\"," +
			"      \"birthdate\": \"1976-03-11\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"UK\"" +
			"      }," +
			"      \"address\": {" +
			"        \"locality\": \"Edinburgh\"," +
			"        \"postal_code\": \"EH1 9GP\"," +
			"        \"country\": \"UK\"," +
			"        \"street_address\": \"122 Burns Crescent\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.UK_TFIDA, verification.getTrustFramework());
		assertEquals(IdentityAssuranceLevel.MEDIUM, verification.getAssuranceLevel());
		assertEquals(new Policy("gpg45"), verification.getAssuranceProcess().getPolicy());
		assertEquals(new Procedure("m1b"), verification.getAssuranceProcess().getProcedure());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-05-11T14:29Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("7675D80F-57E0-AB14-9543-26B41FC22"), verification.getVerificationProcess());
		
		DocumentEvidence evidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(1, verification.getEvidence().size());
		
		assertEquals(IdentityEvidenceType.DOCUMENT, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIRUV, evidence.getValidationMethod().getType());
		assertEquals(new Policy("gpg45"), evidence.getValidationMethod().getPolicy());
		assertEquals(new Procedure("score_3"), evidence.getValidationMethod().getProcedure());
		assertEquals(VerificationMethodType.PVP, evidence.getVerificationMethod().getType());
		assertEquals(new Procedure("score_3"), evidence.getVerificationMethod().getProcedure());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-04-09T14:12Z"), evidence.getVerificationTime());
		assertEquals(DocumentType.DRIVING_PERMIT, evidence.getDocumentDetails().getType());
		assertEquals(new PersonalNumber("MORGA753116SM9IJ"), evidence.getDocumentDetails().getPersonalNumber());
		assertEquals(new DocumentNumber("MORGA753116SM9IJ35"), evidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SerialNumber("ZG21000001"), evidence.getDocumentDetails().getSerialNumber());
		assertEquals(new SimpleDate(2021, 1, 1), evidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2030, 12, 31), evidence.getDocumentDetails().getDateOfExpiry());
		assertEquals(new Name("DVLA"), evidence.getDocumentDetails().getIssuer().getName());
		assertEquals("UK", evidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertEquals(new ISO3166_1Alpha3CountryCode("GBR"), evidence.getDocumentDetails().getIssuer().getCountryCode());
		assertEquals(new Jurisdiction("GB-GBN"), evidence.getDocumentDetails().getIssuer().getJurisdiction());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Sarah", personClaims.getGivenName());
		assertEquals("Meredyth", personClaims.getFamilyName());
		assertEquals("1976-03-11", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("UK"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Edinburgh", personClaims.getAddress().getLocality());
		assertEquals("EH1 9GP", personClaims.getAddress().getPostalCode());
		assertEquals("UK", personClaims.getAddress().getCountry());
		assertEquals("122 Burns Crescent", personClaims.getAddress().getStreetAddress());
	}
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-document-and-verifier-detai
	public void testAssurance_parseExample_documentAndVerifierDetails()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25Z\"," +
			"      \"verification_process\": \"f24c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"method\": \"pipp\"," +
			"          \"verifier\": {" +
			"            \"organization\": \"Deutsche Post\"," +
			"            \"txn\": \"1aa05779-0775-470f-a5c4-9f1f5e56cf06\"" +
			"          }," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"idcard\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Stadt Augsburg\"," +
			"              \"country\": \"DE\"" +
			"            }," +
			"            \"document_number\": \"53554554\"," +
			"            \"date_of_issuance\": \"2010-03-23\"," +
			"            \"date_of_expiry\": \"2020-03-22\"" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Maxstadt\"," +
			"        \"postal_code\": \"12344\"," +
			"        \"country\": \"DE\"," +
			"        \"street_address\": \"An der Weide 22\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"), verification.getVerificationProcess());
		
		DocumentEvidence evidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(1, verification.getEvidence().size());
		assertEquals(IdentityEvidenceType.DOCUMENT, evidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getMethod());
		assertEquals(new Organization("Deutsche Post"), evidence.getVerifier().getOrganizationEntity());
		assertEquals(new TXN("1aa05779-0775-470f-a5c4-9f1f5e56cf06"), evidence.getVerifier().getTXN());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), evidence.getVerificationTime());
		assertEquals(DocumentType.IDCARD, evidence.getDocumentDetails().getType());
		assertEquals(new Name("Stadt Augsburg"), evidence.getDocumentDetails().getIssuer().getName());
		assertEquals("DE", evidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertEquals(new DocumentNumber("53554554"), evidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SimpleDate(2010, 3, 23), evidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 3, 22), evidence.getDocumentDetails().getDateOfExpiry());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", personClaims.getGivenName());
		assertEquals("Meier", personClaims.getFamilyName());
		assertEquals("1956-01-28", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), personClaims.getNationalities());
		assertEquals("Maxstadt", personClaims.getAddress().getLocality());
		assertEquals("12344", personClaims.getAddress().getPostalCode());
		assertEquals("DE", personClaims.getAddress().getCountry());
		assertEquals("An der Weide 22", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-document-with-external-atta
	public void testAssurance_parseExample_documentWithExternalAttachments()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25Z\"," +
			"      \"verification_process\": \"f24c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"method\": \"pipp\"," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"idcard\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Stadt Augsburg\"," +
			"              \"country\": \"DE\"" +
			"            }," +
			"            \"document_number\": \"53554554\"," +
			"            \"date_of_issuance\": \"2010-03-23\"," +
			"            \"date_of_expiry\": \"2020-03-22\"" +
			"          }," +
			"          \"attachments\": [" +
			"            {" +
			"              \"desc\": \"Front of id document\"," +
			"              \"digest\" : {" +
			"                \"alg\": \"SHA-256\"," +
			"                \"value\": \"n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=\"" +
			"              }," +
			"              \"url\": \"https://example.com/attachments/pGL9yz4hZQ\"" +
			"            }," +
			"            {" +
			"              \"desc\": \"Back of id document\"," +
			"              \"digest\" : {" +
			"                \"alg\": \"SHA-256\"," +
			"                \"value\": \"/WGgOvT3fYcPwh4F5+gGeAlcktgIz7O1wnnuBMdKyhM=\"" +
			"              }," +
			"              \"url\": \"https://example.com/attachments/4Ag8IpOf95\"" +
			"            }" +
			"          ]" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Maxstadt\"," +
			"        \"postal_code\": \"12344\"," +
			"        \"country\": \"DE\"," +
			"        \"street_address\": \"An der Weide 22\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"), verification.getVerificationProcess());
		
		DocumentEvidence evidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(1, verification.getEvidence().size());
		assertEquals(IdentityEvidenceType.DOCUMENT, evidence.getEvidenceType());
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getMethod());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), evidence.getVerificationTime());
		assertEquals(DocumentType.IDCARD, evidence.getDocumentDetails().getType());
		assertEquals(new Name("Stadt Augsburg"), evidence.getDocumentDetails().getIssuer().getName());
		assertEquals("DE", evidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertEquals(new DocumentNumber("53554554"), evidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SimpleDate(2010, 3, 23), evidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 3, 22), evidence.getDocumentDetails().getDateOfExpiry());
		
		List<Attachment> attachments = evidence.getAttachments();
		assertEquals(2, attachments.size());
		
		ExternalAttachment frontOfIdDocument = attachments.get(0).toExternalAttachment();
		assertEquals("Front of id document", frontOfIdDocument.getDescriptionString());
		assertEquals(HashAlgorithm.SHA_256, frontOfIdDocument.getDigest().getHashAlgorithm());
		assertEquals(new Base64("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="), frontOfIdDocument.getDigest().getValue());
		assertEquals(URI.create("https://example.com/attachments/pGL9yz4hZQ"), frontOfIdDocument.getURL());
		
		ExternalAttachment backOfIdDocument = attachments.get(1).toExternalAttachment();
		assertEquals("Back of id document", backOfIdDocument.getDescriptionString());
		assertEquals(HashAlgorithm.SHA_256, backOfIdDocument.getDigest().getHashAlgorithm());
		assertEquals(new Base64("/WGgOvT3fYcPwh4F5+gGeAlcktgIz7O1wnnuBMdKyhM="), backOfIdDocument.getDigest().getValue());
		assertEquals(URI.create("https://example.com/attachments/4Ag8IpOf95"), backOfIdDocument.getURL());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", personClaims.getGivenName());
		assertEquals("Meier", personClaims.getFamilyName());
		assertEquals("1956-01-28", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), personClaims.getNationalities());
		assertEquals("Maxstadt", personClaims.getAddress().getLocality());
		assertEquals("12344", personClaims.getAddress().getPostalCode());
		assertEquals("DE", personClaims.getAddress().getCountry());
		assertEquals("An der Weide 22", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-document-with-other-checks
	public void testAssurance_parseExample_documentWithOtherChecks()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"uk_tfida\"," +
			"      \"assurance_level\": \"medium\"," +
			"      \"assurance_process\": {" +
			"          \"policy\": \"gpg45\"," +
			"          \"procedure\": \"m1b\"" +
			"      }," +
			"      \"time\": \"2021-05-11T14:29Z\"," +
			"      \"verification_process\": \"7675D80F-57E0-AB14-9543-26B41FC22\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vpiruv\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_3\"" +
			"          }," +
			"          \"verification_method\": {" +
			"            \"type\": \"pvr\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_3\"" +
			"          }," +
			"          \"time\": \"2021-04-09T14:12Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"driving_permit\"," +
			"            \"personal_number\": \"MORGA753116SM9IJ\"," +
			"            \"document_number\": \"MORGA753116SM9IJ35\"," +
			"            \"serial_number\": \"ZG21000001\"," +
			"            \"date_of_issuance\": \"2021-01-01\"," +
			"            \"date_of_expiry\": \"2030-12-31\"," +
			"            \"issuer\": {" +
			"                \"name\": \"DVLA\"," +
			"                \"country\": \"UK\"," +
			"                \"country_code\": \"GBR\"," +
			"                \"jurisdiction\": \"GB-GBN\"" +
			"            }" +
			"          }" +
			"        }," +
			"        {" +
			"          \"type\": \"electronic_record\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"data\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_2\"," +
			"            \"status\": \"false_positive\"" +
			"          }," +
			"          \"time\": \"2021-04-09T14:12Z\"," +
			"          \"record\": {" +
			"            \"type\": \"death_register\"," +
			"            \"source\": {" +
			"                \"name\": \"General Register Office\"," +
			"                \"street_address\": \"PO BOX 2\"," +
			"                \"locality\": \"Southport\"," +
			"                \"postal_code\": \"PR8 2JD\"," +
			"                \"country\": \"UK\"," +
			"                \"country_code\": \"GBR\"," +
			"                \"jurisdiction\": \"GB-EAW\"" +
			"            }" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Sarah\"," +
			"      \"family_name\": \"Meredyth\"," +
			"      \"birthdate\": \"1976-03-11\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"UK\"" +
			"      }," +
			"      \"address\": {" +
			"        \"locality\": \"Edinburgh\"," +
			"        \"postal_code\": \"EH1 9GP\"," +
			"        \"country\": \"UK\"," +
			"        \"street_address\": \"122 Burns Crescent\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.UK_TFIDA, verification.getTrustFramework());
		assertEquals(IdentityAssuranceLevel.MEDIUM, verification.getAssuranceLevel());
		assertEquals(new Policy("gpg45"), verification.getAssuranceProcess().getPolicy());
		assertEquals(new Procedure("m1b"), verification.getAssuranceProcess().getProcedure());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-05-11T14:29Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("7675D80F-57E0-AB14-9543-26B41FC22"), verification.getVerificationProcess());
		
		DocumentEvidence documentEvidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(2, verification.getEvidence().size());
		
		assertEquals(IdentityEvidenceType.DOCUMENT, documentEvidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIRUV, documentEvidence.getValidationMethod().getType());
		assertEquals(new Policy("gpg45"), documentEvidence.getValidationMethod().getPolicy());
		assertEquals(new Procedure("score_3"), documentEvidence.getValidationMethod().getProcedure());
		assertEquals(VerificationMethodType.PVR, documentEvidence.getVerificationMethod().getType());
		assertEquals(new Procedure("score_3"), documentEvidence.getVerificationMethod().getProcedure());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-04-09T14:12Z"), documentEvidence.getVerificationTime());
		assertEquals(DocumentType.DRIVING_PERMIT, documentEvidence.getDocumentDetails().getType());
		assertEquals(new PersonalNumber("MORGA753116SM9IJ"), documentEvidence.getDocumentDetails().getPersonalNumber());
		assertEquals(new DocumentNumber("MORGA753116SM9IJ35"), documentEvidence.getDocumentDetails().getDocumentNumber());
		assertEquals(new SerialNumber("ZG21000001"), documentEvidence.getDocumentDetails().getSerialNumber());
		assertEquals(new SimpleDate(2021, 1, 1), documentEvidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new SimpleDate(2030, 12, 31), documentEvidence.getDocumentDetails().getDateOfExpiry());
		assertEquals(new Name("DVLA"), documentEvidence.getDocumentDetails().getIssuer().getName());
		assertEquals("UK", documentEvidence.getDocumentDetails().getIssuer().getAddress().getCountry());
		assertEquals(new ISO3166_1Alpha3CountryCode("GBR"), documentEvidence.getDocumentDetails().getIssuer().getCountryCode());
		assertEquals(new Jurisdiction("GB-GBN"), documentEvidence.getDocumentDetails().getIssuer().getJurisdiction());
		
		ElectronicRecordEvidence recordEvidence = verification.getEvidence().get(1).toElectronicRecordEvidence();
		assertEquals(IdentityEvidenceType.ELECTRONIC_RECORD, recordEvidence.getEvidenceType());
		assertEquals(ValidationMethodType.DATA, recordEvidence.getValidationMethod().getType());
		assertEquals(new Policy("gpg45"), recordEvidence.getValidationMethod().getPolicy());
		assertEquals(new Procedure("score_2"), recordEvidence.getValidationMethod().getProcedure());
		assertEquals(new Status("false_positive"), recordEvidence.getValidationMethod().getStatus());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-04-09T14:12Z"), recordEvidence.getVerificationTime());
		assertEquals(new ElectronicRecordType("death_register"), recordEvidence.getRecordDetails().getType());
		assertEquals(new Name("General Register Office"), recordEvidence.getRecordDetails().getSource().getName());
		assertEquals("PO BOX 2", recordEvidence.getRecordDetails().getSource().getAddress().getStreetAddress());
		assertEquals("Southport", recordEvidence.getRecordDetails().getSource().getAddress().getLocality());
		assertEquals("PR8 2JD", recordEvidence.getRecordDetails().getSource().getAddress().getPostalCode());
		assertEquals("UK", recordEvidence.getRecordDetails().getSource().getAddress().getCountry());
		assertEquals(new ISO3166_1Alpha3CountryCode("GBR"), recordEvidence.getRecordDetails().getSource().getCountryCode());
		assertEquals(new Jurisdiction("GB-EAW"), recordEvidence.getRecordDetails().getSource().getJurisdiction());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Sarah", personClaims.getGivenName());
		assertEquals("Meredyth", personClaims.getFamilyName());
		assertEquals("1976-03-11", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("UK"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Edinburgh", personClaims.getAddress().getLocality());
		assertEquals("EH1 9GP", personClaims.getAddress().getPostalCode());
		assertEquals("UK", personClaims.getAddress().getCountry());
		assertEquals("122 Burns Crescent", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-utility-statement-with-atta
	public void testAssurance_parseExample_utilityStatementWithAttachments()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25Z\"," +
			"      \"verification_process\": \"513645-e44b-4951-942c-7091cf7d891d\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vpip\"" +
			"          }," +
			"          \"time\": \"2021-04-09T14:12Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"utility_statement\"," +
			"            \"date_of_issuance\": \"2013-01-31\"," +
			"            \"issuer\": {" +
			"                \"name\": \"Stadtwerke Musterstadt\"," +
			"                \"country\": \"DE\"," +
			"                \"region\": \"Niedersachsen\"," +
			"                \"street_address\": \"Energiestrasse 33\"" +
			"            }" +
			"          }," +
			"          \"attachments\": [" +
			"            {" +
			"              \"desc\": \"scan of bill\"," +
			"              \"content_type\": \"application/pdf\"," +
			"              \"content\": \"iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg==\"" +
			"            }" +
			"          ]" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Maxstadt\"," +
			"        \"postal_code\": \"12344\"," +
			"        \"country\": \"DE\"," +
			"        \"street_address\": \"An der Weide 22\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("513645-e44b-4951-942c-7091cf7d891d"), verification.getVerificationProcess());
		
		DocumentEvidence evidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(IdentityEvidenceType.DOCUMENT, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIP, evidence.getValidationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-04-09T14:12Z"), evidence.getVerificationTime());
		assertEquals(DocumentType.UTILITY_STATEMENT, evidence.getDocumentDetails().getType());
		assertEquals(new SimpleDate(2013, 1, 31), evidence.getDocumentDetails().getDateOfIssuance());
		assertEquals(new Name("Stadtwerke Musterstadt"), evidence.getDocumentDetails().getIssuer().getName());
		assertEquals("Niedersachsen", evidence.getDocumentDetails().getIssuer().getAddress().getRegion());
		assertEquals("Energiestrasse 33", evidence.getDocumentDetails().getIssuer().getAddress().getStreetAddress());
		
		List<Attachment> attachments = evidence.getAttachments();
		assertEquals(1, attachments.size());
		EmbeddedAttachment embeddedAttachment = attachments.get(0).toEmbeddedAttachment();
		
		assertEquals("scan of bill", embeddedAttachment.getDescriptionString());
		assertEquals(ContentType.APPLICATION_PDF, embeddedAttachment.getContent().getType());
		assertEquals(new Base64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAADSFsjdkhjwhAABJRU5ErkJggg=="), embeddedAttachment.getContent().getBase64());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", personClaims.getGivenName());
		assertEquals("Meier", personClaims.getFamilyName());
		assertEquals("1956-01-28", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), personClaims.getNationalities());
		assertEquals("Maxstadt", personClaims.getAddress().getLocality());
		assertEquals("12344", personClaims.getAddress().getPostalCode());
		assertEquals("DE", personClaims.getAddress().getCountry());
		assertEquals("An der Weide 22", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-document-utility-statement
	public void testAssurance_parseExample_documentPlusUtilityStatement()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25Z\"," +
			"      \"verification_process\": \"513645-e44b-4951-942c-7091cf7d891d\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vpip\"" +
			"          }," +
			"          \"verification_method\": {" +
			"            \"type\": \"pvp\"" +
			"          }," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"de_erp_replacement_idcard\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Stadt Augsburg\"," +
			"              \"country\": \"DE\"" +
			"            }," +
			"            \"document_number\": \"53554554\"," +
			"            \"date_of_issuance\": \"2010-04-23\"," +
			"            \"date_of_expiry\": \"2020-04-22\"" +
			"          }" +
			"        }," +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vpip\"" +
			"          }," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"utility_statement\"," +
			"            \"issuer\": {" +
			"                \"name\": \"Stadtwerke Musterstadt\"," +
			"                \"country\": \"DE\"," +
			"                \"region\": \"Niedersachsen\"," +
			"                \"street_address\": \"Energiestrasse 33\"" +
			"            }," +
			"            \"date_of_issuance\": \"2013-01-31\"" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Maxstadt\"," +
			"        \"postal_code\": \"12344\"," +
			"        \"country\": \"DE\"," +
			"        \"street_address\": \"An der Weide 22\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.DE_AML, verification.getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("513645-e44b-4951-942c-7091cf7d891d"), verification.getVerificationProcess());
		
		assertEquals(2, verification.getEvidence().size());
		
		DocumentEvidence idCardEvidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(IdentityEvidenceType.DOCUMENT, idCardEvidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIP, idCardEvidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.PVP, idCardEvidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), idCardEvidence.getVerificationTime());
		
		DocumentDetails idCardDetails = idCardEvidence.getDocumentDetails();
		assertEquals(DocumentType.DE_ERP_REPLACEMENT_IDCARD, idCardDetails.getType());
		assertEquals(new Name("Stadt Augsburg"), idCardDetails.getIssuer().getName());
		assertEquals("DE", idCardDetails.getIssuer().getAddress().getCountry());
		assertEquals(new DocumentNumber("53554554"), idCardDetails.getDocumentNumber());
		assertEquals(new SimpleDate(2010, 4, 23), idCardDetails.getDateOfIssuance());
		assertEquals(new SimpleDate(2020, 4, 22), idCardDetails.getDateOfExpiry());
		
		DocumentEvidence utilityStmtEvidence = verification.getEvidence().get(1).toDocumentEvidence();
		assertEquals(ValidationMethodType.VPIP, utilityStmtEvidence.getValidationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), utilityStmtEvidence.getVerificationTime());
		
		DocumentDetails utilityStmtDetails = utilityStmtEvidence.getDocumentDetails();
		assertEquals(DocumentType.UTILITY_STATEMENT, utilityStmtDetails.getType());
		assertEquals(new Name("Stadtwerke Musterstadt"), utilityStmtDetails.getIssuer().getName());
		assertEquals("DE", utilityStmtDetails.getIssuer().getAddress().getCountry());
		assertEquals("Niedersachsen", utilityStmtDetails.getIssuer().getAddress().getRegion());
		assertEquals("Energiestrasse 33", utilityStmtDetails.getIssuer().getAddress().getStreetAddress());
		assertEquals(new SimpleDate(2013, 1, 31), utilityStmtDetails.getDateOfIssuance());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Max", personClaims.getGivenName());
		assertEquals("Meier", personClaims.getFamilyName());
		assertEquals("1956-01-28", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), personClaims.getNationalities());
		assertEquals("Maxstadt", personClaims.getAddress().getLocality());
		assertEquals("12344", personClaims.getAddress().getPostalCode());
		assertEquals("DE", personClaims.getAddress().getCountry());
		assertEquals("An der Weide 22", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-8.8
	public void testAssurance_parseExample_idDocumentPlusUtilityBill_deprecated()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"de_aml\"," +
			"      \"time\": \"2012-04-23T18:25Z\"," +
			"      \"verification_process\": \"513645-e44b-4951-942c-7091cf7d891d\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"method\": \"pipp\"," +
			"          \"time\": \"2012-04-22T11:30Z\"," +
			"          \"document\": {" +
			"            \"type\": \"de_erp_replacement_idcard\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Stadt Augsburg\"," +
			"              \"country\": \"DE\"" +
			"            }," +
			"            \"number\": \"53554554\"," +
			"            \"date_of_issuance\": \"2010-04-23\"," +
			"            \"date_of_expiry\": \"2020-04-22\"" +
			"          }" +
			"        }," +
			"        {" +
			"          \"type\": \"utility_bill\"," +
			"          \"provider\": {" +
			"            \"name\": \"Stadtwerke Musterstadt\"," +
			"            \"country\": \"DE\"," +
			"            \"region\": \"Niedersachsen\"," +
			"            \"street_address\": \"Energiestrasse 33\"" +
			"          }," +
			"          \"date\": \"2013-01-31\"" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Maxstadt\"," +
			"        \"postal_code\": \"12344\"," +
			"        \"country\": \"DE\"," +
			"        \"street_address\": \"An der Weide 22\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-notified-eid-system-eidas
	public void testAssurance_parseExample_notifiedEIDAS()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"eidas\"," +
			"      \"assurance_level\": \"substantial\"" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Max\"," +
			"      \"family_name\": \"Meier\"," +
			"      \"birthdate\": \"1956-01-28\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"DE\"," +
			"        \"locality\": \"Musterstadt\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"DE\"" +
			"      ]" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		assertEquals(IdentityTrustFramework.EIDAS, verifiedClaimsSet.getVerification().getTrustFramework());
		assertEquals(IdentityAssuranceLevel.SUBSTANTIAL, verifiedClaimsSet.getVerification().getAssuranceLevel());
		
		assertEquals("Max", verifiedClaimsSet.getClaimsSet().getGivenName());
		assertEquals("Meier", verifiedClaimsSet.getClaimsSet().getFamilyName());
		assertEquals("1956-01-28", verifiedClaimsSet.getClaimsSet().getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), verifiedClaimsSet.getClaimsSet().getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", verifiedClaimsSet.getClaimsSet().getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), verifiedClaimsSet.getClaimsSet().getNationalities());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-8.10
	public void testAssurance_parseExample_electronicRecord()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"se_bankid\"," +
			"      \"assurance_level\": \"al2\"," +
			"      \"time\": \"2021-03-03T09:42Z\"," +
			"      \"verification_process\": \"4346D80F-57E0-4E26-9543-26B41FC22\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"electronic_record\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"data\"" +
			"          }," +
			"          \"verification_method\": {" +
			"            \"type\": \"token\"" +
			"          }," +
			"          \"time\": \"2021-02-15T16:51Z\"," +
			"          \"record\": {" +
			"            \"type\": \"population_register\"," +
			"            \"source\": {" +
			"                \"name\": \"Skatteverket\"," +
			"                \"country\": \"Sverige\"," +
			"                \"country_code\": \"SWE\"" +
			"            }," +
			"            \"personal_number\": \"4901224131\"," +
			"            \"created_at\": \"1979-01-22T00:00:00Z\"" + // TODO fix format in example
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Fredrik\"," +
			"      \"family_name\": \"Str&#246;mberg\"," +
			"      \"birthdate\": \"1979-01-22\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"SE\"," + // TODO fix in example
			"        \"locality\": \"&#214;rnsk&#246;ldsvik\"" + // TODO html entities allowed?
			"      }," +
			"      \"nationalities\": [" +
			"        \"SE\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Karlstad\"," +
			"        \"postal_code\": \"65344\"," +
			"        \"country\": \"SWE\"," +
			"        \"street_address\": \"Gatunamn 221b\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.SE_BANKID, verification.getTrustFramework());
		assertEquals(IdentityAssuranceLevel.AL2, verification.getAssuranceLevel());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-03-03T09:42Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("4346D80F-57E0-4E26-9543-26B41FC22"), verification.getVerificationProcess());
		
		ElectronicRecordEvidence evidence = verification.getEvidence().get(0).toElectronicRecordEvidence();
		assertEquals(IdentityEvidenceType.ELECTRONIC_RECORD, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.DATA, evidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.TOKEN, evidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2021-02-15T16:51Z"), evidence.getVerificationTime());
		assertEquals(ElectronicRecordType.POPULATION_REGISTER, evidence.getRecordDetails().getType());
		assertEquals(new Name("Skatteverket"), evidence.getRecordDetails().getSource().getName());
		assertEquals("Sverige", evidence.getRecordDetails().getSource().getAddress().getCountry());
		assertEquals(new ISO3166_1Alpha3CountryCode("SWE"), evidence.getRecordDetails().getSource().getCountryCode());
		assertEquals(new PersonalNumber("4901224131"), evidence.getRecordDetails().getPersonalNumber());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("1979-01-22T00:00:00Z"), evidence.getRecordDetails().getCreatedAt());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Fredrik", personClaims.getGivenName());
		assertEquals("Str&#246;mberg", personClaims.getFamilyName());
		assertEquals("1979-01-22", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("SE"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("&#214;rnsk&#246;ldsvik", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("SE")), personClaims.getNationalities());
		assertEquals("Karlstad", personClaims.getAddress().getLocality());
		assertEquals("65344", personClaims.getAddress().getPostalCode());
		assertEquals("SWE", personClaims.getAddress().getCountry());
		assertEquals("Gatunamn 221b", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-vouch
	public void testAssurance_parseExample_vouch()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"uk_tfida\"," +
			"      \"assurance_level\": \"very_high\"," +
			"      \"time\": \"2020-03-19T13:05Z\"," +
			"      \"verification_process\": \"76755DA2-81E1-5N14-9543-26B415B77\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"vouch\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vcrypt\"" +
			"          }," +
			"          \"verification_method\": {" +
			"            \"type\": \"bvr\"" +
			"          }," +
			"          \"time\": \"2020-03-19T12:42Z\"," +
			"          \"attestation\": {" +
			"            \"type\": \"digital_attestation\"," +
			"            \"reference_number\": \"6485-1619-3976-6671\"," +
			"            \"date_of_issuance\": \"2021-06-04\"," +
			"            \"voucher\": {" +
			"                \"organization\": \"HMP Dartmoor\"" +
			"            }" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Sam\"," +
			"      \"family_name\": \"Lawler\"," +
			"      \"birthdate\": \"1981-04-13\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"GB\"" + // TODO fix in example 3 letter code
			"      }," +
			"      \"address\": {" +
			"        \"postal_code\": \"98015\"," +
			"        \"country\": \"Monaco\"" +
			"      }" +
			"    }" +
			"  }" +
			"}" +
			"";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.UK_TFIDA, verification.getTrustFramework());
		assertEquals(IdentityAssuranceLevel.VERY_HIGH, verification.getAssuranceLevel());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2020-03-19T13:05Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("76755DA2-81E1-5N14-9543-26B415B77"), verification.getVerificationProcess());
		
		VouchEvidence evidence = verification.getEvidence().get(0).toVouchEvidence();
		assertEquals(IdentityEvidenceType.VOUCH, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.VCRYPT, evidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.BVR, evidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2020-03-19T12:42Z"), evidence.getVerificationTime());
		Attestation attestation = evidence.getAttestation();
		assertEquals(VouchType.DIGITAL_ATTESTATION, attestation.getType());
		assertEquals(new ReferenceNumber("6485-1619-3976-6671"), attestation.getReferenceNumber());
		assertEquals(new SimpleDate(2021, 6, 4), attestation.getDateOfIssuance());
		assertEquals(new Organization("HMP Dartmoor"), attestation.getVoucher().getOrganization());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Sam", personClaims.getGivenName());
		assertEquals("Lawler", personClaims.getFamilyName());
		assertEquals("1981-04-13", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("GB"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("98015", personClaims.getAddress().getPostalCode());
		assertEquals("Monaco", personClaims.getAddress().getCountry());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-8.12
	public void testAssurance_parseExample_vouchWithEmbeddedAttachments()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"uk_tfida\"," +
			"      \"assurance_level\": \"high\"," +
			"      \"assurance_process\": {" +
			"          \"policy\": \"gpg45\"," +
			"          \"procedure\": \"h1b\"" +
			"      }," +
			"      \"time\": \"2020-09-23T14:12Z\"," +
			"      \"verification_process\": \"99476DA2-ACDC-5N13-10WC-26B415B52\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"vouch\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vpip\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_3\"" +
			"          }," +
			"          \"verification_method\": {" +
			"            \"type\": \"pvr\"," +
			"            \"policy\": \"gpg45\"," +
			"            \"procedure\": \"score_3\"" +
			"          }," +
			"          \"time\": \"2020-02-23T07:52Z\"," +
			"          \"attestation\": {" +
			"            \"type\": \"written_attestation\"," +
			"            \"reference_number\": \"6485-1619-3976-6671\"," +
			"            \"date_of_issuance\": \"2020-02-13\"," +
			"            \"voucher\": {" +
			"                \"name\": \"Peter Crowe\"," + // TODO given_name and family_name merged into name, fix example
			"                \"occupation\": \"Executive Principal\"," +
			"                \"organization\": \"Kristin School\"" +
			"            }" +
			"          }," +
			"          \"attachments\": [" +
			"            {" +
			"              \"desc\": \"scan of vouch\"," +
			"              \"content_type\": \"application/pdf\"," +
			"              \"content\": \"d16d2552e35582810e5a40e523716504525b6016ae96844ddc533163059b3067==\"" +
			"            }" +
			"          ]" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Megan\"," +
			"      \"family_name\": \"Howard\"," +
			"      \"birthdate\": \"2000-01-31\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"NZ\"" +
			"      }," +
			"      \"address\": {" +
			"        \"locality\": \"Croydon\"," +
			"        \"country\": \"UK\"," +
			"        \"street_address\": \"69 Kidderminster Road\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.UK_TFIDA, verification.getTrustFramework());
		assertEquals(IdentityAssuranceLevel.HIGH, verification.getAssuranceLevel());
		assertEquals(new Policy("gpg45"), verification.getAssuranceProcess().getPolicy());
		assertEquals(new Procedure("h1b"), verification.getAssuranceProcess().getProcedure());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2020-09-23T14:12Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("99476DA2-ACDC-5N13-10WC-26B415B52"), verification.getVerificationProcess());
		
		VouchEvidence evidence = verification.getEvidence().get(0).toVouchEvidence();
		assertEquals(IdentityEvidenceType.VOUCH, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.VPIP, evidence.getValidationMethod().getType());
		assertEquals(new Policy("gpg45"), evidence.getValidationMethod().getPolicy());
		assertEquals(new Procedure("score_3"), evidence.getValidationMethod().getProcedure());
		assertEquals(VerificationMethodType.PVR, evidence.getVerificationMethod().getType());
		assertEquals(new Policy("gpg45"), evidence.getVerificationMethod().getPolicy());
		assertEquals(new Procedure("score_3"), evidence.getVerificationMethod().getProcedure());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2020-02-23T07:52Z"), evidence.getVerificationTime());
		
		Attestation attestation = evidence.getAttestation();
		assertEquals(VouchType.WRITTEN_ATTESTATION, attestation.getType());
		assertEquals(new ReferenceNumber("6485-1619-3976-6671"), attestation.getReferenceNumber());
		assertEquals(new SimpleDate(2020, 2, 13), attestation.getDateOfIssuance());
		
		Voucher voucher = attestation.getVoucher();
		assertEquals(new Name("Peter Crowe"), voucher.getName());
		assertEquals(new Occupation("Executive Principal"), voucher.getOccupation());
		assertEquals(new Organization("Kristin School"), voucher.getOrganization());
		
		EmbeddedAttachment scanOfVouch = evidence.getAttachments().get(0).toEmbeddedAttachment();
		assertEquals("scan of vouch", scanOfVouch.getDescriptionString());
		assertEquals(ContentType.APPLICATION_PDF, scanOfVouch.getContent().getType());
		assertEquals(new Base64("d16d2552e35582810e5a40e523716504525b6016ae96844ddc533163059b3067=="), scanOfVouch.getContent().getBase64());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		
		assertEquals("Megan", personClaims.getGivenName());
		assertEquals("Howard", personClaims.getFamilyName());
		assertEquals("2000-01-31", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("NZ"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Croydon", personClaims.getAddress().getLocality());
		assertEquals("UK", personClaims.getAddress().getCountry());
		assertEquals("69 Kidderminster Road", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#name-document-with-validation-an
	public void testAssurance_parseExample_documentWithValidationAndVerificationDetails()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": {" +
			"    \"verification\": {" +
			"      \"trust_framework\": \"it_spid\"," +
			"      \"time\": \"2019-04-20T20:16Z\"," +
			"      \"verification_process\": \"b54c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"      \"evidence\": [" +
			"        {" +
			"          \"type\": \"document\"," +
			"          \"validation_method\": {" +
			"            \"type\": \"vcrypt\"" +
			"          }," +
			"          \"verification_method\": {" +
			"              \"type\": \"bvr\"" +
			"          }," +
			"          \"time\": \"2019-04-20T20:11Z\"," +
			"          \"document_details\": {" +
			"            \"type\": \"passport\"," +
			"            \"issuer\": {" +
			"              \"name\": \"Ministro Affari Esteri\"," +
			"              \"country_code\": \"ITA\"" + // TODO fix example
			"            }," +
			"            \"document_number\": \"83774554\"," +
			"            \"date_of_issuance\": \"2011-04-20\"," +
			"            \"date_of_expiry\": \"2021-04-19\"" +
			"          }" +
			"        }" +
			"      ]" +
			"    }," +
			"    \"claims\": {" +
			"      \"given_name\": \"Maria\"," +
			"      \"family_name\": \"Rossi\"," +
			"      \"birthdate\": \"1980-01-11\"," +
			"      \"place_of_birth\": {" +
			"        \"country\": \"IT\"," + // TODO fix example, 3 letter code
			"        \"locality\": \"Roma\"" +
			"      }," +
			"      \"nationalities\": [" +
			"        \"IT\"" +
			"      ]," +
			"      \"address\": {" +
			"        \"locality\": \"Imola BO\"," +
			"        \"postal_code\": \"40026\"," +
			"        \"country\": \"ITA\"," +
			"        \"street_address\": \"Viale Dante Alighieri, 26\"" +
			"      }" +
			"    }" +
			"  }" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(1, verifiedClaimsSets.size());
		
		VerifiedClaimsSet verifiedClaimsSet = verifiedClaimsSets.get(0);
		
		IdentityVerification verification = verifiedClaimsSet.getVerification();
		assertEquals(IdentityTrustFramework.IT_SPID, verification.getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2019-04-20T20:16Z"), verification.getVerificationTime());
		assertEquals(new VerificationProcess("b54c6f-6d3f-4ec5-973e-b0d8506f3bc7"), verification.getVerificationProcess());
		
		DocumentEvidence evidence = verification.getEvidence().get(0).toDocumentEvidence();
		assertEquals(IdentityEvidenceType.DOCUMENT, evidence.getEvidenceType());
		assertEquals(ValidationMethodType.VCRYPT, evidence.getValidationMethod().getType());
		assertEquals(VerificationMethodType.BVR, evidence.getVerificationMethod().getType());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2019-04-20T20:11Z"), evidence.getVerificationTime());
		
		DocumentDetails documentDetails = evidence.getDocumentDetails();
		assertEquals(DocumentType.PASSPORT, documentDetails.getType());
		assertEquals(new Name("Ministro Affari Esteri"), documentDetails.getIssuer().getName());
		assertEquals(new ISO3166_1Alpha3CountryCode("ITA"), documentDetails.getIssuer().getCountryCode());
		assertEquals(new DocumentNumber("83774554"), documentDetails.getDocumentNumber());
		assertEquals(new SimpleDate(2011, 4, 20), documentDetails.getDateOfIssuance());
		assertEquals(new SimpleDate(2021, 4, 19), documentDetails.getDateOfExpiry());
		
		PersonClaims personClaims = verifiedClaimsSet.getClaimsSet();
		assertEquals("Maria", personClaims.getGivenName());
		assertEquals("Rossi", personClaims.getFamilyName());
		assertEquals("1980-01-11", personClaims.getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("IT"), personClaims.getPlaceOfBirth().getCountry());
		assertEquals("Roma", personClaims.getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("IT")), personClaims.getNationalities());
		assertEquals("Imola BO", personClaims.getAddress().getLocality());
		assertEquals("40026", personClaims.getAddress().getPostalCode());
		assertEquals("ITA", personClaims.getAddress().getCountry());
		assertEquals("Viale Dante Alighieri, 26", personClaims.getAddress().getStreetAddress());
	}
	
	
	// https://openid.bitbucket.io/eKYC-IDA/openid-connect-4-identity-assurance-1_0-master.html#section-8.14
	public void testAssurance_parseExample_multipleVerifiedClaims()
		throws ParseException {
		
		String json =
			"{" +
			"  \"sub\":\"556be981-31ec-4cf0-8427-dd70ae7699db\"," + // added for valid UserInfo
			"  \"verified_claims\": [" +
			"    {" +
			"      \"verification\": {" +
			"        \"trust_framework\": \"eidas\"," +
			"        \"assurance_level\": \"substantial\"" +
			"      }," +
			"      \"claims\": {" +
			"        \"given_name\": \"Max\"," +
			"        \"family_name\": \"Meier\"," +
			"        \"birthdate\": \"1956-01-28\"," +
			"        \"place_of_birth\": {" +
			"          \"country\": \"DE\"," +
			"          \"locality\": \"Musterstadt\"" +
			"        }," +
			"        \"nationalities\": [" +
			"          \"DE\"" +
			"        ]" +
			"      }" +
			"    }," +
			"    {" +
			"      \"verification\": {" +
			"        \"trust_framework\": \"de_aml\"," +
			"        \"time\": \"2012-04-23T18:25Z\"," +
			"        \"verification_process\": \"f24c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"        \"evidence\": [" +
			"          {" +
			"            \"type\": \"document\"," +
			"            \"method\": \"pipp\"," +
			"            \"time\": \"2012-04-22T11:30Z\"," +
			"            \"document_details\": {" +
			"              \"type\": \"idcard\"" +
			"            }" +
			"          }" +
			"        ]" +
			"      }," +
			"      \"claims\": {" +
			"        \"address\": {" +
			"          \"locality\": \"Maxstadt\"," +
			"          \"postal_code\": \"12344\"," +
			"          \"country\": \"DE\"," +
			"          \"street_address\": \"An der Weide 22\"" +
			"        }" +
			"      }" +
			"    }" +
			"  ]" +
			"}" +
			"";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("556be981-31ec-4cf0-8427-dd70ae7699db"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSets = userInfo.getVerifiedClaims();
		assertEquals(2, verifiedClaimsSets.size());
		
		VerifiedClaimsSet claimsSetOne = verifiedClaimsSets.get(0);
		assertEquals(IdentityTrustFramework.EIDAS, claimsSetOne.getVerification().getTrustFramework());
		assertEquals(IdentityAssuranceLevel.SUBSTANTIAL, claimsSetOne.getVerification().getAssuranceLevel());
		assertEquals("Max", claimsSetOne.getClaimsSet().getGivenName());
		assertEquals("Meier", claimsSetOne.getClaimsSet().getFamilyName());
		assertEquals("1956-01-28", claimsSetOne.getClaimsSet().getBirthdate());
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), claimsSetOne.getClaimsSet().getPlaceOfBirth().getCountry());
		assertEquals("Musterstadt", claimsSetOne.getClaimsSet().getPlaceOfBirth().getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), claimsSetOne.getClaimsSet().getNationalities());
		
		
		VerifiedClaimsSet claimsSetTwo = verifiedClaimsSets.get(1);
		assertEquals(IdentityTrustFramework.DE_AML, claimsSetTwo.getVerification().getTrustFramework());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-23T18:25Z"), claimsSetTwo.getVerification().getVerificationTime());
		assertEquals(new VerificationProcess("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"), claimsSetTwo.getVerification().getVerificationProcess());
		assertEquals(IdentityVerificationMethod.PIPP, claimsSetTwo.getVerification().getEvidence().get(0).toDocumentEvidence().getMethod());
		assertEquals(DateWithTimeZoneOffset.parseISO8601String("2012-04-22T11:30Z"), claimsSetTwo.getVerification().getEvidence().get(0).toDocumentEvidence().getVerificationTime());
		assertEquals(DocumentType.IDCARD, claimsSetTwo.getVerification().getEvidence().get(0).toDocumentEvidence().getDocumentDetails().getType());
	}
	
	
	public void testAssurance_basicGettersAndSetters() throws ParseException {
		
		Subject subject = new Subject("alice");
		UserInfo userInfo = new UserInfo(subject);
		
		assertNull(userInfo.getPlaceOfBirth());
		Birthplace birthplace = new Birthplace(new ISO3166_1Alpha2CountryCode("DE"), "Muster Region", "Musterstadt");
		userInfo.setPlaceOfBirth(birthplace);
		assertEquals(birthplace.getCountry(), userInfo.getPlaceOfBirth().getCountry());
		assertEquals(birthplace.getRegion(), userInfo.getPlaceOfBirth().getRegion());
		assertEquals(birthplace.getLocality(), userInfo.getPlaceOfBirth().getLocality());
		
		assertNull(userInfo.getBirthplace());
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
		String title = "Mrs.";
		userInfo.setTitle(title);
		assertEquals(title, userInfo.getTitle());
		
		assertNull(userInfo.getMSISDN());
		MSISDN msisdn = new MSISDN("359861000000");
		userInfo.setMSISDN(msisdn);
		assertEquals(msisdn, userInfo.getMSISDN());
		
		assertNull(userInfo.getAlsoKnownAs());
		String aka = "aka";
		userInfo.setAlsoKnownAs(aka);
		assertEquals(aka, userInfo.getAlsoKnownAs());
		
		String json = userInfo.toJSONString();
		
		userInfo = UserInfo.parse(json);
		
		assertEquals(birthplace.getCountry(), userInfo.getPlaceOfBirth().getCountry());
		assertEquals(birthplace.getRegion(), userInfo.getPlaceOfBirth().getRegion());
		assertEquals(birthplace.getLocality(), userInfo.getPlaceOfBirth().getLocality());
		assertEquals(birthplace.getCountry(), userInfo.getBirthplace().getCountry());
		assertEquals(birthplace.getRegion(), userInfo.getBirthplace().getRegion());
		assertEquals(birthplace.getLocality(), userInfo.getBirthplace().getLocality());
		assertEquals(nats, userInfo.getNationalities());
		assertEquals(birthFamilyName, userInfo.getBirthFamilyName());
		assertEquals(birthGivenName, userInfo.getBirthGivenName());
		assertEquals(birthMiddleName, userInfo.getBirthMiddleName());
		assertEquals(salutation, userInfo.getSalutation());
		assertEquals(title, userInfo.getTitle());
		assertEquals(msisdn, userInfo.getMSISDN());
		assertEquals(aka, userInfo.getAlsoKnownAs());
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
		
		assertNull(userInfo.getAlsoKnownAs(en));
		assertNull(userInfo.getAlsoKnownAs(de));
		String aka = "aka";
		userInfo.setAlsoKnownAs(aka + "#en", en);
		userInfo.setAlsoKnownAs(aka + "#de", de);
		assertEquals(aka + "#en", userInfo.getAlsoKnownAs(en));
		assertEquals(aka + "#de", userInfo.getAlsoKnownAs(de));
		
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
		
		map = userInfo.getAlsoKnownAsEntries();
		assertEquals(aka + "#en", map.get(en));
		assertEquals(aka + "#de", map.get(de));
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
		assertEquals(aka + "#en", userInfo.getAlsoKnownAs(en));
		assertEquals(aka + "#de", userInfo.getAlsoKnownAs(de));
		
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
		
		map = userInfo.getAlsoKnownAsEntries();
		assertEquals(aka + "#en", map.get(en));
		assertEquals(aka + "#de", map.get(de));
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
	
	
	// https://bitbucket.org/openid/ekyc-ida/src/master/examples/response/multiple_verified_claims.json
	public void testAssurance_exampleMultipleVerifiedClaims() throws ParseException {
		
		String json = "{" +
			"  \"sub\":\"66dd9858-9e0c-460c-a173-0b7291c5c1b2\", " + // to make valid userinfo
			"  \"verified_claims\":[" +
			"    {" +
			"      \"verification\": {" +
			"        \"trust_framework\": \"eidas_ial_substantial\"" +
			"      }," +
			"      \"claims\": {" +
			"        \"given_name\": \"Max\"," +
			"        \"family_name\": \"Meier\"," +
			"        \"birthdate\": \"1956-01-28\"," +
			"        \"place_of_birth\": {" +
			"          \"country\": \"DE\"," +
			"          \"locality\": \"Musterstadt\"" +
			"        }," +
			"        \"nationalities\": [" +
			"          \"DE\"" +
			"        ]" +
			"      }" +
			"    }," +
			"    {" +
			"      \"verification\":{" +
			"        \"trust_framework\":\"de_aml\"," +
			"        \"time\":\"2012-04-23T18:25Z\"," +
			"        \"verification_process\":\"f24c6f-6d3f-4ec5-973e-b0d8506f3bc7\"," +
			"        \"evidence\":[" +
			"          {" +
			"            \"type\":\"id_document\"," +
			"            \"method\":\"pipp\"," +
			"            \"time\": \"2012-04-22T11:30Z\"," +
			"            \"document\":{" +
			"              \"type\":\"idcard\"" +
			"            }" +
			"          }" +
			"        ]" +
			"      }," +
			"      \"claims\":{" +
			"        \"address\":{" +
			"          \"locality\":\"Maxstadt\"," +
			"          \"postal_code\":\"12344\"," +
			"          \"country\":\"DE\"," +
			"          \"street_address\":\"An der Sanddüne 22\"" +
			"        }" +
			"      }" +
			"    }" +
			"  ]" +
			"}";
		
		UserInfo userInfo = UserInfo.parse(json);
		
		assertEquals(new Subject("66dd9858-9e0c-460c-a173-0b7291c5c1b2"), userInfo.getSubject());
		
		List<VerifiedClaimsSet> verifiedClaimsSetList = userInfo.getVerifiedClaims();
		assertEquals(2, verifiedClaimsSetList.size());
		
		VerifiedClaimsSet s1 = verifiedClaimsSetList.get(0);
		assertEquals(IdentityTrustFramework.EIDAS_IAL_SUBSTANTIAL, s1.getVerification().getTrustFramework());
		assertEquals("Max", s1.getClaimsSet().getGivenName());
		assertEquals("Meier", s1.getClaimsSet().getFamilyName());
		assertEquals("1956-01-28", s1.getClaimsSet().getBirthdate());
		Birthplace birthplace = s1.getClaimsSet().getPlaceOfBirth();
		assertEquals(new ISO3166_1Alpha2CountryCode("DE"), birthplace.getCountry());
		assertEquals("Musterstadt", birthplace.getLocality());
		assertEquals(Collections.singletonList(new ISO3166_1Alpha2CountryCode("DE")), s1.getClaimsSet().getNationalities());
		
		VerifiedClaimsSet s2 = verifiedClaimsSetList.get(1);
		assertEquals(IdentityTrustFramework.DE_AML, s2.getVerification().getTrustFramework());
		assertEquals("2012-04-23T18:25:00Z", s2.getVerification().getVerificationTime().toISO8601String());
		assertEquals(new VerificationProcess("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"), s2.getVerification().getVerificationProcess());
		IDDocumentEvidence evidence = s2.getVerification().getEvidence().get(0).toIDDocumentEvidence();
		assertEquals(IdentityVerificationMethod.PIPP, evidence.getVerificationMethod());
		assertEquals("2012-04-22T11:30:00Z", evidence.getVerificationTime().toISO8601String());
		assertEquals(IDDocumentType.IDCARD, evidence.getIdentityDocument().getType());
		Address address = s2.getClaimsSet().getAddress();
		assertEquals("Maxstadt", address.getLocality());
		assertEquals("12344", address.getPostalCode());
		assertEquals("DE", address.getCountry());
		assertEquals("An der Sanddüne 22", address.getStreetAddress());
	}
	
	
	public void testAssurance_onlineExampleWithVerifiedClaims() throws ParseException {
		
		// The verification details for some eIDAS process
		Date now = new Date();
		DateWithTimeZoneOffset timestamp = new DateWithTimeZoneOffset(
			now,
			TimeZone.getDefault());
		
		IdentityVerification verification = new IdentityVerification(
			IdentityTrustFramework.EIDAS,
			IdentityAssuranceLevel.SUBSTANTIAL,
			null,
			timestamp,
			new VerificationProcess(UUID.randomUUID().toString()),
			new ElectronicSignatureEvidence(
				new SignatureType("qes_eidas"),
				new Issuer("https://qes-provider.org"),
				new SerialNumber("cc58176d-6cd4-4d9d-bad9-50981ad3ee1f"),
				timestamp,
				null));
		
		PersonClaims claims = new PersonClaims();
		claims.setGivenName("Alice");
		claims.setFamilyName("Adams");
		claims.setEmailAddress("alice@wonderland.com");
		
		VerifiedClaimsSet verifiedClaims = new VerifiedClaimsSet(
			verification,
			claims);
		
		UserInfo userInfo = new UserInfo(new Subject("alice"));
		userInfo.setVerifiedClaims(verifiedClaims);
		
//		System.out.println(userInfo.toJSONObject());
		
		UserInfoSuccessResponse userInfoResponse = new UserInfoSuccessResponse(userInfo);
		userInfo = userInfoResponse.getUserInfo();
		
//		System.out.println("Subject: " + userInfo.getSubject());
		
		if (userInfo.getVerifiedClaims() == null) {
			System.out.println("No verified claims found");
			return;
		}
		
		for (VerifiedClaimsSet verifiedClaimsSet: userInfo.getVerifiedClaims()) {
			
			IdentityVerification verification1 = verifiedClaimsSet.getVerification();
//			System.out.println("Trust framework: " + verification1.getTrustFramework());
//			System.out.println("Assurance level: " + verification1.getAssuranceLevel());
//			System.out.println("Time: " + verification1.getVerificationTime());
//			System.out.println("Verification process: " + verification1.getVerificationProcess());
			
			if (verification1.getEvidence() != null) {
				for (IdentityEvidence ev : verification1.getEvidence()) {
//					System.out.println("Evidence type: " + ev.getEvidenceType());
				}
			}
			
//			System.out.println("Verified claims: ");
			claims = verifiedClaimsSet.getClaimsSet();
//			System.out.println("Given name: " + claims.getGivenName());
//			System.out.println("Family name: " + claims.getFamilyName());
//			System.out.println("Email: " + claims.getEmailAddress());
		}
	}
}
