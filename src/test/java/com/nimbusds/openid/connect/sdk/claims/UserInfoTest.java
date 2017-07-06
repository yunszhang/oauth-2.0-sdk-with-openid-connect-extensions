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

import com.nimbusds.jose.util.DateUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the UserInfo claims set.
 */
public class UserInfoTest extends TestCase {


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


	public void testPutAll()
		throws Exception {

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
	
	
	public void testAggregatedClaims_addAndGet()
		throws Exception {
		
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
}
