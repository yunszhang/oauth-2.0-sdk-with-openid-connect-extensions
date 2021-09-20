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

package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.ciba.CIBAGrant;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;


/**
 * Tests the abstract authorisation grant class.
 */
public class AuthorizationGrantTest extends TestCase {
	
	
	public void testParseCode()
		throws Exception {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));
		
		AuthorizationCodeGrant grant = (AuthorizationCodeGrant)AuthorizationGrant.parse(params);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals("abc", grant.getAuthorizationCode().getValue());
		assertEquals("https://client.com/in", grant.getRedirectionURI().toString());
	}


	public void testParseRefreshToken()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("refresh_token"));
		params.put("refresh_token", Collections.singletonList("abc123"));

		RefreshTokenGrant grant = (RefreshTokenGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.REFRESH_TOKEN, grant.getType());
		assertEquals("abc123", grant.getRefreshToken().getValue());
	}


	public void testParsePassword()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.PASSWORD, grant.getType());
		assertEquals("alice", grant.getUsername());
		assertEquals("secret", grant.getPassword().getValue());
	}


	public void testParseClientCredentials()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("client_credentials"));

		ClientCredentialsGrant grant = (ClientCredentialsGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.CLIENT_CREDENTIALS, grant.getType());
	}


	public void testParseJWTBearer()
		throws Exception {

		// Claims set not verified
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.JWT_BEARER.getValue()));
		params.put("assertion", Collections.singletonList(assertion.serialize()));

		JWTBearerGrant grant = (JWTBearerGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion.serialize(), grant.getAssertion());
		assertEquals(JWSAlgorithm.HS256, grant.getJWTAssertion().getHeader().getAlgorithm());
	}


	public void testParseSAML2Bearer()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.SAML2_BEARER.getValue()));
		params.put("assertion", Collections.singletonList("abc"));

		SAML2BearerGrant grant = (SAML2BearerGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.SAML2_BEARER, grant.getType());
		assertEquals("abc", grant.getAssertion());
		assertEquals("abc", grant.getSAML2Assertion().toString());
	}

	
	public void testParseDeviceCode()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.DEVICE_CODE.getValue()));
		params.put("device_code", Collections.singletonList("abc"));

		DeviceCodeGrant grant = (DeviceCodeGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.DEVICE_CODE, grant.getType());
		assertEquals("abc", grant.getDeviceCode().getValue());
	}
	

	public void testParseCIBA()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.CIBA.getValue()));
		params.put("auth_req_id", Collections.singletonList("1c266114-a1be-4252-8ad1-04986c5b9ac1"));

		CIBAGrant grant = (CIBAGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.CIBA, grant.getType());
		assertEquals("1c266114-a1be-4252-8ad1-04986c5b9ac1", grant.getAuthRequestID().getValue());
	}

	public void testParseTokenExchange() throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
		params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
		params.put("subject_token", Collections.singletonList("subjectToken"));
		params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
		params.put("actor_token", Collections.singletonList("actorToken"));
		params.put("actor_token_type", Collections.singletonList("actorTokenType"));

		TokenExchangeGrant grant = (TokenExchangeGrant) AuthorizationGrant.parse(params);

		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals("requestedTokenType", grant.getRequestedTokenType().getURI().toString());
		assertEquals("subjectToken", grant.getSubjectToken().getValue());
		assertEquals("subjectTokenType", grant.getSubjectTokenType().getURI().toString());
		assertEquals("actorToken", grant.getActorToken().getValue());
		assertEquals("actorTokenType", grant.getActorTokenType().getURI().toString());
	}
	
	
	public void testParseException_missingGrantTypeParameter() {
		
		Map<String,List<String>> params = new HashMap<>();
		
		try {
			AuthorizationGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing grant_type parameter", e.getMessage());
		}
	}
	
	
	public void testParseException_unsupportedGrant() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("no-such-grant"));
		
		try {
			AuthorizationGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid or unsupported grant type: no-such-grant", e.getMessage());
		}
	}
}
