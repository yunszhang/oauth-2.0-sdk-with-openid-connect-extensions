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


import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;


/**
 * Tests the UserInfo success response.
 */
public class UserInfoSuccessResponseTest extends TestCase {


	public void testPlain()
		throws Exception {

		UserInfo claims = new UserInfo(new Subject("alice"));
		claims.setName("Alice Adams");
		claims.setEmailAddress("alice@wonderland.net");
		claims.setEmailVerified(true);

		UserInfoSuccessResponse response = new UserInfoSuccessResponse(claims);

		assertTrue(response.indicatesSuccess());
		assertEquals("application/json; charset=UTF-8", response.getEntityContentType().toString());
		assertNull(response.getUserInfoJWT());
		assertEquals(claims, response.getUserInfo());
		HTTPResponse httpResponse = response.toHTTPResponse();

		response = UserInfoSuccessResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("application/json; charset=UTF-8", response.getEntityContentType().toString());
		assertNull(response.getUserInfoJWT());

		claims = response.getUserInfo();

		assertEquals("alice", claims.getSubject().getValue());
		assertEquals("Alice Adams", claims.getName());
		assertEquals("alice@wonderland.net", claims.getEmailAddress());
		assertTrue(claims.getEmailVerified());
	}


	public void testJWT()
		throws Exception {

		UserInfo claims = new UserInfo(new Subject("alice"));
		claims.setName("Alice Adams");
		claims.setEmailAddress("alice@wonderland.net");
		claims.setEmailVerified(true);

		JWTClaimsSet claimsSet = claims.toJWTClaimsSet();

		Secret secret = new Secret();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		jwt.sign(new MACSigner(secret.getValueBytes()));

		UserInfoSuccessResponse response = new UserInfoSuccessResponse(jwt);

		assertTrue(response.indicatesSuccess());
		assertEquals(jwt, response.getUserInfoJWT());
		assertEquals("application/jwt; charset=UTF-8", response.getEntityContentType().toString());
		assertNull(response.getUserInfo());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = UserInfoSuccessResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("application/jwt; charset=UTF-8", response.getEntityContentType().toString());
		assertNull(response.getUserInfo());

		jwt = (SignedJWT)response.getUserInfoJWT();

		assertTrue(jwt.getState().equals(JWSObject.State.SIGNED));

		claims = new UserInfo(response.getUserInfoJWT().getJWTClaimsSet().toJSONObject());

		assertEquals("alice", claims.getSubject().getValue());
		assertEquals("Alice Adams", claims.getName());
		assertEquals("alice@wonderland.net", claims.getEmailAddress());
		assertTrue(claims.getEmailVerified());
	}
}
