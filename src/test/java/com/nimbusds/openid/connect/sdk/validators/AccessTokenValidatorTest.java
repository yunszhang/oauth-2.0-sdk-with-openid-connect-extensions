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

package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import junit.framework.TestCase;


/**
 * Tests the access token hash validator.
 */
public class AccessTokenValidatorTest extends TestCase {
	

	public void testValid()
		throws InvalidHashException {

		AccessToken token = new BearerAccessToken(32);
		AccessTokenHash atHash = AccessTokenHash.compute(token, JWSAlgorithm.HS256);
		AccessTokenValidator.validate(token, JWSAlgorithm.HS256, atHash);
	}


	public void testUnsupportedAlg() {

		AccessToken token = new BearerAccessToken(32);
		AccessTokenHash atHash = AccessTokenHash.compute(token, JWSAlgorithm.HS256);
		try {
			AccessTokenValidator.validate(token, new JWSAlgorithm("none"), atHash);
			fail();
		} catch (InvalidHashException e) {
			// ok
		}
	}


	public void testInvalidHash() {

		AccessToken token = new BearerAccessToken(32);
		try {
			AccessTokenValidator.validate(token, JWSAlgorithm.HS256, new AccessTokenHash("xxx"));
			fail();
		} catch (InvalidHashException e) {
			// ok
		}
	}
}
