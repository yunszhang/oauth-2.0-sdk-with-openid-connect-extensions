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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import junit.framework.TestCase;


/**
 * Tests the code validator.
 */
public class AuthorizationCodeValidatorTest extends TestCase {
	

	public void testSuccess()
		throws InvalidHashException {

		AuthorizationCode code = new AuthorizationCode(16);
		CodeHash codeHash = CodeHash.compute(code, JWSAlgorithm.RS256);
		AuthorizationCodeValidator.validate(code, JWSAlgorithm.RS256, codeHash);
	}


	public void testUnsupportedAlg() {

		AuthorizationCode code = new AuthorizationCode(16);
		CodeHash codeHash = CodeHash.compute(code, JWSAlgorithm.RS256);
		try {
			AuthorizationCodeValidator.validate(code, new JWSAlgorithm("none"), codeHash);
			fail();
		} catch (InvalidHashException e) {
			assertEquals("Authorization code hash (c_hash) mismatch", e.getMessage());
		}
	}


	public void testInvalidHash() {

		AuthorizationCode code = new AuthorizationCode(16);
		try {
			AuthorizationCodeValidator.validate(code, JWSAlgorithm.RS256, new CodeHash("xxx"));
			fail();
		} catch (InvalidHashException e) {
			assertEquals("Authorization code hash (c_hash) mismatch", e.getMessage());
		}
	}
}
