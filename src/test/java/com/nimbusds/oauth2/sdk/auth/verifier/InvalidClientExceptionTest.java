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

package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import junit.framework.TestCase;


public class InvalidClientExceptionTest extends TestCase {


	public void testInheritance() {

		assertTrue(InvalidClientException.BAD_ID instanceof GeneralException);
	}


	public void testStatic() {

		assertEquals("Bad client ID", InvalidClientException.BAD_ID.getMessage());
		assertEquals("The client is not registered for the requested authentication method", InvalidClientException.NOT_REGISTERED_FOR_AUTH_METHOD.getMessage());
		assertEquals("The client has no registered secret", InvalidClientException.NO_REGISTERED_SECRET.getMessage());
		assertEquals("The client has no registered JWK set", InvalidClientException.NO_REGISTERED_JWK_SET.getMessage());
		assertEquals("Expired client secret", InvalidClientException.EXPIRED_SECRET.getMessage());
		assertEquals("Bad client secret", InvalidClientException.BAD_SECRET.getMessage());
		assertEquals("Bad JWT HMAC", InvalidClientException.BAD_JWT_HMAC.getMessage());
		assertEquals("No matching JWKs found", InvalidClientException.NO_MATCHING_JWK.getMessage());
		assertEquals("Bad JWT signature", InvalidClientException.BAD_JWT_SIGNATURE.getMessage());
		assertEquals("Couldn't validate client X.509 certificate signature: No matching registered client JWK found", InvalidClientException.BAD_SELF_SIGNED_CLIENT_CERTIFICATE.getMessage());
	}


	public void testConstructor() {

		InvalidClientException e = new InvalidClientException("message");
		assertEquals("message", e.getMessage());
	}


	public void testToInvalidClientErrorObject() {

		ErrorObject error = new InvalidClientException("message").getErrorObject();
		assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), error.getCode());
		assertEquals(OAuth2Error.INVALID_CLIENT.getDescription(), error.getDescription());
		assertNull(error.getURI());
	}
}
