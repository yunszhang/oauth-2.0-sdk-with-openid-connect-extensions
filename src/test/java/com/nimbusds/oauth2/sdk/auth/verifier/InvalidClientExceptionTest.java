package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import junit.framework.TestCase;


public class InvalidClientExceptionTest extends TestCase {
	
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
	}


	public void testConstructor() {

		InvalidClientException e = new InvalidClientException("message");
		assertEquals("message", e.getMessage());
	}


	public void testToInvalidClientErrorObject() {

		ErrorObject error = new InvalidClientException("message").toErrorObject();
		assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), error.getCode());
		assertEquals(OAuth2Error.INVALID_CLIENT.getDescription(), error.getDescription());
		assertNull(error.getURI());
	}
}
