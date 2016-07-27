package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;


public class OIDCErrorTest extends TestCase {
	

	public void testConstants() {
		
		assertEquals("invalid_request_uri", OIDCError.INVALID_REQUEST_URI.getCode());
		assertEquals("Invalid OpenID request URI", OIDCError.INVALID_REQUEST_URI.getDescription());
		assertNull(OIDCError.INVALID_REQUEST_URI.getURI());
		
		assertEquals("invalid_request_object", OIDCError.INVALID_REQUEST_OBJECT.getCode());
		assertEquals("Invalid OpenID request JWT", OIDCError.INVALID_REQUEST_OBJECT.getDescription());
		assertNull(OIDCError.INVALID_REQUEST_OBJECT.getURI());
	}
}
