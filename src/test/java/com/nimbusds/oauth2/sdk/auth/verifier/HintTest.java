package com.nimbusds.oauth2.sdk.auth.verifier;


import junit.framework.TestCase;


public class HintTest extends TestCase {
	

	public void testConstants() {

		assertEquals("CLIENT_HAS_REMOTE_JWK_SET", Hint.CLIENT_HAS_REMOTE_JWK_SET.name());
		assertEquals(1, Hint.values().length);
	}
}
