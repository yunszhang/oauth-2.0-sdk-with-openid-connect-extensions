package com.nimbusds.oauth2.sdk.ciba;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import junit.framework.TestCase;

public class CIBASuccessfulTokenResponseTest extends TestCase {

	public void testValidConstructor() {
		try {
			String authReqId = "123";
			AccessToken accessToken = new BearerAccessToken();
			CIBASuccessfulTokenResponse response = new CIBASuccessfulTokenResponse(accessToken,
					authReqId);
			assertNotNull("CIBASuccessfulAcknowledgementResponse is initiated correctly with required fields",
					response);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse throws incorrectly IllegalArgumentException with required field - not empty",
					false);
		}
	}

	public void testInvalidValidConstructor() {
		try {
			CIBASuccessfulTokenResponse response = new CIBASuccessfulTokenResponse(null, null);
			assertNull(
					"CIBASuccessfulAcknowledgementResponse should not be able to initialize with null into required fields",
					response);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse throws correctly IllegalArgumentException with required field - empty",
					true);
		}

		try {
			String authReqId = "123";
			CIBASuccessfulTokenResponse response = new CIBASuccessfulTokenResponse(null, authReqId);
			assertNull(
					"CIBASuccessfulAcknowledgementResponse should not be able to initialize with null into required fields",
					response);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse throws correctly IllegalArgumentException with required field - empty",
					true);
		}

		try {

			AccessToken accessToken = new BearerAccessToken();
			CIBASuccessfulTokenResponse response = new CIBASuccessfulTokenResponse(accessToken, null);
			assertNull(
					"CIBASuccessfulAcknowledgementResponse should not be able to initialize with null into required fields",
					response);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse throws correctly IllegalArgumentException with required field - empty",
					true);
		}
	}
}
