package com.nimbusds.oauth2.sdk.ciba;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

public class CIBASuccessfulAcknowledgementResponseTest extends TestCase {

	public void testConstructors() {
		final String authReqId = "asd";
		int expiresIn = 1;
		Integer interval = Integer.valueOf(1);
		CIBASuccessfulAcknowledgementResponse response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn,
				interval);

		assertNotNull(response);

		try {
			interval = Integer.valueOf(-1);
			response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn, interval);
			assertTrue("CIBASuccessfulAcknowledgementResponse incorrectly is initialized with negative interval value",
					false);

		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse correctly throws Illegal Argument Exception with negative interval value",
					true);
		}

		try {
			expiresIn = -1;
			interval = Integer.valueOf(1);
			response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn, interval);
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse incorrectly is initialized with negative 'expires in' value",
					false);

		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse correctly throws Illegal Argument Exception with negative 'expires in' value",
					true);
		}

		expiresIn = 1;
		interval = null;
		response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn, interval);
		assertNotNull(response);

		response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn);
		assertNotNull(response);

		try {
			response = new CIBASuccessfulAcknowledgementResponse(null, expiresIn);
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse incorrectly is initialized with negative null value for authentication request id",
					false);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASuccessfulAcknowledgementResponse correctly throws Illegal Argument Exception null value for authentication request id",
					true);
		}
	}

	public void testToJson() {
		final String authReqId = "asd";
		final int expiresIn = 1;
		final Integer interval = Integer.valueOf(1);
		CIBASuccessfulAcknowledgementResponse response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn,
				interval);

		JSONObject jsonObject = response.toJSONObject();
		assertNotNull(jsonObject);
		assertEquals(jsonObject.entrySet().size(), 3);
	}

	public void testToHttpResponse() {
		final String authReqId = "asd";
		final int expiresIn = 1;
		Integer interval = Integer.valueOf(1);
		CIBASuccessfulAcknowledgementResponse response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn,
				interval);

		HTTPResponse httpResponse = response.toHTTPResponse();
		assertNotNull(httpResponse);
	}

	public void testToJsonAndParse() {
		final String authReqId = "asd";
		final int expiresIn = 1;
		Integer interval = Integer.valueOf(1);
		CIBASuccessfulAcknowledgementResponse response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn,
				interval);

		JSONObject jsonObject = response.toJSONObject();
		assertNotNull(jsonObject);
		assertEquals(jsonObject.entrySet().size(), 3);

		try {
			CIBASuccessfulAcknowledgementResponse response2 = (CIBASuccessfulAcknowledgementResponse) CIBASuccessfulAcknowledgementResponse
					.parse(jsonObject);
			assertEquals(response2.getAuthReqId(), response.getAuthReqId());
			assertEquals(response2.getExpiresIn(), response.getExpiresIn());
			assertEquals(response2.getInterval(), response.getInterval());
		} catch (ParseException e) {
			fail();
		}
	}

	public void testToHttpResponseAndParse() {
		final String authReqId = "asd";
		final int expiresIn = 1;
		Integer interval = Integer.valueOf(1);
		CIBASuccessfulAcknowledgementResponse response = new CIBASuccessfulAcknowledgementResponse(authReqId, expiresIn,
				interval);

		HTTPResponse httpResponse = response.toHTTPResponse();
		assertNotNull(httpResponse);

		try {
			CIBASuccessfulAcknowledgementResponse response2 = CIBASuccessfulAcknowledgementResponse.parse(httpResponse);
			assertEquals(response2.getAuthReqId(), response.getAuthReqId());
			assertEquals(response2.getExpiresIn(), response.getExpiresIn());
			assertEquals(response2.getInterval(), response.getInterval());
		} catch (ParseException e) {
			fail();
		}

	}
}