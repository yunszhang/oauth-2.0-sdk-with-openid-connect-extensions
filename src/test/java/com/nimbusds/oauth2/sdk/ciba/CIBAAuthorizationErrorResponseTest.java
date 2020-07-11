package com.nimbusds.oauth2.sdk.ciba;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

public class CIBAAuthorizationErrorResponseTest extends TestCase{

	public void testStdErrors() {

		assertTrue(CIBAAuthorizationErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_SCOPE));
		assertTrue(CIBAAuthorizationErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(CIBAAuthorizationErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_CLIENT));

		assertEquals(3, CIBAAuthorizationErrorResponse.getStandardErrors().size());
	}
	public void testToHTTPResponse()
			throws Exception {

			HTTPResponse httpResponse =
				new CIBAAuthorizationErrorResponse(OAuth2Error.INVALID_SCOPE).toHTTPResponse();

			assertEquals( HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
			assertTrue(ContentType.APPLICATION_JSON.matches(httpResponse.getEntityContentType()));
			JSONObject content = httpResponse.getContentAsJSONObject();
			assertEquals("invalid_scope", (String)content.get("error"));
			assertEquals("Invalid, unknown or malformed scope", (String)content.get("error_description"));

				
			
			assertEquals("no-store", httpResponse.getCacheControl());
			assertEquals("no-cache", httpResponse.getPragma());
		}
	

	public void testSerialiozation() {
		CIBAAuthorizationErrorResponse httpResponse = new CIBAAuthorizationErrorResponse(OAuth2Error.INVALID_SCOPE);

		HTTPResponse httpResponse2 = httpResponse.toHTTPResponse();
		JSONObject jsonObject = httpResponse.toJSONObject();
		
		try {
			CIBAAuthorizationErrorResponse parse = CIBAAuthorizationErrorResponse.parse(jsonObject);
			assertEquals(httpResponse.getErrorObject(), parse.getErrorObject());
			
		} catch (ParseException e) {
			fail();
		}
		
		try {
			CIBAAuthorizationErrorResponse parse = CIBAAuthorizationErrorResponse.parse(httpResponse2);
			assertEquals(httpResponse.getErrorObject(), parse.getErrorObject());
		} catch (ParseException e) {
			fail();
		}
	}
	
	public void testParse()
		throws Exception {

		HTTPResponse httpResponse =
			new CIBAAuthorizationErrorResponse(OAuth2Error.INVALID_SCOPE).toHTTPResponse();

		CIBAAuthorizationErrorResponse errorResponse =
				CIBAAuthorizationErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_SCOPE, errorResponse.getErrorObject());
	}
}
