package com.nimbusds.oauth2.sdk.ciba;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class CIBAAuthorizationErrorResponseTest extends TestCase{

	
	public void testStdErrors() {

		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_SCOPE));;
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_CLIENT));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.UNAUTHORIZED_CLIENT));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(OAuth2Error.ACCESS_DENIED));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.EXPIRED_LOGIN_HINT_TOKEN));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.UNKNOWN_USER_ID));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.MISSING_USER_CODE));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.INVALID_USER_CODE));
		assertTrue(CIBAErrorResponse.getStandardErrors().contains(CIBAError.INVALID_BINDING_MESSAGE));

		assertEquals(10, CIBAErrorResponse.getStandardErrors().size());
	}
	
	
	public void testToHTTPResponse()
			throws Exception {

		HTTPResponse httpResponse =
			new CIBAErrorResponse(OAuth2Error.INVALID_SCOPE).toHTTPResponse();

		assertEquals( HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		assertTrue(ContentType.APPLICATION_JSON.matches(httpResponse.getEntityContentType()));
		JSONObject content = httpResponse.getContentAsJSONObject();
		assertEquals("invalid_scope", (String)content.get("error"));
		assertEquals("Invalid, unknown or malformed scope", (String)content.get("error_description"));

		
		
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
	}
	

	public void testSerialization() {
		CIBAErrorResponse httpResponse = new CIBAErrorResponse(OAuth2Error.INVALID_SCOPE);

		HTTPResponse httpResponse2 = httpResponse.toHTTPResponse();
		JSONObject jsonObject = httpResponse.toJSONObject();
		
		try {
			CIBAErrorResponse parse = CIBAErrorResponse.parse(jsonObject);
			assertEquals(httpResponse.getErrorObject(), parse.getErrorObject());
			
		} catch (ParseException e) {
			fail();
		}
		
		try {
			CIBAErrorResponse parse = CIBAErrorResponse.parse(httpResponse2);
			assertEquals(httpResponse.getErrorObject(), parse.getErrorObject());
		} catch (ParseException e) {
			fail();
		}
	}
	
	
	public void testParse()
		throws Exception {

		HTTPResponse httpResponse =
			new CIBAErrorResponse(OAuth2Error.INVALID_SCOPE).toHTTPResponse();

		CIBAErrorResponse errorResponse =
				CIBAErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_SCOPE, errorResponse.getErrorObject());
	}
}
