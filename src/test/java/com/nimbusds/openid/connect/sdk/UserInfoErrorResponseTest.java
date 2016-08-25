package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the UserInfo error response class.
 */
public class UserInfoErrorResponseTest extends TestCase {


	public void testStandardErrors() {

		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE));
		assertEquals(4, UserInfoErrorResponse.getStandardErrors().size());
	}


	public void testConstructAndParse()
		throws Exception {

		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());

		assertEquals("Bearer error=\"invalid_token\", error_description=\"Invalid access token\"", httpResponse.getWWWAuthenticate());

		errorResponse = UserInfoErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());

		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());
	}
	
	
	public void testOtherError()
		throws Exception {
		
		ErrorObject error = new ErrorObject("conflict", "Couldn't encrypt UserInfo JWT: Missing / expired client_secret", 409);
		
		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(error);
		
		assertEquals(error, errorResponse.getErrorObject());
		
		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertEquals(409, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getContentType().toString());
		assertNull(httpResponse.getWWWAuthenticate());
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		assertEquals(error.getCode(), jsonObject.get("error"));
		assertEquals(error.getDescription(), jsonObject.get("error_description"));
		assertEquals(2, jsonObject.size());
		
		errorResponse = UserInfoErrorResponse.parse(httpResponse);
		
		assertEquals(error.getCode(), errorResponse.getErrorObject().getCode());
		assertEquals(error.getDescription(), errorResponse.getErrorObject().getDescription());
		assertNull(errorResponse.getErrorObject().getURI());
		assertEquals(error.getHTTPStatusCode(), errorResponse.getErrorObject().getHTTPStatusCode());
	}
}
