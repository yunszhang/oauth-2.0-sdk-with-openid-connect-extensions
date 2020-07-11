package com.nimbusds.oauth2.sdk.ciba;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ACR;

import junit.framework.TestCase;

public class CIBAAuthorizationRequestTest extends TestCase {

	public void testConstructorsWithTwoParameters() {

		Scope scope = new Scope();
		String token = "";
		CIBAAuthorizationRequest request = null;

		try {
			request = new CIBAAuthorizationRequest(scope, token);
			assertNotNull(request);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBAAuthorizationRequest failed", false);

		}
	}

	public void testConstructorsWithAllParameters() throws URISyntaxException {

		Scope scope = new Scope();
		String token = "";
		CIBAAuthorizationRequest request = null;
		URI uri = new URI("https://c2id.com/ciba/");
		ClientID clientId = new ClientID("123");
		String clientNotificationToken = "123";
		List<ACR> acrValues = Arrays.asList(ACR.PHR);
		String loginHintToken = "123";
		String idTokenHint = "123";
		String loginHint = "123";
		String bindingMessage = "123";
		String userCode = "123";
		Integer requestedЕxpiry = Integer.valueOf(1);
		try {
			request = new CIBAAuthorizationRequest(uri, clientId, scope, clientNotificationToken, acrValues, loginHintToken,
					idTokenHint, loginHint, bindingMessage, userCode, requestedЕxpiry);
			assertNotNull(request);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBAAuthorizationRequest failed", false);

		}
	}

	public void testCorrectClientNotificationTokenSize() {

		Scope scope = new Scope();
		StringBuffer sb = new StringBuffer();
//		The length of the token MUST NOT exceed 1024 characters and it MUST conform to the syntax for Bearer credentials as defined in Section 2.1 o

		for (int i = 0; i < 1024; i++) {
			sb.append("A");
		}

		String token = sb.toString();
		try {
			CIBAAuthorizationRequest request = new CIBAAuthorizationRequest(scope, token);
			assertNotNull(request);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBAAuthorizationRequest failed", false);
		}
	}

	public void testInvalidClientNotificationTokenSize() {

		try {
			CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().build();
			assertTrue("CIBAAuthorizationRequest has scope and client_notification_token as required", false);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBAAuthorizationRequest throws correctly IllegalArgumentException with required fields empty",
					true);
		}
//		 token empty 
		try {

			Scope scope = new Scope();
			CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().scope(scope).build();
			assertTrue("CIBAAuthorizationRequest has scope and client_notification_token as required", false);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBAAuthorizationRequest throws correctly IllegalArgumentException with required field empty",
					true);
		}

		// scope empty
		try {

			String token = "";
			CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().clientNotificationToken(token)
					.build();
			assertTrue("CIBAAuthorizationRequest has scope and client_notification_token as required", false);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBAAuthorizationRequest throws correctly IllegalArgumentException with required field empty",
					true);
		}

		// token too long
		String token = "";
		Scope scope = new Scope();
		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < 1025; i++) {
			sb.append("A");
		}

		CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().scope(scope)
				.clientNotificationToken(token).build();

		assertNotNull(request);

		// TODO test invalid bearer credential syntax
	}

	public void testRequestedЕxpiryDifferentInputs() {

		String token = "";
		Scope scope = new Scope();

		// no requested expiry
		CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().scope(scope)
				.clientNotificationToken(token).build();
		assertNotNull(request);
//		positive integer
		request = new CIBAAuthorizationRequest.Builder().scope(scope).clientNotificationToken(token)
				.setRequestedЕxpiry(Integer.valueOf(1)).build();
		assertNotNull(request);

		// negative integer
		try {
			request = new CIBAAuthorizationRequest.Builder().scope(scope).clientNotificationToken(token)
					.setRequestedЕxpiry(Integer.valueOf(-1)).build();

			assertTrue("Requested Еxpiry should not be negative", false);
		} catch (IllegalArgumentException e) {
			assertTrue("The \"requested_expiry\" parameter must be positive integer".equals(e.getMessage()));
		}
	}

	public void testToHTTPRequest() throws URISyntaxException {
		String token = "";
		Scope scope = new Scope();
		URI uri = new URI("https://c2id.com/ciba/");
		CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().setUri(uri).scope(scope)
				.clientNotificationToken(token).build();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertNotNull(httpRequest);

	}

	public void testParse() throws URISyntaxException {
		String token = "";
		Scope scope = new Scope("123");
		ClientID clientId = new ClientID("123");
		URI uri = new URI("https://c2id.com/ciba/");
		CIBAAuthorizationRequest request = new CIBAAuthorizationRequest.Builder().setClientId(clientId).setUri(uri).scope(scope)
				.clientNotificationToken(token).build();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertNotNull(httpRequest);

		try {
			CIBAAuthorizationRequest request2 = CIBAAuthorizationRequest.parse(httpRequest);
			assertEquals(request.getAcrValues(), request2.getAcrValues());
			assertEquals(request.getBindingMessage(), request2.getBindingMessage());
			assertEquals(request.getClientNotificationToken(), request2.getClientNotificationToken());
			assertEquals(request.getIdTokenHint(), request2.getIdTokenHint());
			assertEquals(request.getLoginHint(), request2.getLoginHint());
			assertEquals(request.getLoginHintToken(), request2.getLoginHintToken());
			assertEquals(request.getUserCode(), request2.getUserCode());
			assertEquals(request.getClientAuthentication(), request2.getClientAuthentication());
			assertEquals(request.getClientID(), request2.getClientID());
			assertEquals(request.getEndpointURI(), request2.getEndpointURI());
			assertEquals(request.getRequestedЕxpiry(), request2.getRequestedЕxpiry());
			assertEquals(request.getScope(), request2.getScope());
			assertEquals(request.getRegisteredParameterNames(), request2.getRegisteredParameterNames());
			
		} catch (ParseException e) {
			e.printStackTrace();
			fail();
		}

	}
}
