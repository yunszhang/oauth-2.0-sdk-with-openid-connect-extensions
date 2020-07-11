package com.nimbusds.oauth2.sdk.ciba;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.claims.ACR;

import junit.framework.TestCase;

public class CIBASignedAuthenticationRequestTest extends TestCase {

	public void testConstructorsWithAllParameters() throws URISyntaxException {

		Scope scope = new Scope();
		String token = "";
		CIBASignedAuthenticationRequest request = null;
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
		final Audience aud = Audience.create("https://server.example.com").get(0);
		final Issuer iss = new Issuer("s6BhdRkqt3");
		final Date exp = new Date(1537820086000L);
		final Date iat = new Date(1537819486000L);
		final Date nbf = new Date(1537818886000L);
		final JWTID jti = new JWTID("4LTCqACC2ESC5BWCnN3j58EnA");
		try {
			request = new CIBASignedAuthenticationRequest(uri, clientId, scope, clientNotificationToken, acrValues,
					loginHintToken, idTokenHint, loginHint, bindingMessage, userCode, requestedЕxpiry, aud, iss, exp, iat, nbf, jti);
			
			assertNotNull(request);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBASignedAuthenticationRequest failed", false);

		}
	}

	public void testCorrectClientNotificationTokenSize() throws URISyntaxException {

		URI uri = new URI("https://c2id.com/ciba/");
		final Audience aud = Audience.create("https://server.example.com").get(0);
		final Issuer iss = new Issuer("s6BhdRkqt3");
		final Date exp = new Date(1537820086000L);
		final Date iat = new Date(1537819486000L);
		final Date nbf = new Date(1537818886000L);
		final JWTID jti = new JWTID("4LTCqACC2ESC5BWCnN3j58EnA");
		Scope scope = new Scope();
		StringBuffer sb = new StringBuffer();
//	The length of the token MUST NOT exceed 1024 characters and it MUST conform to the syntax for Bearer credentials as defined in Section 2.1 o

		for (int i = 0; i < 1024; i++) {
			sb.append("A");
		}

		String token = sb.toString();
		try {
			CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest(uri, scope, token, aud, iss, exp, iat, nbf, jti);
			assertNotNull(request);
		} catch (IllegalArgumentException e) {
			assertTrue("CIBASignedAuthenticationRequest failed", false);
		}
	}

	public void testInvalidClientNotificationTokenSize() {

		try {
			CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder().build();
			assertTrue("CIBASignedAuthenticationRequest has scope and client_notification_token as required", false);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASignedAuthenticationRequest throws correctly IllegalArgumentException with required fields empty",
					true);
		}
//	 token empty 
		try {

			Scope scope = new Scope();
			CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder().scope(scope)
					.build();
			assertTrue("CIBASignedAuthenticationRequest has scope and client_notification_token as required", false);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASignedAuthenticationRequest throws correctly IllegalArgumentException with required field empty",
					true);
		}

		// scope empty
		try {

			String token = "";
			CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder()
					.clientNotificationToken(token).build();
			assertTrue("CIBASignedAuthenticationRequest has scope and client_notification_token as required", false);
		} catch (IllegalArgumentException e) {
			assertTrue(
					"CIBASignedAuthenticationRequest throws correctly IllegalArgumentException with required field empty",
					true);
		}

		// token too long
		String token = "";
		Scope scope = new Scope();
		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < 1025; i++) {
			sb.append("A");
		}

		CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder().scope(scope)
				.clientNotificationToken(token).build();

		assertNotNull(request);

		// TODO test invalid bearer credential syntax
	}

	public void testRequestedЕxpiryDifferentInputs() {
		final Audience aud = Audience.create("https://server.example.com").get(0);
		final Issuer iss = new Issuer("s6BhdRkqt3");
		final Date exp = new Date(1537820086000L);
		final Date iat = new Date(1537819486000L);
		final Date nbf = new Date(1537818886000L);
		final JWTID jti = new JWTID("4LTCqACC2ESC5BWCnN3j58EnA");
		
		String token = "";
		Scope scope = new Scope();

		// no requested expiry
		CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder().scope(scope)
				.setIat(iat).setAud(aud).setExp(exp).setNbf(nbf).setJti(jti).setIss(iss)
				.clientNotificationToken(token).build();
		assertNotNull(request);
//	positive integer
		request = new CIBASignedAuthenticationRequest.Builder().scope(scope).clientNotificationToken(token)
				.setIat(iat).setAud(aud).setExp(exp).setNbf(nbf).setJti(jti).setIss(iss)
				.setRequestedЕxpiry(Integer.valueOf(1)).build();
		assertNotNull(request);

		// negative integer
		try {
			request = new CIBASignedAuthenticationRequest.Builder().scope(scope).clientNotificationToken(token)
					.setIat(iat).setAud(aud).setExp(exp).setNbf(nbf).setJti(jti).setIss(iss)
					.setRequestedЕxpiry(Integer.valueOf(-1)).build();

			assertTrue("Requested Еxpiry should not be negative", false);
		} catch (IllegalArgumentException e) {
			assertTrue("The \"requested_expiry\" parameter must be positive integer".equals(e.getMessage()));
		}
	}

	public void testToHTTPRequest() throws URISyntaxException {
		final Audience aud = Audience.create("https://server.example.com").get(0);
		final Issuer iss = new Issuer("s6BhdRkqt3");
		final Date exp = new Date(1537820086000L);
		final Date iat = new Date(1537819486000L);
		final Date nbf = new Date(1537818886000L);
		final JWTID jti = new JWTID("4LTCqACC2ESC5BWCnN3j58EnA");
		
		URI uri = new URI("https://c2id.com/ciba/");
		ClientID clientId = new ClientID("asd");
		CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder().setClientId(clientId)
				.setIat(iat).setAud(aud).setExp(exp).setNbf(nbf).setJti(jti).setIss(iss)
				.setUri(uri).setScope(new Scope()).setClientNotificationToken("123").build();
		HTTPRequest request2 = request.toHTTPRequest();
		assertNotNull(request2);
	}

	public void testParse() throws URISyntaxException {
		String token = "";
		Scope scope = new Scope("123");
		ClientID clientId = new ClientID("123");
		URI uri = new URI("https://c2id.com/ciba/");
		final Audience aud = Audience.create("https://server.example.com").get(0);
		final Issuer iss = new Issuer("s6BhdRkqt3");
		final Date exp = new Date(1537820086000L);
		final Date iat = new Date(1537819486000L);
		final Date nbf = new Date(1537818886000L);
		final JWTID jti = new JWTID("4LTCqACC2ESC5BWCnN3j58EnA");
		
		
		CIBASignedAuthenticationRequest request = new CIBASignedAuthenticationRequest.Builder().setClientId(clientId)
				.setIat(iat).setAud(aud).setExp(exp).setNbf(nbf).setJti(jti).setIss(iss)
				.setUri(uri).scope(scope).clientNotificationToken(token).build();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertNotNull(httpRequest);

		try {
			CIBASignedAuthenticationRequest request2 = CIBASignedAuthenticationRequest.parse(httpRequest);
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

			assertEquals(request.getAud(), request2.getAud());
			assertEquals(request.getIss(), request2.getIss());
			assertEquals(request.getExp(), request2.getExp());
			assertEquals(request.getIat(), request2.getIat());
			assertEquals(request.getNbf(), request2.getNbf());
			assertEquals(request.getJti(), request2.getJti());
		} catch (ParseException e) {
			e.printStackTrace();
			fail();
		}

	}
}