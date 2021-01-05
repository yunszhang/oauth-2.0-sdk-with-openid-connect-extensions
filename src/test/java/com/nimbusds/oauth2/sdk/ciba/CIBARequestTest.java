package com.nimbusds.oauth2.sdk.ciba;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.ACR;

public class CIBARequestTest extends TestCase {
	
	private static final URI ENDPOINT_URI = URI.create("https://c2id.com/ciba/");
	
	private static final URL ENDPOINT_URL;
	
	private static final ClientAuthentication CLIENT_AUTH = new ClientSecretBasic(new ClientID("123"), new Secret());
	
	private static final Scope SCOPE = new Scope("openid");
	
	private static final BearerAccessToken CLIENT_NOTIFICATION_TOKEN = new BearerAccessToken("iexi7ahziT1eiCei2eengei6lai3meeg");
	
	private static final List<ACR> ACR_VALUES = Collections.singletonList(new ACR("0"));
	
	private static final String LOGIN_HINT_TOKEN_STRING = "jue7zi8Fah6siem2Eengail1ue1chu9k";
	
	private static final SignedJWT ID_TOKEN;
	
	private static final String LOGIN_HINT = "alice@wonderland.net";
	
	private static final String BINDING_MESSAGE = "W4SCT";
	
	private static final Secret USER_CODE = new Secret("8364");
	
	private static final Integer REQUESTED_EXPIRY = 60;
	
	private static final Map<String,List<String>> CUSTOM_PARAMS;
	
	static {
		try {
			ENDPOINT_URL = ENDPOINT_URI.toURL();
			
			RSAKey rsaJWK = new RSAKeyGenerator(2048)
				.keyID("1")
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			
			Issuer iss = new Issuer("https://c2id.com");
			ClientID clientID = new ClientID("123");
			Date now = new Date();
			
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10 * 60 * 1000L))
				.issueTime(now)
				.build();
			
			ID_TOKEN = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
			ID_TOKEN.sign(new RSASSASigner(rsaJWK));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("custom-xyz", Collections.singletonList("abc"));
		CUSTOM_PARAMS = Collections.unmodifiableMap(params);
	}
	
	
	private static BearerAccessToken generateExcessiveClientNotificationToken() {
		
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < CIBARequest.CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH + 1; i++) {
			sb.append("A");
		}
		BearerAccessToken clientNotificationToken = new BearerAccessToken(sb.toString());
		
		assertEquals(1025, clientNotificationToken.getValue().length());
		
		return clientNotificationToken;
	}
	
	
	public void testConstants() {
		
		assertEquals(1024, CIBARequest.CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH);
	}

	

	public void testConstructor_requiredOnly() throws java.text.ParseException {
		
		CIBARequest request = new CIBARequest(
			null,
			CLIENT_AUTH,
			SCOPE,
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null
		);
		
		assertNull(request.getEndpointURI());
		assertEquals(CLIENT_AUTH, request.getClientAuthentication());
		assertEquals(SCOPE, request.getScope());
		assertNull(request.getClientNotificationToken());
		assertNull(request.getACRValues());
		assertNull(request.getLoginHintTokenString());
		assertNull(request.getIDTokenHint());
		assertNull(request.getLoginHint());
		assertNull(request.getUserCode());
		assertNull(request.getRequestedExpiry());
		assertTrue(request.getCustomParameters().isEmpty());
		assertNull(request.getCustomParameter("no-such-param"));
		
		try {
			request.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			assertEquals("The endpoint URI is not specified", e.getMessage());
		}
		
		JWTClaimsSet jwtClaimsSet = request.toJWTClaimsSet();
		assertEquals("openid", jwtClaimsSet.getStringClaim("scope"));
		assertEquals(1, jwtClaimsSet.getClaims().size());
	}
	

	public void testConstructor_allSet() throws MalformedURLException, ParseException {
		
		CIBARequest request = new CIBARequest(
			ENDPOINT_URI,
			CLIENT_AUTH,
			SCOPE,
			CLIENT_NOTIFICATION_TOKEN,
			ACR_VALUES,
			LOGIN_HINT_TOKEN_STRING,
			ID_TOKEN,
			LOGIN_HINT,
			BINDING_MESSAGE,
			USER_CODE,
			REQUESTED_EXPIRY,
			CUSTOM_PARAMS
		);
		
		assertEquals(ENDPOINT_URI, request.getEndpointURI());
		assertEquals(CLIENT_AUTH, request.getClientAuthentication());
		assertEquals(SCOPE, request.getScope());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
		assertEquals(ACR_VALUES, request.getACRValues());
		assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
		assertEquals(ID_TOKEN, request.getIDTokenHint());
		assertEquals(LOGIN_HINT, request.getLoginHint());
		assertEquals(BINDING_MESSAGE, request.getBindingMessage());
		assertEquals(USER_CODE, request.getUserCode());
		assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
		assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT_URI.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		
		assertEquals(((ClientSecretBasic)CLIENT_AUTH).toHTTPAuthorizationHeader(), ClientSecretBasic.parse(httpRequest).toHTTPAuthorizationHeader());
		
		assertEquals(2, httpRequest.getHeaderMap().size());
		
		assertEquals(request.toParameters(), httpRequest.getQueryParameters());
		
		request = CIBARequest.parse(httpRequest);
		
		assertEquals(ENDPOINT_URI, request.getEndpointURI());
		assertEquals(((ClientSecretBasic)CLIENT_AUTH).toHTTPAuthorizationHeader(), ((ClientSecretBasic)request.getClientAuthentication()).toHTTPAuthorizationHeader());
		assertEquals(SCOPE, request.getScope());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
		assertEquals(ACR_VALUES, request.getACRValues());
		assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
		assertEquals(ID_TOKEN.serialize(), request.getIDTokenHint().getParsedString());
		assertEquals(LOGIN_HINT, request.getLoginHint());
		assertEquals(BINDING_MESSAGE, request.getBindingMessage());
		assertEquals(USER_CODE, request.getUserCode());
		assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
		assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
		
		JWTClaimsSet jwtClaimsSet = request.toJWTClaimsSet();
		Map<String, List<String>> params = request.toParameters();
		for (Map.Entry<String,Object> en: jwtClaimsSet.getClaims().entrySet()) {
			assertEquals(Collections.singletonList((String)en.getValue()), params.get(en.getKey()));
		}
		assertEquals(params.size(), jwtClaimsSet.getClaims().size());
	}
	

	public void testBuilders() {
		
		// Regular
		CIBARequest request = new CIBARequest.Builder(CLIENT_AUTH, SCOPE)
			.endpointURI(ENDPOINT_URI)
			.clientNotificationToken(CLIENT_NOTIFICATION_TOKEN)
			.acrValues(ACR_VALUES)
			.loginHintTokenString(LOGIN_HINT_TOKEN_STRING)
			.idTokenHint(ID_TOKEN)
			.loginHint(LOGIN_HINT)
			.bindingMessage(BINDING_MESSAGE)
			.userCode(USER_CODE)
			.requestedExpiry(REQUESTED_EXPIRY)
			.customParameter("custom-xyz", "abc")
			.build();
		
		assertEquals(ENDPOINT_URI, request.getEndpointURI());
		assertEquals(CLIENT_AUTH, request.getClientAuthentication());
		assertEquals(SCOPE, request.getScope());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
		assertEquals(ACR_VALUES, request.getACRValues());
		assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
		assertEquals(ID_TOKEN, request.getIDTokenHint());
		assertEquals(LOGIN_HINT, request.getLoginHint());
		assertEquals(BINDING_MESSAGE, request.getBindingMessage());
		assertEquals(USER_CODE, request.getUserCode());
		assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
		assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
		
		// Copy
		request = new CIBARequest.Builder(request)
			.build();
		
		assertEquals(ENDPOINT_URI, request.getEndpointURI());
		assertEquals(CLIENT_AUTH, request.getClientAuthentication());
		assertEquals(SCOPE, request.getScope());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
		assertEquals(ACR_VALUES, request.getACRValues());
		assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
		assertEquals(ID_TOKEN, request.getIDTokenHint());
		assertEquals(LOGIN_HINT, request.getLoginHint());
		assertEquals(BINDING_MESSAGE, request.getBindingMessage());
		assertEquals(USER_CODE, request.getUserCode());
		assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
		assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
	}
	
	
	public void testConstructor_rejectNullScope() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				null, // scope
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The scope must not be null or empty", exception.getMessage());
	}
	
	
	public void testConstructor_rejectEmptyScope() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				new Scope(), // empty scope
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The scope must not be null or empty", exception.getMessage());
	}
	
	
	public void testConstructor_rejectExcessiveClientNotificationToken() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				generateExcessiveClientNotificationToken(),
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The client notification token must not exceed 1024 chars", exception.getMessage());
	}
	
	
	public void testConstructor_rejectZeroExpiry() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				0,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The requested expiry must be a positive integer", exception.getMessage());
	}
	
	
	public void testConstructor_rejectNegativeExpiry() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				0,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The requested expiry must be a positive integer", exception.getMessage());
	}
	
	
	public void testParse_expectPOST() {
		
		try {
			CIBARequest.parse(new HTTPRequest(HTTPRequest.Method.PUT, ENDPOINT_URL));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_expectContentTypeURLEncoded() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
		
		httpRequest.setEntityContentType(ContentType.TEXT_PLAIN);
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/x-www-form-urlencoded, received text/plain", e.getMessage());
		}
	}
	
	
	public void testParse_expectScopeParameter() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_notification_token=Yuo1chie");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The scope must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testParse_idTokenHintNotJWT() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("scope=openid&id_token_hint=cheTh0ae");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid \"id_token_hint\" parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getMessage());
		}
	}
	
	
	public void testParse_rejectExpiryString() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("scope=openid&requested_expiry=abc");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The \"requested_expiry\" parameter must be an integer", e.getMessage());
		}
	}
	
	
	public void testParse_rejectNegativeExpiry() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("scope=openid&requested_expiry=-1");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The requested expiry must be a positive integer", e.getMessage());
		}
	}
	
	
	public void testParse_rejectZeroExpiry() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("scope=openid&requested_expiry=-1");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The requested expiry must be a positive integer", e.getMessage());
		}
	}
	
	
	public void testParse_rejectExcessiveClientNotificationToken() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("scope=openid&client_notification_token=" + generateExcessiveClientNotificationToken().getValue());
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The client notification token must not exceed 1024 chars", e.getMessage());
		}
	}
	
	
	public void testParse_rejectIfAuthMissing() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("scope=openid");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required client authentication", e.getMessage());
		}
	}
}
