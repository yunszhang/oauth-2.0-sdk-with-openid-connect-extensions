/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.nimbusds.oauth2.sdk.ciba;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/**
 * 
 * <div> Example, a signed authentication request using the same authentication
 * request parameters and values as the example from the previous section would
 * look like the following (with line wraps within values for display purposes
 * only): </div>
 * 
 * POST /bc-authorize HTTP/1.1 Host: server.example.com Content-Type:
 * application/x-www-form-urlencoded
 * 
 * <pre>
 * request=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJz
 * NkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJl
 * eHAiOjE1Mzc4MjAwODYsImlhdCI6MTUzNzgxOTQ4NiwibmJmIjoxNTM3ODE4ODg2
 * LCJqdGkiOiI0TFRDcUFDQzJFU0M1QldDbk4zajU4RW5BIiwic2NvcGUiOiJvcGVu
 * aWQgZW1haWwgZXhhbXBsZS1zY29wZSIsImNsaWVudF9ub3RpZmljYXRpb25fdG9r
 * ZW4iOiI4ZDY3ZGM3OC03ZmFhLTRkNDEtYWFiZC02NzcwN2IzNzQyNTUiLCJiaW5k
 * aW5nX21lc3NhZ2UiOiJXNFNDVCIsImxvZ2luX2hpbnRfdG9rZW4iOiJleUpyYVdR
 * aU9pSnNkR0ZqWlhOaWR5SXNJbUZzWnlJNklrVlRNalUySW4wLmV5SnpkV0pmYVdR
 * aU9uc2ljM1ZpYW1WamRGOTBlWEJsSWpvaWNHaHZibVVpTENKd2FHOXVaU0k2SWlz
 * eE16TXdNamd4T0RBd05DSjlmUS5LazhqY1ViSGpKQVFrUlNIeUR1RlFyM05NRU9T
 * SkVaYzg1VmZFUjc0dFg2SjlDdVVsbHI4OVdLVUhVUjdNQTAtbVdscHRNUlJoZGdX
 * MVpEdDdnMXV3USJ9.RB-iFvzpkQ_gUzg0eutoviViCKyLugjVYfVqdjDZ63U1MZR
 * Z-KcUNSsBjCVptc-QdljCSNCUyULIzT2R5Nmg4Q&
 * client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
 * client-assertion-type%3Ajwt-bearer&
 * client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
 * pc3MiOiJzNkJoZFJrcXQzIiwic3ViIjoiczZCaGRSa3F0MyIsImF1ZCI6Imh0dHB
 * zOi8vc2VydmVyLmV4YW1wbGUuY29tIiwianRpIjoiY2NfMVhzc3NmLTJpOG8yZ1B
 * 6SUprMSIsImlhdCI6MTUzNzgxOTQ4NiwiZXhwIjoxNTM3ODE5Nzc3fQ.PWb_VMzU
 * IbD_aaO5xYpygnAlhRIjzoc6kxg4NixDuD1DVpkKVSBbBweqgbDLV-awkDtuWnyF
 * yUpHqg83AUV5TA
 * </pre>
 * 
 * Where the following is the JWT payload (with line wraps and added whitespace
 * for display purposes only):
 * 
 * 
 * <pre>
 * {
  "iss": "s6BhdRkqt3",
  "aud": "https://server.example.com",
  "exp": 1537820086,
  "iat": 1537819486,
  "nbf": 1537818886,
  "jti": "4LTCqACC2ESC5BWCnN3j58EnA",
  "scope": "openid email example-scope",
  "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
  "binding_message": "W4SCT",
  "login_hint_token": "eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2I
    n0.eyJzdWJfaWQiOnsic3ViamVjdF90eXBlIjoicGhvbmUiLCJwaG9uZSI6I
    isxMzMwMjgxODAwNCJ9fQ.Kk8jcUbHjJAQkRSHyDuFQr3NMEOSJEZc85VfER
    74tX6J9CuUllr89WKUHUR7MA0-mWlptMRRhdgW1ZDt7g1uwQ"
 }
 * </pre>
 */
public class CIBASignedAuthenticationRequest extends CIBAAuthorizationRequest {

	/**
	 * The Audience claim MUST contain the value of the Issuer Identifier for the
	 * OP, which identifies the Authorization Server as an intended audience.
	 */
	private final Audience aud;

	/**
	 * The Issuer claim MUST be the client_id of the OAuth Client.
	 */
	private final Issuer iss;

	/**
	 * An expiration time that limits the validity lifetime of the signed
	 * authentication request.
	 */
	private final Date exp;

	/**
	 * The time at which the signed authentication request was created.
	 */
	private final Date iat;

	/**
	 * The time before which the signed authentication request is unacceptable.
	 */
	private final Date nbf;

	/**
	 * A unique identifier for the signed authentication request.
	 */
	private final JWTID jti;

	/**
	 * 
	 * @param scope
	 * @param clientNotificationToken
	 */
	public CIBASignedAuthenticationRequest(final URI uri, final Scope scope, final String clientNotificationToken,
			final Audience aud, final Issuer iss, final Date exp, final Date iat, final Date nbf,
			final JWTID jti) {
		super(uri, scope, clientNotificationToken);
		
		this.aud = aud;
		this.iss = iss;
		this.exp = exp;
		this.iat = iat;
		this.nbf = nbf;
		this.jti = jti;
	}

	@Override
	public HTTPRequest toHTTPRequest() {
		com.nimbusds.jwt.JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		if (getScope() != null && !getScope().isEmpty()) {
			builder.claim("scope", getScope().toString());
		}

		if (getClientNotificationToken() != null) {
			builder.claim("client_notification_token", getClientNotificationToken());

		}
		if (getAcrValues() != null) {
			builder.claim("acr_values", Identifier.toStringList(getAcrValues()));
		}
		if (getIdTokenHint() != null) {
			builder.claim("id_token_hint", getIdTokenHint());
		}
		if (getLoginHint() != null) {
			builder.claim("login_hint", getLoginHint());
		}
		if (getLoginHintToken() != null) {
			builder.claim("login_hint_token", getLoginHintToken());
		}
		if (getUserCode() != null) {
			builder.claim("user_code", getUserCode());
		}
		if (getBindingMessage() != null) {
			builder.claim("binding_message", getBindingMessage());
		}
		if (getRequestedЕxpiry() != null) {
			builder.claim("requested_expiry", getRequestedЕxpiry().toString());
		}
		if (getClientID() != null) {
			builder.claim("client_id", getClientID().getValue());
		}

		if (aud != null) {
			builder.claim("aud", aud.toString());
		}
		if (iss != null) {
			builder.claim("iss", iss.toString());
		}
		builder.expirationTime(exp);
		builder.issueTime(iat);
		builder.notBeforeTime(nbf);
		if (jti != null) {
			builder.claim("jti", jti.toString());
		}

		JWTClaimsSet jwtClaimsSet = builder.build();

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		URL endpointURL;

		try {
			endpointURL = getEndpointURI().toURL();

		} catch (MalformedURLException e) {

			throw new SerializeException(e.getMessage(), e);
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String, List<String>> params = new HashMap<String, List<String>>();
		params.put("request", Arrays.asList(jwtClaimsSet.toString()));
		httpRequest.setQuery(URLUtils.serializeParameters(params));
		return httpRequest;
	}

	/**
	 * 
	 * @param httpRequest
	 * @return
	 * @throws ParseException
	 */
	public static CIBASignedAuthenticationRequest parse(final HTTPRequest httpRequest) throws ParseException {

		// Only HTTP POST accepted
		URI uri;

		try {
			uri = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}

		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);

		// No fragment! May use query component!
		List<String> list = httpRequest.getQueryParameters().get("request");
		if (list == null || list.isEmpty()) {
			String msg = "Missing \"request\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}
		JWTClaimsSet jwtClaimsSet;
		try {
			jwtClaimsSet = JWTClaimsSet.parse(list.get(0));
		} catch (java.text.ParseException e1) {
			throw new ParseException(e1.getMessage(),
					OAuth2Error.INVALID_REQUEST.appendDescription(": " + e1.getMessage()));
		}

		try {
			String v;

			// Parse mandatory client ID for unauthenticated requests
			v = jwtClaimsSet.getStringClaim("client_id");
			ClientID clientId;

			if (StringUtils.isBlank(v)) {
				String msg = "Missing \"client_id\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			} else {
				clientId = new ClientID(v);
			}

			// Parse optional scope
			v = jwtClaimsSet.getStringClaim("scope");

			Scope scope = null;

			if (StringUtils.isNotBlank(v))
				scope = Scope.parse(v);

			String clientNotificationToken = jwtClaimsSet.getStringClaim("client_notification_token");
			List<ACR> acrValues = null;
			if (jwtClaimsSet.getStringListClaim("acr_values") != null
					&& jwtClaimsSet.getStringListClaim("acr_values") instanceof List) {

				acrValues = new ArrayList<>();
				List<String> listArcValues = jwtClaimsSet.getStringListClaim("acr_values");
				for (String v1 : listArcValues) {
					if (v1 != null)
						acrValues.add(new ACR(v1));
				}
			}

			String loginHintToken = jwtClaimsSet.getStringClaim("login_hint_token");
			String idTokenHint = jwtClaimsSet.getStringClaim("id_token_hint");
			String loginHint = jwtClaimsSet.getStringClaim("login_hint");
			String userCode = jwtClaimsSet.getStringClaim("user_code");
			String bindingMessage = jwtClaimsSet.getStringClaim("binding_message");
			String requestedЕxpiry = jwtClaimsSet.getStringClaim("requested_expiry");
			Integer requestedЕxpiryInteger = null;

			if (requestedЕxpiry != null) {

				try {
					requestedЕxpiryInteger = Integer.valueOf(requestedЕxpiry);
					if (requestedЕxpiryInteger.intValue() < 0) {
						String msg = "The \"requested_expiry\" parameter must be positive integer";
						throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
					}
				} catch (NumberFormatException e) {
					String msg = "The \"requested_expiry\" parameter must be an integer";
					throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
				}
			}

			List<String> audiences = jwtClaimsSet.getAudience();
			if (audiences == null || audiences.isEmpty()) {
				String msg = "Missing \"aud\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
			List<Audience> audiencesList = Audience.create(audiences);
			
			v = jwtClaimsSet.getStringClaim("iss");
			if (StringUtils.isBlank(v)) {
				String msg = "Missing \"iss\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
			Issuer iss = new Issuer(jwtClaimsSet.getStringClaim("iss"));

			Date expirationTime = jwtClaimsSet.getExpirationTime();
			if (expirationTime == null) {
				String msg = "Missing \"exp\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}

			Date issueTime = jwtClaimsSet.getIssueTime();
			if (issueTime == null) {
				String msg = "Missing \"iat\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}

			Date beforeTime = jwtClaimsSet.getNotBeforeTime();
			if (beforeTime == null) {
				String msg = "Missing \"nbf\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}

			v = jwtClaimsSet.getStringClaim("jti");
			if (StringUtils.isBlank(v)) {
				String msg = "Missing \"jti\" parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
			JWTID jti = new JWTID(jwtClaimsSet.getStringClaim("jti"));

			return new CIBASignedAuthenticationRequest(uri, clientId, scope, clientNotificationToken, acrValues,
					loginHintToken, idTokenHint, loginHint, bindingMessage, userCode, requestedЕxpiryInteger, audiencesList.get(0), iss,
					expirationTime, issueTime, beforeTime, jti);
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}

	/**
	 * Tries to extract value from a JWT claims map with the value being a list
	 * 
	 * @param claims
	 * @param key    - the key
	 * @return the value if present or null //
	 */
//	private static String getFirstValueFromClaim(Map<String, Object> claims, String key) {
//		Object object = claims.get(key);
//
//		if (object != null && object instanceof String) {
//			return (String) object;
//		}
//		if (object != null && object instanceof List) {
//			List<Object> valueList = (List<Object>) object;
//			if (valueList.size() > 0 && valueList.get(0) != null) {
//				return valueList.get(0).toString();
//			}
//		}
//		return null;
//	}

	/**
	 * 
	 * @param uri
	 * @param clientId
	 * @param scope
	 * @param clientNotificationToken
	 * @param acrValues
	 * @param loginHintToken
	 * @param idTokenHint
	 * @param loginHint
	 * @param bindingMessage
	 * @param userCode
	 * @param requestedЕxpiry
	 * @param aud
	 * @param iss
	 * @param exp
	 * @param iat
	 * @param nbf
	 * @param jti
	 */
	public CIBASignedAuthenticationRequest(final URI uri, final ClientID clientId, final Scope scope,
			final String clientNotificationToken, final List<ACR> acrValues, final String loginHintToken,
			final String idTokenHint, final String loginHint, final String bindingMessage, final String userCode,
			final Integer requestedЕxpiry, final Audience aud, final Issuer iss, final Date exp, final Date iat,
			final Date nbf, final JWTID jti) {
		super(uri, clientId, scope, clientNotificationToken, acrValues, loginHintToken, idTokenHint, loginHint,
				bindingMessage, userCode, requestedЕxpiry);
		this.aud = aud;
		this.iss = iss;
		this.exp = exp;
		this.iat = iat;
		this.nbf = nbf;
		this.jti = jti;
	}

	/**
	 * Builder for constructing authorisation requests.
	 */
	public static class Builder {

		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;

		/**
		 * The scope (required). The scope of the access request as described by Section
		 * 3.3 of [RFC6749]. OpenID Connect implements authentication as an extension to
		 * OAuth 2.0 by including the openid scope value in the authorization requests.
		 * Consistent with that, CIBA authentication requests MUST therefore contain the
		 * openid scope value.
		 */
		private Scope scope;

		/**
		 * (required) - if the Client is registered to use Ping or Push modes. It is a
		 * bearer token provided by the Client that will be used by the OpenID Provider
		 * to authenticate the callback request to the Client
		 */
		private String clientNotificationToken;

		/**
		 * (optional) Space-separated string that specifies the acr values that the
		 * OpenID Provider is being requested to use for processing this Authentication
		 * Request, with the values appearing in order of preference. The actual means
		 * of authenticating the end-user, however, are ultimately at the discretion of
		 * the OP and the Authentication Context Class satisfied by the authentication
		 * performed is returned as the acr Claim Value of the ID Token
		 */
		private List<ACR> acrValues;
		/**
		 * (optional). A token containing information identifying the end-user for whom
		 * authentication is being requested. The particular details and security
		 * requirements for the login_hint_token as well as how the end-user is
		 * identified by its content are deployment or profile specific.
		 */
		private String loginHintToken;
		/**
		 * (optional). An ID Token previously issued to the Client by the OpenID
		 * Provider being passed back as a hint to identify the end-user for whom
		 * authentication is being requested. If the ID Token received by the Client
		 * from the OP was asymmetrically encrypted, to use it as an id_token_hint, the
		 * client MUST decrypt the encrypted ID Token to extract the signed ID Token
		 * contained in it.
		 */
		private String idTokenHint;
		/**
		 * (optional). A hint to the OpenID Provider regarding the end-user for whom
		 * authentication is being requested. The value may contain an email address,
		 * phone number, account number, subject identifier, username, etc., which
		 * identifies the end-user to the OP. The value may be directly collected from
		 * the user by the Client before requesting authentication at the OP, for
		 * example, but may also be obtained by other means.
		 */
		private String loginHint;
		/**
		 * (optional). A human readable identifier or message intended to be displayed
		 * on both the consumption device and the authentication device to interlock
		 * them together for the transaction by way of a visual cue for the end-user.
		 * This interlocking message enables the end-user to ensure that the action
		 * taken on the authentication device is related to the request initiated by the
		 * consumption device. The value SHOULD contain something that enables the
		 * end-user to reliably discern that the transaction is related across the
		 * consumption device and the authentication device, such as a random value of
		 * reasonable entropy (e.g. a transactional approval code). Because the various
		 * devices involved may have limited display abilities and the message is
		 * intending for visual inspection by the end-user, the binding_message value
		 * SHOULD be relatively short and use a limited set of plain text characters.
		 * The invalid_binding_message defined in Section 13 is used in the case that it
		 * is necessary to inform the Client that the provided binding_message is
		 * unacceptable.
		 */
		private String bindingMessage;
		/**
		 * (optional). A secret code, such as password or pin, known only to the user
		 * but verifiable by the OP. The code is used to authorize sending an
		 * authentication request to user's authentication device. This parameter should
		 * only be present if client registration parameter
		 * backchannel_user_code_parameter indicates support for user code.
		 */
		private String userCode;
		/**
		 * (optional). A positive integer allowing the client to request the expires_in
		 * value for the auth_req_id the server will return. The server MAY use this
		 * value to influence the lifetime of the authentication request and is
		 * encouraged to do so where it will improve the user experience, for example by
		 * terminating the authentication when as it knows the client is no longer
		 * interested in the result.
		 */
		private Integer requestedЕxpiry;

		/**
		 */
		private ClientID clientId;

		/**
		 * The Audience claim MUST contain the value of the Issuer Identifier for the
		 * OP, which identifies the Authorization Server as an intended audience.
		 */
		private Audience aud;

		/**
		 * The Issuer claim MUST be the client_id of the OAuth Client.
		 */
		private Issuer iss;

		/**
		 * An expiration time that limits the validity lifetime of the signed
		 * authentication request.
		 */
		private Date exp;

		/**
		 * The time at which the signed authentication request was created.
		 */
		private Date iat;

		/**
		 * The time before which the signed authentication request is unacceptable.
		 */
		private Date nbf;

		/**
		 * A unique identifier for the signed authentication request.
		 */
		private JWTID jti;

		/**
		 * Creates a new Client Initiated Backchannel Authorization request builder for
		 * an authenticated request.
		 *
		 * @param clientAuth The client authentication. Must not be {@code null}.
		 */
		public Builder() {
		}

		/**
		 * Creates a new Client Initiated Backchannel Authorization request builder from
		 * the specified request.
		 *
		 * @param request The Client Initiated Backchannel Authorization request. Must
		 *                not be {@code null}.
		 */
		public Builder(final CIBASignedAuthenticationRequest request, final String clientNotificationToken) {
			scope = request.getScope();
		}

		/**
		 * Sets the scope. Corresponds to the required {@code scope} parameter.
		 *
		 * @param scope The scope
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {

			this.scope = scope;
			return this;
		}

		/**
		 * 
		 * Sets the the client notification token and returns the builder for further
		 * building
		 * 
		 * @param the client notification token
		 * @return This builder.
		 */
		public Builder clientNotificationToken(final String token) {
			this.clientNotificationToken = token;
			return this;
		}

		/**
		 * Builds a new Client Initiated Backchannel Authorization request.
		 *
		 * @return The Client Initiated Backchannel Authorization request.
		 */
		public CIBASignedAuthenticationRequest build() {

			try {
				return new CIBASignedAuthenticationRequest(uri, clientId, scope, clientNotificationToken, acrValues,
						loginHintToken, idTokenHint, loginHint, bindingMessage, userCode, requestedЕxpiry, aud, iss,
						exp, iat, nbf, jti);
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException(e.getMessage(), e);
			}
		}

		/**
		 * Sets the scope into the Builder object and returns the Builder for further
		 * request construction
		 * 
		 * @param scope - the scope
		 * @return the builder
		 */
		public Builder setScope(final Scope scope) {
			this.scope = scope;
			return this;
		}

		/**
		 * Sets the client notification token into the Builder object and returns the
		 * Builder for further request construction
		 * 
		 * @return the builder
		 * @param clientNotificationToken - the client notification token
		 */
		public Builder setClientNotificationToken(final String clientNotificationToken) {
			this.clientNotificationToken = clientNotificationToken;
			return this;
		}

		/**
		 * Sets the arc values into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param acrValues - the arc values
		 * @return the builder
		 */
		public Builder setAcrValues(final List<ACR> acrValues) {
			this.acrValues = acrValues;
			return this;
		}

		/**
		 * Sets the login hint token into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param loginHintToken - the login hint token
		 * @return the builder
		 */
		public Builder setLoginHintToken(final String loginHintToken) {
			this.loginHintToken = loginHintToken;
			return this;
		}

		/**
		 * Sets the id token hint into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param idTokenHint - the id token hint
		 * @return the builder
		 */
		public Builder setIdTokenHint(final String idTokenHint) {
			this.idTokenHint = idTokenHint;
			return this;
		}

		/**
		 * Sets the login hint into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param loginHint - the login hint
		 * @return the builder
		 */
		public Builder setLoginHint(final String loginHint) {
			this.loginHint = loginHint;
			return this;
		}

		/**
		 * Sets the biding message into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param bindingMessage - the binding message
		 * @return the builder
		 */
		public Builder setBindingMessage(final String bindingMessage) {
			this.bindingMessage = bindingMessage;
			return this;
		}

		/**
		 * Sets the user code into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param userCode - the user Code
		 * @return the builder
		 */
		public Builder setUserCode(final String userCode) {
			this.userCode = userCode;
			return this;
		}

		/**
		 * Sets the requested expiry into the Builder object and returns the Builder for
		 * further request construction
		 * 
		 * @param requestedЕxpiry - the requested expiry
		 * @return the builder
		 */
		public Builder setRequestedЕxpiry(final Integer requestedЕxpiry) {
			this.requestedЕxpiry = requestedЕxpiry;
			return this;
		}

		/**
		 * Sets the uri
		 * 
		 * @param the uri
		 * @return the builder
		 */
		public Builder setUri(final URI uri) {
			this.uri = uri;
			return this;
		}

		/**
		 * Sets the client ID
		 * 
		 * @param the clientId
		 * @return the builder
		 * 
		 * @param clientId - the client ID
		 * @return the builder
		 */
		public Builder setClientId(final ClientID clientId) {
			this.clientId = clientId;
			return this;
		}

		/**
		 * Sets the audience
		 * 
		 * @param aud - the audience
		 * @return the builder
		 */
		public Builder setAud(final Audience aud) {
			this.aud = aud;
			return this;
		}

		/**
		 * Sets the iss - that is the client_id of the OAuth Client.
		 * 
		 * @param iss - the client_id of the OAuth Client.
		 * @return the builder
		 */
		public Builder setIss(final Issuer iss) {
			this.iss = iss;
			return this;
		}

		/**
		 * Sets the expiration time of the signed authentication request.
		 * 
		 * @param exp - the expiration time
		 * @return the builder
		 */
		public Builder setExp(final Date exp) {
			this.exp = exp;
			return this;
		}

		/**
		 * Sets the time at which the signed authentication request was created.
		 * 
		 * @param iat - the time at which the signed authentication request was created.
		 * @return the builder
		 */
		public Builder setIat(final Date iat) {
			this.iat = iat;
			return this;
		}

		/**
		 * Sets the time before which the signed authentication request is unacceptable.
		 * 
		 * @param nbf - the time before which the signed authentication request is
		 *            unacceptable.
		 * @return the builder
		 */
		public Builder setNbf(final Date nbf) {
			this.nbf = nbf;
			return this;
		}

		/**
		 * A unique identifier for the signed authentication request.
		 * 
		 * @param jti - the identifier
		 * @return the builder
		 */
		public Builder setJti(final JWTID jti) {
			this.jti = jti;
			return this;
		}

	}

	/**
	 * Gets the request Audience
	 * 
	 * @return the Audience
	 */
	public Audience getAud() {
		return aud;
	}

	/**
	 * Gets the request Issuer
	 * 
	 * @return the issuer
	 */
	public Issuer getIss() {
		return iss;
	}

	/**
	 * Gets the expiration time
	 * 
	 * @return the expiration time
	 */
	public Date getExp() {
		return exp;
	}

	/**
	 * Gets the time at which the signed authentication request was created.
	 * 
	 * @return the creation time
	 */
	public Date getIat() {
		return iat;
	}

	/**
	 * Gets the time before which the signed authentication request is unacceptable.
	 * 
	 * @return the time before request becomes unacceptable
	 */
	public Date getNbf() {
		return nbf;
	}

	/**
	 * Gets the request identifier
	 * 
	 * @return the identifier
	 */
	public JWTID getJti() {
		return jti;
	}

}
