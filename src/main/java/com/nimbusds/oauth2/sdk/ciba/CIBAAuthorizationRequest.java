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
import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/**
 * <p>
 * An authentication request that is requested directly from the Client to the
 * OpenID Provider without going through the user's browser. The Client MUST
 * send an authentication request to the OpenID Provider by building an "HTTP
 * POST" request that will take to the OpenID Provider all the information
 * needed to authenticate the user without asking them for their identifier.
 * <p>
 * 
 * <div> The following is a non-normative example of an authentication request
 * (with line wraps within values for display purposes only):
 * 
 * </div>
 * 
 * <pre>
 *      
   POST /bc-authorize HTTP/1.1
   Host: server.example.com
   Content-Type: application/x-www-form-urlencoded

   scope=openid%20email%20example-scope&
   client_notification_token=8d67dc78-7faa-4d41-aabd-67707b374255&
   binding_message=W4SCT&
   login_hint_token=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
   zdWJfaWQiOnsic3ViamVjdF90eXBlIjoicGhvbmUiLCJwaG9uZSI6IisxMzMwMjg
   xODAwNCJ9fQ.Kk8jcUbHjJAQkRSHyDuFQr3NMEOSJEZc85VfER74tX6J9CuUllr8
   9WKUHUR7MA0-mWlptMRRhdgW1ZDt7g1uwQ&
   client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
   client-assertion-type%3Ajwt-bearer&
   client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
   pc3MiOiJzNkJoZFJrcXQzIiwic3ViIjoiczZCaGRSa3F0MyIsImF1ZCI6Imh0dHB
   zOi8vc2VydmVyLmV4YW1wbGUuY29tIiwianRpIjoiYmRjLVhzX3NmLTNZTW80RlN
   6SUoyUSIsImlhdCI6MTUzNzgxOTQ4NiwiZXhwIjoxNTM3ODE5Nzc3fQ.Ybr8mg_3
   E2OptOSsA8rnelYO_y1L-yFaF_j1iemM3ntB61_GN3APe5cl_-5a6cvGlP154XAK
   7fL-GaZSdnd9kg
 * 
 * </pre>
 * 
 */
@Immutable
public class CIBAAuthorizationRequest extends AbstractOptionallyIdentifiedRequest {

	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	static {
		Set<String> p = new HashSet<>();

		p.add("scope");
		p.add("client_notification_token");
		p.add("acr_values");
		p.add("login_hint_token");
		p.add("id_token_hint");
		p.add("login_hint");
		p.add("binding_message");
		p.add("user_code");
		p.add("requested_expiry");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}

	/**
	 * The scope (required). The scope of the access request as described by Section
	 * 3.3 of [RFC6749]. OpenID Connect implements authentication as an extension to
	 * OAuth 2.0 by including the openid scope value in the authorization requests.
	 * Consistent with that, CIBA authentication requests MUST therefore contain the
	 * openid scope value.
	 */
	private final Scope scope;

	/**
	 * (required) - if the Client is registered to use Ping or Push modes. It is a
	 * bearer token provided by the Client that will be used by the OpenID Provider
	 * to authenticate the callback request to the Client
	 */
	private final String clientNotificationToken;

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

		private ClientID clientId;

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
		public Builder(final CIBAAuthorizationRequest request, String clientNotificationToken) {
			scope = request.scope;
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
		public Builder clientNotificationToken(String token) {
			this.clientNotificationToken = token;
			return this;
		}

		/**
		 * Builds a new Client Initiated Backchannel Authorization request.
		 *
		 * @return The Client Initiated Backchannel Authorization request.
		 */
		public CIBAAuthorizationRequest build() {

			try {
				return new CIBAAuthorizationRequest(uri, clientId, scope, clientNotificationToken, acrValues, loginHintToken,
						idTokenHint, loginHint, bindingMessage, userCode, requestedЕxpiry);
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

		public Builder setUri(final URI uri) {
			this.uri = uri;
			return this;
		}

		public Builder setClientId(final ClientID clientId) {
			this.clientId = clientId;
			return this;
		}

	}

	/**
	 * Creates a new Client Initiated Backchannel Authorization request.
	 *
	 * @param uri      The URI of the Client Initiated Backchannel Authorization
	 *                 endpoint. May be {@code null} if the {@link #toHTTPRequest}
	 *                 method will not be used.
	 * @param clientID The client identifier. Corresponds to the {@code client_id}
	 *                 parameter. Must not be {@code null}.
	 * @param scope    The request scope. Corresponds to the optional {@code scope}
	 *                 parameter. {@code null} if not specified.
	 */
	public CIBAAuthorizationRequest(final URI uri, final Scope scope, final String clientNotificationToken) {

		super(uri, (ClientAuthentication) null);
		this.clientNotificationToken = clientNotificationToken;
		this.scope = scope;
	}

	public CIBAAuthorizationRequest(final URI uri, final ClientID clientId, final Scope scope, final String clientNotificationToken, final List<ACR> acrValues,
			final String loginHintToken, final String idTokenHint, final String loginHint, final String bindingMessage, final String userCode,
			final Integer requestedЕxpiry) {
		super(uri, clientId);
		this.scope = scope;
		this.clientNotificationToken = clientNotificationToken;
		this.acrValues = acrValues;
		this.loginHintToken = loginHintToken;
		this.idTokenHint = idTokenHint;
		this.loginHint = loginHint;
		this.bindingMessage = bindingMessage;
		this.userCode = userCode;

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (clientNotificationToken == null)
			throw new IllegalArgumentException("The client notification token must not be null");
		
		if (requestedЕxpiry != null) {
			if (requestedЕxpiry.intValue() < 0) {
				String msg = "The \"requested_expiry\" parameter must be positive integer";
				throw new IllegalArgumentException(msg);
			}
		}

		this.requestedЕxpiry = requestedЕxpiry;
	}

	/**
	 * Creates a new authenticated Client Initiated Backchannel Authorization
	 * request.
	 */

	public CIBAAuthorizationRequest(final Scope scope, final String clientNotificationToken) {
		super(null, (ClientID) null);

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (clientNotificationToken == null)
			throw new IllegalArgumentException("The client notification token must not be null");

		this.scope = scope;
		this.clientNotificationToken = clientNotificationToken;
	}

	/**
	 * Returns the registered (standard) OAuth 2.0 Connect Client Initiated
	 * Backchannel Authorization request parameter names.
	 *
	 * @return The registered OAuth 2.0 Connect Client Initiated Backchannel
	 *         Authorization request parameter names, as a unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}

	/**
	 * Gets the scope. Corresponds to the optional {@code scope} parameter.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}

	/**
	 * Returns the matching HTTP request.
	 *
	 * @return The HTTP request.
	 */
	@Override
	public HTTPRequest toHTTPRequest() {

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

		if (getClientAuthentication() != null) {
			getClientAuthentication().applyTo(httpRequest);
		}

		Map<String, List<String>> params = httpRequest.getQueryParameters();

		if (scope != null && !scope.isEmpty()) {
			params.put("scope", Collections.singletonList(scope.toString()));
		}

		if (getClientNotificationToken() != null) {
			params.put("client_notification_token", Collections.singletonList(getClientNotificationToken()));
			
//			String requestedЕxpiry = MultivaluedMapUtils.getFirstValue(params, "requested_expiry");

		}
		if (getAcrValues() != null) {
			params.put("acr_values", Identifier.toStringList(acrValues));
		}
		if (getIdTokenHint() != null) {
			params.put("id_token_hint", Collections.singletonList(getIdTokenHint()));
		}
		if (getLoginHint() != null) {
			params.put("login_hint", Collections.singletonList(getLoginHint()));
		}
		if (getLoginHintToken() != null) {
			params.put("login_hint_token", Collections.singletonList(getLoginHintToken()));
		}
		if (getUserCode() != null) {
			params.put("user_code", Collections.singletonList(getUserCode()));
		}
		if (getBindingMessage() != null) {
			params.put("binding_message", Collections.singletonList(getBindingMessage()));
		}
		if (getRequestedЕxpiry() != null) {
			params.put("requested_expiry", Collections.singletonList(getRequestedЕxpiry().toString()));
		}
		if (getClientID() != null) {
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
		}
		httpRequest.setQuery(URLUtils.serializeParameters(params));
		return httpRequest;
	}

	/**
	 * Parses an Client Initiated Backchannel Authorization request from the
	 * specified HTTP request.
	 *
	 * <p>
	 * Example HTTP request:
	 *
	 * <pre>
	 * POST /ciba HTTP/1.1
	 * Host: server.example.com
	 * Content-Type: application/x-www-form-urlencoded
	 *
	 * client_id=459691054427
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The Client Initiated Backchannel Authorization request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an Client
	 *                        Initiated Backchannel Authorization request.
	 */
	public static CIBAAuthorizationRequest parse(final HTTPRequest httpRequest) throws ParseException {

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
		Map<String, List<String>> params = httpRequest.getQueryParameters();

		String v;

		// Parse mandatory client ID for unauthenticated requests
		v = MultivaluedMapUtils.getFirstValue(params, "client_id");
		ClientID clientId;

		if (StringUtils.isBlank(v)) {
			String msg = "Missing \"client_id\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		} else {
			clientId = new ClientID(v);
		}

		// Parse optional scope
		v = MultivaluedMapUtils.getFirstValue(params, "scope");

		Scope scope = null;

		if (StringUtils.isNotBlank(v))
			scope = Scope.parse(v);

		String clientNotificationToken = MultivaluedMapUtils.getFirstValue(params, "client_notification_token");
		List<ACR> acrValues = null;
		if (params.get("acr_values") != null) {

			acrValues = new ArrayList<>();
			List<String> list = params.get("acr_values");
			for (String v1: list) {
				if (v1 != null)
					acrValues.add(new ACR(v1));
			}
		}
		
		String loginHintToken = MultivaluedMapUtils.getFirstValue(params, "login_hint_token");
		String idTokenHint = MultivaluedMapUtils.getFirstValue(params, "id_token_hint");
		String loginHint = MultivaluedMapUtils.getFirstValue(params, "login_hint");
		String userCode = MultivaluedMapUtils.getFirstValue(params, "user_code");
		String bindingMessage = MultivaluedMapUtils.getFirstValue(params, "binding_message");
		String requestedЕxpiry = MultivaluedMapUtils.getFirstValue(params, "requested_expiry");
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

		return new CIBAAuthorizationRequest(uri, clientId, scope, clientNotificationToken, acrValues, loginHintToken, idTokenHint,
				loginHint, bindingMessage, userCode, requestedЕxpiryInteger);

	}

	/**
	 * Returns the client notification token
	 * 
	 * @return the client notification token
	 */
	public String getClientNotificationToken() {
		return clientNotificationToken;
	}

	/**
	 * Returns the authentication context class reference values in a
	 * space-separated string
	 * 
	 * @return the authentication context class reference values in a
	 *         space-separated string
	 */
	public List<ACR> getAcrValues() {
		return acrValues;
	}

	/**
	 * Sets the authentication context class reference values
	 * 
	 * @param the authentication context class reference values
	 */
	public void setAcrValues(final List<ACR> acrValues) {
		this.acrValues = acrValues;
	}

	/**
	 * Get the login hint token
	 * 
	 * @return the login hint token
	 */
	public String getLoginHintToken() {
		return loginHintToken;
	}

	/**
	 * Set the login hint token
	 * 
	 * @param the login hint token
	 */
	public void setLoginHintToken(final String loginHintToken) {
		this.loginHintToken = loginHintToken;
	}

	/**
	 * Get the id token hint
	 * 
	 * @return the id token hint
	 */

	public String getIdTokenHint() {
		return idTokenHint;
	}

	/**
	 * Sets the id token hint
	 * 
	 * @param the id token hint
	 */
	public void setIdTokenHint(final String idTokenHint) {
		this.idTokenHint = idTokenHint;
	}

	/**
	 * Get the login hint
	 * 
	 * @return the login hint
	 */
	public String getLoginHint() {
		return loginHint;
	}

	/**
	 * Set the login hint
	 * 
	 * @param the login hint
	 */
	public void setLoginHint(final String loginHint) {
		this.loginHint = loginHint;
	}

	/**
	 * Get the binding message
	 * 
	 * @return the binding message
	 */
	public String getBindingMessage() {
		return bindingMessage;
	}

	/**
	 * Sets the binding message
	 * 
	 * @param the binding message
	 */
	public void setBindingMessage(final String bindingMessage) {
		this.bindingMessage = bindingMessage;
	}

	/**
	 * Gets the user code
	 * 
	 * @return the user code
	 */
	public String getUserCode() {
		return userCode;
	}

	/**
	 * Sets the user code
	 * 
	 * @param the user code
	 */
	public void setUserCode(final String userCode) {
		this.userCode = userCode;
	}

	/**
	 * Gets the requested expire
	 * 
	 * @return
	 */
	public Integer getRequestedЕxpiry() {
		return requestedЕxpiry;
	}

	/**
	 * Sets the requested expire
	 * 
	 * @param the requested expire
	 */
	public void setRequestedЕxpiry(final Integer requestedЕxpiry) {
		this.requestedЕxpiry = requestedЕxpiry;
	}
}
