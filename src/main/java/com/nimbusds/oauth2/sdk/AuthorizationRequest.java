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

package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.*;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Prompt;


/**
 * Authorisation request. Used to authenticate an end-user and request the
 * end-user's consent to grant the client access to a protected resource.
 * Supports custom request parameters.
 *
 * <p>Extending classes may define additional request parameters as well as 
 * enforce tighter requirements on the base parameters.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * https://server.example.com/authorize?
 * response_type=code
 * &amp;client_id=s6BhdRkqt3
 * &amp;state=xyz
 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.1 and 4.2.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 *     <li>Resource Indicators for OAuth 2.0 (RFC 8707)
 *     <li>OAuth 2.0 Incremental Authorization
 *         (draft-ietf-oauth-incremental-authz-04)
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (RFC 9101)
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 * </ul>
 */
@Immutable
public class AuthorizationRequest extends AbstractRequest {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	static {
		Set<String> p = new HashSet<>();

		p.add("response_type");
		p.add("client_id");
		p.add("redirect_uri");
		p.add("scope");
		p.add("state");
		p.add("response_mode");
		p.add("code_challenge");
		p.add("code_challenge_method");
		p.add("resource");
		p.add("include_granted_scopes");
		p.add("request_uri");
		p.add("request");
		p.add("prompt");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * The response type (required unless in JAR).
	 */
	private final ResponseType rt;


	/**
	 * The client identifier (required).
	 */
	private final ClientID clientID;


	/**
	 * The redirection URI where the response will be sent (optional). 
	 */
	private final URI redirectURI;
	
	
	/**
	 * The scope (optional).
	 */
	private final Scope scope;
	
	
	/**
	 * The opaque value to maintain state between the request and the 
	 * callback (recommended).
	 */
	private final State state;


	/**
	 * The response mode (optional).
	 */
	private final ResponseMode rm;


	/**
	 * The authorisation code challenge for PKCE (optional).
	 */
	private final CodeChallenge codeChallenge;


	/**
	 * The authorisation code challenge method for PKCE (optional).
	 */
	private final CodeChallengeMethod codeChallengeMethod;
	
	
	/**
	 * The resource URI(s) (optional).
	 */
	private final List<URI> resources;
	
	
	/**
	 * Indicates incremental authorisation (optional).
	 */
	private final boolean includeGrantedScopes;
	
	
	/**
	 * Request object (optional).
	 */
	private final JWT requestObject;
	
	
	/**
	 * Request object URI (optional).
	 */
	private final URI requestURI;
	
	
	/**
	 * The requested prompt (optional).
	 */
	protected final Prompt prompt;


	/**
	 * Custom parameters.
	 */
	private final Map<String,List<String>> customParams;


	/**
	 * Builder for constructing authorisation requests.
	 */
	public static class Builder {


		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;


		/**
		 * The response type (required unless in JAR).
		 */
		private ResponseType rt;


		/**
		 * The client identifier (required).
		 */
		private final ClientID clientID;


		/**
		 * The redirection URI where the response will be sent
		 * (optional).
		 */
		private URI redirectURI;


		/**
		 * The scope (optional).
		 */
		private Scope scope;


		/**
		 * The opaque value to maintain state between the request and
		 * the callback (recommended).
		 */
		private State state;


		/**
		 * The response mode (optional).
		 */
		private ResponseMode rm;


		/**
		 * The authorisation code challenge for PKCE (optional).
		 */
		private CodeChallenge codeChallenge;


		/**
		 * The authorisation code challenge method for PKCE (optional).
		 */
		private CodeChallengeMethod codeChallengeMethod;
		
		
		/**
		 * Indicates incremental authorisation (optional).
		 */
		private boolean includeGrantedScopes;
		
		
		/**
		 * The resource URI(s) (optional).
		 */
		private List<URI> resources;
		
		
		/**
		 * Request object (optional).
		 */
		private JWT requestObject;
		
		
		/**
		 * Request object URI (optional).
		 */
		private URI requestURI;
		
		
		/**
		 * The requested prompt (optional).
		 */
		private Prompt prompt;


		/**
		 * Custom parameters.
		 */
		private final Map<String,List<String>> customParams = new HashMap<>();


		/**
		 * Creates a new authorisation request builder.
		 *
		 * @param rt       The response type. Corresponds to the
		 *                 {@code response_type} parameter. Must not be
		 *                 {@code null}.
		 * @param clientID The client identifier. Corresponds to the
		 *                 {@code client_id} parameter. Must not be
		 *                 {@code null}.
		 */
		public Builder(final ResponseType rt, final ClientID clientID) {

			if (rt == null)
				throw new IllegalArgumentException("The response type must not be null");

			this.rt = rt;


			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");

			this.clientID = clientID;
		}
		
		
		/**
		 * Creates a new JWT secured authorisation request (JAR)
		 * builder.
		 *
		 * @param requestObject The request object. Must not be
		 *                      {@code null}.'
		 * @param clientID      The client ID. Must not be
		 *                      {@code null}.
		 */
		public Builder(final JWT requestObject, final ClientID clientID) {
			
			if (requestObject == null)
				throw new IllegalArgumentException("The request object must not be null");
			
			this.requestObject = requestObject;
			
			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");
			
			this.clientID = clientID;
		}
		
		
		/**
		 * Creates a new JWT secured authorisation request (JAR)
		 * builder.
		 *
		 * @param requestURI The request object URI. Must not be
		 *                   {@code null}.
		 * @param clientID   The client ID. Must not be {@code null}.
		 */
		public Builder(final URI requestURI, final ClientID clientID) {
			
			if (requestURI == null)
				throw new IllegalArgumentException("The request URI must not be null");
			
			this.requestURI = requestURI;
			
			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");
			
			this.clientID = clientID;
		}
		
		
		/**
		 * Creates a new authorisation request builder from the
		 * specified request.
		 *
		 * @param request The authorisation request. Must not be
		 *                {@code null}.
		 */
		public Builder(final AuthorizationRequest request) {
			
			uri = request.getEndpointURI();
			scope = request.scope;
			rt = request.getResponseType();
			clientID = request.getClientID();
			redirectURI = request.getRedirectionURI();
			state = request.getState();
			rm = request.getResponseMode();
			codeChallenge = request.getCodeChallenge();
			codeChallengeMethod = request.getCodeChallengeMethod();
			resources = request.getResources();
			includeGrantedScopes = request.includeGrantedScopes();
			requestObject = request.requestObject;
			requestURI = request.requestURI;
			prompt = request.prompt;
			
			if (request instanceof AuthenticationRequest) {
				AuthenticationRequest oidcRequest = (AuthenticationRequest) request;
				for (Map.Entry<String,List<String>> oidcParam: oidcRequest.toParameters().entrySet()) {
					if (! REGISTERED_PARAMETER_NAMES.contains(oidcParam.getKey())) {
						customParams.put(oidcParam.getKey(), oidcParam.getValue());
					}
				}
			} else {
				customParams.putAll(request.getCustomParameters());
			}
		}
		
		
		/**
		 * Sets the response type. Corresponds to the
		 * {@code response_type} parameter.
		 *
		 * @param rt The response type. Must not be {@code null}.
		 *
		 * @return This builder.
		 */
		public Builder responseType(final ResponseType rt) {
			
			if (rt == null)
				throw new IllegalArgumentException("The response type must not be null");
			
			this.rt = rt;
			return this;
		}


		/**
		 * Sets the redirection URI. Corresponds to the optional
		 * {@code redirection_uri} parameter.
		 *
		 * @param redirectURI The redirection URI, {@code null} if not
		 *                    specified.
		 *
		 * @return This builder.
		 */
		public Builder redirectionURI(final URI redirectURI) {

			this.redirectURI = redirectURI;
			return this;
		}


		/**
		 * Sets the scope. Corresponds to the optional {@code scope}
		 * parameter.
		 *
		 * @param scope The scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {

			this.scope = scope;
			return this;
		}


		/**
		 * Sets the state. Corresponds to the recommended {@code state}
		 * parameter.
		 *
		 * @param state The state, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder state(final State state) {

			this.state = state;
			return this;
		}


		/**
		 * Sets the response mode. Corresponds to the optional
		 * {@code response_mode} parameter. Use of this parameter is
		 * not recommended unless a non-default response mode is
		 * requested (e.g. form_post).
		 *
		 * @param rm The response mode, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder responseMode(final ResponseMode rm) {

			this.rm = rm;
			return this;
		}


		/**
		 * Sets the code challenge for Proof Key for Code Exchange
		 * (PKCE) by public OAuth clients.
		 *
		 * @param codeChallenge       The code challenge, {@code null}
		 *                            if not specified.
		 * @param codeChallengeMethod The code challenge method,
		 *                            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder codeChallenge(final CodeChallenge codeChallenge, final CodeChallengeMethod codeChallengeMethod) {

			this.codeChallenge = codeChallenge;
			this.codeChallengeMethod = codeChallengeMethod;
			return this;
		}


		/**
		 * Sets the code challenge for Proof Key for Code Exchange
		 * (PKCE) by public OAuth clients.
		 *
		 * @param codeVerifier        The code verifier to use to
		 *                            compute the code challenge,
		 *                            {@code null} if PKCE is not
		 *                            specified.
		 * @param codeChallengeMethod The code challenge method,
		 *                            {@code null} if not specified.
		 *                            Defaults to
		 *                            {@link CodeChallengeMethod#PLAIN}
		 *                            if a code verifier is specified.
		 *
		 * @return This builder.
		 */
		public Builder codeChallenge(final CodeVerifier codeVerifier, final CodeChallengeMethod codeChallengeMethod) {

			if (codeVerifier != null) {
				CodeChallengeMethod method = codeChallengeMethod != null ? codeChallengeMethod : CodeChallengeMethod.getDefault();
				this.codeChallenge = CodeChallenge.compute(method, codeVerifier);
				this.codeChallengeMethod = method;
			} else {
				this.codeChallenge = null;
				this.codeChallengeMethod = null;
			}
			return this;
		}
		
		
		/**
		 * Sets the resource server URI.
		 *
		 * @param resource The resource URI, {@code null} if not
		 *                 specified.
		 *
		 * @return This builder.
		 */
		public Builder resource(final URI resource) {
			if (resource != null) {
				this.resources = Collections.singletonList(resource);
			} else {
				this.resources = null;
			}
			return this;
		}
		
		
		/**
		 * Sets the resource server URI(s).
		 *
		 * @param resources The resource URI(s), {@code null} if not
		 *                  specified.
		 *
		 * @return This builder.
		 */
		public Builder resources(final URI ... resources) {
			if (resources != null) {
				this.resources = Arrays.asList(resources);
			} else {
				this.resources = null;
			}
			return this;
		}
		
		
		/**
		 * Requests incremental authorisation.
		 *
		 * @param includeGrantedScopes {@code true} to request
		 *                             incremental authorisation.
		 *
		 * @return This builder.
		 */
		public Builder includeGrantedScopes(final boolean includeGrantedScopes) {
			
			this.includeGrantedScopes = includeGrantedScopes;
			return this;
		}
		
		
		/**
		 * Sets the request object. Corresponds to the optional
		 * {@code request} parameter. Must not be specified together
		 * with a request object URI.
		 *
		 * @param requestObject The request object, {@code null} if not
		 *                      specified.
		 *
		 * @return This builder.
		 */
		public Builder requestObject(final JWT requestObject) {
			
			this.requestObject = requestObject;
			return this;
		}
		
		
		/**
		 * Sets the request object URI. Corresponds to the optional
		 * {@code request_uri} parameter. Must not be specified
		 * together with a request object.
		 *
		 * @param requestURI The request object URI, {@code null} if
		 *                   not specified.
		 *
		 * @return This builder.
		 */
		public Builder requestURI(final URI requestURI) {
			
			this.requestURI = requestURI;
			return this;
		}
		
		
		/**
		 * Sets the requested prompt. Corresponds to the optional
		 * {@code prompt} parameter.
		 *
		 * @param prompt The requested prompt, {@code null} if not
		 *               specified.
		 *
		 * @return This builder.
		 */
		public Builder prompt(final Prompt prompt) {
			
			this.prompt = prompt;
			return this;
		}
		
		
		/**
		 * Sets a custom parameter.
		 *
		 * @param name   The parameter name. Must not be {@code null}.
		 * @param values The parameter values, {@code null} if not
		 *               specified.
		 *
		 * @return This builder.
		 */
		public Builder customParameter(final String name, final String ... values) {

			if (values == null || values.length == 0) {
				customParams.remove(name);
			} else {
				customParams.put(name, Arrays.asList(values));
			}
			
			return this;
		}


		/**
		 * Sets the URI of the endpoint (HTTP or HTTPS) for which the
		 * request is intended.
		 *
		 * @param uri The endpoint URI, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder endpointURI(final URI uri) {

			this.uri = uri;
			return this;
		}


		/**
		 * Builds a new authorisation request.
		 *
		 * @return The authorisation request.
		 */
		public AuthorizationRequest build() {

			try {
				return new AuthorizationRequest(uri, rt, rm, clientID, redirectURI, scope, state,
					codeChallenge, codeChallengeMethod, resources, includeGrantedScopes,
					requestObject, requestURI,
					prompt,
					customParams);
			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}


	/**
	 * Creates a new minimal authorisation request.
	 *
	 * @param uri      The URI of the authorisation endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method
	 *                 will not be used.
	 * @param rt       The response type. Corresponds to the
	 *                 {@code response_type} parameter. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier. Corresponds to the
	 *                 {@code client_id} parameter. Must not be
	 *                 {@code null}.
	 */
	public AuthorizationRequest(final URI uri,
		                    final ResponseType rt,
	                            final ClientID clientID) {

		this(uri, rt, null, clientID, null, null, null, null, null, null, false, null, null, null, null);
	}


	/**
	 * Creates a new authorisation request.
	 *
	 * @param uri                 The URI of the authorisation endpoint.
	 *                            May be {@code null} if the
	 *                            {@link #toHTTPRequest} method will not be
	 *                            used.
	 * @param rt                  The response type. Corresponds to the
	 *                            {@code response_type} parameter. Must not
	 *                            be {@code null}.
	 * @param rm                  The response mode. Corresponds to the
	 *                            optional {@code response_mode} parameter.
	 *                            Use of this parameter is not recommended
	 *                            unless a non-default response mode is
	 *                            requested (e.g. form_post).
	 * @param clientID            The client identifier. Corresponds to the
	 *                            {@code client_id} parameter. Must not be
	 *                            {@code null}.
	 * @param redirectURI         The redirection URI. Corresponds to the
	 *                            optional {@code redirect_uri} parameter.
	 *                            {@code null} if not specified.
	 * @param scope               The request scope. Corresponds to the
	 *                            optional {@code scope} parameter.
	 *                            {@code null} if not specified.
	 * @param state               The state. Corresponds to the recommended
	 *                            {@code state} parameter. {@code null} if
	 *                            not specified.
	 */
	public AuthorizationRequest(final URI uri,
		                    final ResponseType rt,
				    final ResponseMode rm,
	                            final ClientID clientID,
				    final URI redirectURI,
	                            final Scope scope,
				    final State state) {

		this(uri, rt, rm, clientID, redirectURI, scope, state, null, null, null, false, null, null, null, null);
	}


	/**
	 * Creates a new authorisation request with extension and custom
	 * parameters.
	 *
	 * @param uri                  The URI of the authorisation endpoint.
	 *                             May be {@code null} if the
	 *                             {@link #toHTTPRequest} method will not
	 *                             be used.
	 * @param rt                   The response type. Corresponds to the
	 *                             {@code response_type} parameter. Must
	 *                             not be {@code null}, unless a request a
	 *                             request object or URI is specified.
	 * @param rm                   The response mode. Corresponds to the
	 *                             optional {@code response_mode}
	 *                             parameter. Use of this parameter is not
	 *                             recommended unless a non-default
	 *                             response mode is requested (e.g.
	 *                             form_post).
	 * @param clientID             The client identifier. Corresponds to
	 *                             the {@code client_id} parameter. Must
	 *                             not be {@code null}, unless a request
	 *                             object or URI is specified.
	 * @param redirectURI          The redirection URI. Corresponds to the
	 *                             optional {@code redirect_uri} parameter.
	 *                             {@code null} if not specified.
	 * @param scope                The request scope. Corresponds to the
	 *                             optional {@code scope} parameter.
	 *                             {@code null} if not specified.
	 * @param state                The state. Corresponds to the
	 *                             recommended {@code state} parameter.
	 *                             {@code null} if not specified.
	 * @param codeChallenge        The code challenge for PKCE,
	 *                             {@code null} if not specified.
	 * @param codeChallengeMethod  The code challenge method for PKCE,
	 *                             {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param includeGrantedScopes {@code true} to request incremental
	 *                             authorisation.
	 * @param requestObject        The request object. Corresponds to the
	 *                             optional {@code request} parameter. Must
	 *                             not be specified together with a request
	 *                             object URI. {@code null} if not
	 *                             specified.
	 * @param requestURI           The request object URI. Corresponds to
	 *                             the optional {@code request_uri}
	 *                             parameter. Must not be specified
	 *                             together with a request object.
	 *                             {@code null} if not specified.
	 * @param prompt               The requested prompt. Corresponds to the
	 *                             optional {@code prompt} parameter.
	 * @param customParams         Custom parameters, empty map or
	 *                             {@code null} if none.
	 */
	public AuthorizationRequest(final URI uri,
				    final ResponseType rt,
				    final ResponseMode rm,
				    final ClientID clientID,
				    final URI redirectURI,
				    final Scope scope,
				    final State state,
				    final CodeChallenge codeChallenge,
				    final CodeChallengeMethod codeChallengeMethod,
				    final List<URI> resources,
				    final boolean includeGrantedScopes,
				    final JWT requestObject,
				    final URI requestURI,
				    final Prompt prompt,
				    final Map<String, List<String>> customParams) {

		super(uri);

		if (rt == null && requestObject == null && requestURI == null)
			throw new IllegalArgumentException("The response type must not be null");

		this.rt = rt;

		this.rm = rm;


		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		this.clientID = clientID;


		this.redirectURI = redirectURI;
		this.scope = scope;
		this.state = state;

		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		
		this.resources = ResourceUtils.ensureLegalResourceURIs(resources);
		
		this.includeGrantedScopes = includeGrantedScopes;
		
		if (requestObject != null && requestURI != null)
			throw new IllegalArgumentException("Either a request object or a request URI must be specified, but not both");
		
		this.requestObject = requestObject;
		this.requestURI = requestURI;
		
		if (requestObject instanceof SignedJWT) {
			// Make sure the "sub" claim is not set to the client_id value
			// https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-29#section-10.8
			JWTClaimsSet requestObjectClaims;
			try {
				requestObjectClaims = requestObject.getJWTClaimsSet();
			} catch (java.text.ParseException e) {
				// Should never happen
				throw new IllegalArgumentException("Illegal request parameter: " + e.getMessage(), e);
			}
			if (clientID.getValue().equals(requestObjectClaims.getSubject())) {
				throw new IllegalArgumentException("Illegal request parameter: The JWT sub (subject) claim must not equal the client_id");
			}
		}
		
		this.prompt = prompt; // technically OpenID

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = Collections.unmodifiableMap(customParams);
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Returns the registered (standard) OAuth 2.0 authorisation request
	 * parameter names.
	 *
	 * @return The registered OAuth 2.0 authorisation request parameter
	 *         names, as a unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the response type. Corresponds to the {@code response_type}
	 * parameter.
	 *
	 * @return The response type, may be {@code null} for a
	 *         {@link #specifiesRequestObject() JWT secured authorisation
	 *         request} with a {@link #getRequestObject() request} or
	 *         {@link #getRequestURI() request_uri} parameter.
	 */
	public ResponseType getResponseType() {
	
		return rt;
	}


	/**
	 * Gets the optional response mode. Corresponds to the optional
	 * {@code response_mode} parameter.
	 *
	 * @return The response mode, {@code null} if not specified.
	 */
	public ResponseMode getResponseMode() {

		return rm;
	}


	/**
	 * Returns the implied response mode, determined by the optional
	 * {@code response_mode} parameter, and if that isn't specified, by
	 * the {@code response_type}.
	 *
	 * <p>If the {@link ResponseMode#JWT jwt} response mode shortcut from
	 * JARM is explicitly requested expands it to
	 * {@link ResponseMode#QUERY_JWT query.jwt} or
	 * {@link ResponseMode#FRAGMENT_JWT fragment.jwt} depending on the
	 * response type ({@code response_type}).
	 *
	 * @return The implied response mode.
	 */
	public ResponseMode impliedResponseMode() {
		
		return ResponseMode.resolve(rm, rt);
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code client_id} 
	 * parameter.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {
	
		return clientID;
	}


	/**
	 * Gets the redirection URI. Corresponds to the optional 
	 * {@code redirection_uri} parameter.
	 *
	 * @return The redirection URI, {@code null} if not specified.
	 */
	public URI getRedirectionURI() {
	
		return redirectURI;
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
	 * Gets the state. Corresponds to the recommended {@code state} 
	 * parameter.
	 *
	 * @return The state, {@code null} if not specified.
	 */
	public State getState() {
	
		return state;
	}


	/**
	 * Returns the code challenge for PKCE.
	 *
	 * @return The code challenge, {@code null} if not specified.
	 */
	public CodeChallenge getCodeChallenge() {

		return codeChallenge;
	}


	/**
	 * Returns the code challenge method for PKCE.
	 *
	 * @return The code challenge method, {@code null} if not specified.
	 */
	public CodeChallengeMethod getCodeChallengeMethod() {

		return codeChallengeMethod;
	}
	
	
	/**
	 * Returns the resource server URI.
	 *
	 * @return The resource URI(s), {@code null} if not specified.
	 */
	public List<URI> getResources() {
		
		return resources;
	}
	
	
	/**
	 * Returns {@code true} if incremental authorisation is requested.
	 *
	 * @return {@code true} if incremental authorisation is requested,
	 *         else {@code false}.
	 */
	public boolean includeGrantedScopes() {
		
		return includeGrantedScopes;
	}
	
	
	/**
	 * Gets the request object. Corresponds to the optional {@code request}
	 * parameter.
	 *
	 * @return The request object, {@code null} if not specified.
	 */
	public JWT getRequestObject() {
		
		return requestObject;
	}
	
	
	/**
	 * Gets the request object URI. Corresponds to the optional
	 * {@code request_uri} parameter.
	 *
	 * @return The request object URI, {@code null} if not specified.
	 */
	public URI getRequestURI() {
		
		return requestURI;
	}
	
	
	/**
	 * Returns {@code true} if this is a JWT secured authentication
	 * request.
	 *
	 * @return {@code true} if a request object via a {@code request} or
	 *         {@code request_uri} parameter is specified, else
	 *         {@code false}.
	 */
	public boolean specifiesRequestObject() {
		
		return requestObject != null || requestURI != null;
	}
	
	
	/**
	 * Gets the requested prompt. Corresponds to the optional
	 * {@code prompt} parameter.
	 *
	 * @return The requested prompt, {@code null} if not specified.
	 */
	public Prompt getPrompt() {
		
		return prompt;
	}
	
	
	/**
	 * Returns the additional custom parameters.
	 *
	 * @return The additional custom parameters as a unmodifiable map,
	 *         empty map if none.
	 */
	public Map<String,List<String>> getCustomParameters () {

		return customParams;
	}
	
	
	/**
	 * Returns the specified custom parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter value(s), {@code null} if not specified.
	 */
	public List<String> getCustomParameter(final String name) {

		return customParams.get(name);
	}
	
	
	/**
	 * Returns the URI query parameters for this authorisation request.
	 * Query parameters which are part of the authorisation endpoint are
	 * not included.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = code
	 * client_id     = s6BhdRkqt3
	 * state         = xyz
	 * redirect_uri  = https://client.example.com/cb
	 * </pre>
	 * 
	 * @return The parameters.
	 */
	public Map<String,List<String>> toParameters() {
		
		// Put custom params first, so they may be overwritten by std params
		Map<String, List<String>> params = new LinkedHashMap<>(customParams);
		
		params.put("client_id", Collections.singletonList(clientID.getValue()));
		
		if (rt != null)
			params.put("response_type", Collections.singletonList(rt.toString()));

		if (rm != null)
			params.put("response_mode", Collections.singletonList(rm.getValue()));

		if (redirectURI != null)
			params.put("redirect_uri", Collections.singletonList(redirectURI.toString()));

		if (scope != null)
			params.put("scope", Collections.singletonList(scope.toString()));
		
		if (state != null)
			params.put("state", Collections.singletonList(state.getValue()));

		if (codeChallenge != null) {
			params.put("code_challenge", Collections.singletonList(codeChallenge.getValue()));

			if (codeChallengeMethod != null) {
				params.put("code_challenge_method", Collections.singletonList(codeChallengeMethod.getValue()));
			}
		}
		
		if (includeGrantedScopes)
			params.put("include_granted_scopes", Collections.singletonList("true"));
		
		if (resources != null)
			params.put("resource", URIUtils.toStringList(resources));
		
		if (requestObject != null) {
			try {
				params.put("request", Collections.singletonList(requestObject.serialize()));
				
			} catch (IllegalStateException e) {
				throw new SerializeException("Couldn't serialize request object to JWT: " + e.getMessage(), e);
			}
		}
		
		if (requestURI != null)
			params.put("request_uri", Collections.singletonList(requestURI.toString()));
		
		if (prompt != null)
			params.put("prompt", Collections.singletonList(prompt.toString()));

		return params;
	}
	
	
	/**
	 * Returns the parameters for this authorisation request as a JSON Web
	 * Token (JWT) claims set. Intended for creating a request object.
	 *
	 * @return The parameters as JWT claim set.
	 */
	public JWTClaimsSet toJWTClaimsSet() {
		
		if (specifiesRequestObject()) {
			throw new IllegalStateException("Cannot create nested JWT secured authorization request");
		}
		
		return JWTClaimsSetUtils.toJWTClaimsSet(toParameters());
	}
	
	
	/**
	 * Returns the URI query string for this authorisation request.
	 *
	 * <p>Note that the '?' character preceding the query string in an URI
	 * is not included in the returned string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 * 
	 * @return The URI query string.
	 */
	public String toQueryString() {
		
		Map<String, List<String>> params = new HashMap<>();
		if (getEndpointURI() != null) {
			params.putAll(URLUtils.parseParameters(getEndpointURI().getQuery()));
		}
		params.putAll(toParameters());
		
		return URLUtils.serializeParameters(params);
	}


	/**
	 * Returns the complete URI representation for this authorisation
	 * request, consisting of the {@link #getEndpointURI authorization
	 * endpoint URI} with the {@link #toQueryString query string} appended.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @return The URI representation.
	 */
	public URI toURI() {

		if (getEndpointURI() == null)
			throw new SerializeException("The authorization endpoint URI is not specified");
		
		StringBuilder sb = new StringBuilder(URIUtils.stripQueryString(getEndpointURI()).toString());
		sb.append('?');
		sb.append(toQueryString());
		try {
			return new URI(sb.toString());
		} catch (URISyntaxException e) {
			throw new SerializeException("Couldn't append query string: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Returns the matching HTTP request.
	 *
	 * @param method The HTTP request method which can be GET or POST. Must
	 *               not be {@code null}.
	 *
	 * @return The HTTP request.
	 */
	public HTTPRequest toHTTPRequest(final HTTPRequest.Method method) {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
		
		HTTPRequest httpRequest;
		if (method.equals(HTTPRequest.Method.GET)) {
			httpRequest = new HTTPRequest(HTTPRequest.Method.GET, getEndpointURI());
		} else if (method.equals(HTTPRequest.Method.POST)) {
			httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		} else {
			throw new IllegalArgumentException("The HTTP request method must be GET or POST");
		}
		
		httpRequest.setQuery(toQueryString());
		
		return httpRequest;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
	
		return toHTTPRequest(HTTPRequest.Method.GET);
	}


	/**
	 * Parses an authorisation request from the specified URI query
	 * parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = code
	 * client_id     = s6BhdRkqt3
	 * state         = xyz
	 * redirect_uri  = https://client.example.com/cb
	 * </pre>
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final Map<String,List<String>> params)
		throws ParseException {

		return parse(null, params);
	}


	/**
	 * Parses an authorisation request from the specified URI and query
	 * parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = code
	 * client_id     = s6BhdRkqt3
	 * state         = xyz
	 * redirect_uri  = https://client.example.com/cb
	 * </pre>
	 *
	 * @param uri    The URI of the authorisation endpoint. May be
	 *               {@code null} if the {@link #toHTTPRequest()} method
	 *               will not be used.
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final URI uri, final Map<String,List<String>> params)
		throws ParseException {
		
		Set<String> repeatParams = MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, Collections.singleton("resource"));
		
		if (! repeatParams.isEmpty()) {
			// Always result in non-redirecting error. Technically
			// only duplicate client_id, state, redirect_uri,
			// response_type, request_uri and request should
			String msg = "Parameter(s) present more than once: " + repeatParams;
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.setDescription(msg));
		}
		
		// Parse response_mode, response_type, client_id, redirect_uri and state first,
		// needed if parsing results in a error response
		final ClientID clientID;
		URI redirectURI = null;
		State state = State.parse(MultivaluedMapUtils.getFirstValue(params, "state"));
		ResponseMode rm = null;
		ResponseType rt = null;
		
		// Optional response_mode
		String v = MultivaluedMapUtils.getFirstValue(params, "response_mode");
		if (StringUtils.isNotBlank(v)) {
			rm = new ResponseMode(v);
		}
		
		// Mandatory client_id
		v = MultivaluedMapUtils.getFirstValue(params, "client_id");
		if (StringUtils.isBlank(v)) {
			// No automatic redirection https://tools.ietf.org/html/rfc6749#section-4.1.2.1
			String msg = "Missing client_id parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}
		clientID = new ClientID(v);
		
		// Optional redirect_uri
		v = MultivaluedMapUtils.getFirstValue(params, "redirect_uri");
		if (StringUtils.isNotBlank(v)) {
			try {
				redirectURI = new URI(v);
			} catch (URISyntaxException e) {
				// No automatic redirection https://tools.ietf.org/html/rfc6749#section-4.1.2.1
				String msg = "Invalid redirect_uri parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
		}
		
		// Mandatory response_type, unless in JAR
		v = MultivaluedMapUtils.getFirstValue(params, "response_type");
		if (StringUtils.isNotBlank(v)) {
			try {
				rt = ResponseType.parse(v);
			} catch (ParseException e) {
				// Only cause
				String msg = "Invalid response_type parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					clientID, redirectURI, rm, state, e);
			}
		}
		
		// Check for a JAR in request or request_uri parameters
		v = MultivaluedMapUtils.getFirstValue(params, "request_uri");
		URI requestURI = null;
		if (StringUtils.isNotBlank(v)) {
			try {
				requestURI = new URI(v);
			} catch (URISyntaxException e) {
				String msg = "Invalid request_uri parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					clientID, redirectURI, ResponseMode.resolve(rm, rt), state, e);
			}
		}
		
		v = MultivaluedMapUtils.getFirstValue(params, "request");
		
		JWT requestObject = null;
		
		if (StringUtils.isNotBlank(v)) {
			
			// request_object and request_uri must not be present at the same time
			if (requestURI != null) {
				String msg = "Invalid request: Found mutually exclusive request and request_uri parameters";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					clientID, redirectURI, ResponseMode.resolve(rm, rt), state, null);
			}
			
			try {
				requestObject = JWTParser.parse(v);
				
				if (requestObject instanceof SignedJWT) {
					// Make sure the "sub" claim is not set to the client_id value
					// https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-29#section-10.8
					JWTClaimsSet requestObjectClaims = requestObject.getJWTClaimsSet();
					if (clientID.getValue().equals(requestObjectClaims.getSubject())) {
						throw new java.text.ParseException("The JWT sub (subject) claim must not equal the client_id", 0);
					}
				}
				
			} catch (java.text.ParseException e) {
				String msg = "Invalid request parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					clientID, redirectURI, ResponseMode.resolve(rm, rt), state, e);
			}
		}

		// Response type mandatory, unless in JAR
		if (rt == null && requestObject == null && requestURI == null) {
			String msg = "Missing response_type parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				clientID, redirectURI, ResponseMode.resolve(rm, null), state, null);
		}


		// Parse optional scope
		v = MultivaluedMapUtils.getFirstValue(params, "scope");

		Scope scope = null;

		if (StringUtils.isNotBlank(v))
			scope = Scope.parse(v);


		// Parse optional code challenge and method for PKCE
		CodeChallenge codeChallenge = null;
		CodeChallengeMethod codeChallengeMethod = null;

		v = MultivaluedMapUtils.getFirstValue(params, "code_challenge");

		if (StringUtils.isNotBlank(v))
			codeChallenge = CodeChallenge.parse(v);

		if (codeChallenge != null) {

			v = MultivaluedMapUtils.getFirstValue(params, "code_challenge_method");

			if (StringUtils.isNotBlank(v))
				codeChallengeMethod = CodeChallengeMethod.parse(v);
		}
		
		
		List<URI> resources;
		try {
			resources = ResourceUtils.parseResourceURIs(params.get("resource"));
		} catch (ParseException e) {
			throw new ParseException(e.getMessage(), OAuth2Error.INVALID_RESOURCE.setDescription(e.getMessage()),
				clientID, redirectURI, ResponseMode.resolve(rm, rt), state, e);
		}
		
		boolean includeGrantedScopes = false;
		v = MultivaluedMapUtils.getFirstValue(params, "include_granted_scopes");
		if ("true".equals(v)) {
			includeGrantedScopes = true;
		}
		
		Prompt prompt;
		try {
			prompt = Prompt.parse(MultivaluedMapUtils.getFirstValue(params, "prompt"));
			
		} catch (ParseException e) {
			String msg = "Invalid prompt parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				clientID, redirectURI, ResponseMode.resolve(rm, rt), state, e);
		}
		
		// Parse custom parameters
		Map<String,List<String>> customParams = null;

		for (Map.Entry<String,List<String>> p: params.entrySet()) {

			if (! REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}


		return new AuthorizationRequest(uri, rt, rm, clientID, redirectURI, scope, state,
			codeChallenge, codeChallengeMethod, resources, includeGrantedScopes,
			requestObject, requestURI,
			prompt,
			customParams);
	}


	/**
	 * Parses an authorisation request from the specified URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final String query)
		throws ParseException {

		return parse(null, URLUtils.parseParameters(query));
	}
	
	
	/**
	 * Parses an authorisation request from the specified URI and query
	 * string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param uri   The URI of the authorisation endpoint. May be 
	 *              {@code null} if the {@link #toHTTPRequest()} method
	 *              will not be used.
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an 
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final URI uri, final String query)
		throws ParseException {
	
		return parse(uri, URLUtils.parseParameters(query));
	}


	/**
	 * Parses an authorisation request from the specified URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getRawQuery()));
	}
	
	
	/**
	 * Parses an authorisation request from the specified HTTP request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final HTTPRequest httpRequest) 
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URI query string");
		
		return parse(URIUtils.getBaseURI(httpRequest.getURI()), query);
	}
}
