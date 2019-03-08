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

package com.nimbusds.oauth2.sdk.device;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import net.jcip.annotations.Immutable;

/**
 * Device authorisation request. Used to start the authorization flow for
 * browserless and input constraint devices. Supports custom request parameters.
 *
 * <p>
 * Extending classes may define additional request parameters as well as enforce
 * tighter requirements on the base parameters.
 *
 * <p>
 * Example HTTP request:
 *
 * <pre>
 * POST /device_authorization HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * client_id=459691054427
 * </pre>
 *
 * <p>
 * Related specifications:
 *
 * <ul>
 * <li>OAuth 2.0 Device Flow for Browserless and Input Constrained Devices
 * (draft-ietf-oauth-device-flow-14)
 * </ul>
 */
@Immutable
public class DeviceAuthorizationRequest extends AbstractRequest {

	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	static {
		Set<String> p = new HashSet<>();

		p.add("client_id");
		p.add("scope");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The client identifier (required).
	 */
	private final ClientID clientID;


	/**
	 * The scope (optional).
	 */
	private final Scope scope;


	/**
	 * Custom parameters.
	 */
	private final Map<String, List<String>> customParams;


	/**
	 * Builder for constructing authorisation requests.
	 */
	public static class Builder {

		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;


		/**
		 * The client identifier (required).
		 */
		private final ClientID clientID;


		/**
		 * The scope (optional).
		 */
		private Scope scope;


		/**
		 * Custom parameters.
		 */
		private final Map<String, List<String>> customParams = new HashMap<>();


		/**
		 * Creates a new devize authorization request builder.
		 *
		 * @param clientID The client identifier. Corresponds to the {@code client_id}
		 *                 parameter. Must not be {@code null}.
		 */
		public Builder(final ClientID clientID) {

			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");

			this.clientID = clientID;
		}


		/**
		 * Creates a new device authorization request builder from the specified
		 * request.
		 *
		 * @param request The device authorization request. Must not be {@code null}.
		 */
		public Builder(final DeviceAuthorizationRequest request) {

			uri = request.getEndpointURI();
			scope = request.scope;
			clientID = request.getClientID();
			customParams.putAll(request.getCustomParameters());
		}


		/**
		 * Sets the scope. Corresponds to the optional {@code scope} parameter.
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
		 * Sets a custom parameter.
		 *
		 * @param name   The parameter name. Must not be {@code null}.
		 * @param values The parameter values, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder customParameter(final String name, final String... values) {

			if (values == null || values.length == 0) {
				customParams.remove(name);
			} else {
				customParams.put(name, Arrays.asList(values));
			}

			return this;
		}


		/**
		 * Sets the URI of the endpoint (HTTP or HTTPS) for which the request is
		 * intended.
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
		 * Builds a new device authorization request.
		 *
		 * @return The device authorization request.
		 */
		public DeviceAuthorizationRequest build() {

			try {
				return new DeviceAuthorizationRequest(uri, clientID, scope, customParams);
			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}


	/**
	 * Creates a new minimal device authorization request.
	 *
	 * @param uri      The URI of the device authorization endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method will not be
	 *                 used.
	 * @param clientID The client identifier. Corresponds to the {@code client_id}
	 *                 parameter. Must not be {@code null}.
	 */
	public DeviceAuthorizationRequest(final URI uri, final ClientID clientID) {

		this(uri, clientID, null, null);
	}


	/**
	 * Creates a new device authorization request.
	 *
	 * @param uri      The URI of the device authorization endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method will not be
	 *                 used.
	 * @param clientID The client identifier. Corresponds to the {@code client_id}
	 *                 parameter. Must not be {@code null}.
	 * @param scope    The request scope. Corresponds to the optional {@code scope}
	 *                 parameter. {@code null} if not specified.
	 */
	public DeviceAuthorizationRequest(final URI uri, final ClientID clientID, final Scope scope) {

		this(uri, clientID, scope, null);
	}


	/**
	 * Creates a new device authorization request with extension and custom
	 * parameters.
	 *
	 * @param uri          The URI of the device authorization endpoint. May be
	 *                     {@code null} if the {@link #toHTTPRequest} method will
	 *                     not be used.
	 * @param clientID     The client identifier. Corresponds to the
	 *                     {@code client_id} parameter. Must not be {@code null}.
	 * @param scope        The request scope. Corresponds to the optional
	 *                     {@code scope} parameter. {@code null} if not specified.
	 * @param customParams Custom parameters, empty map or {@code null} if none.
	 */
	public DeviceAuthorizationRequest(final URI uri,
	                                  final ClientID clientID,
	                                  final Scope scope,
	                                  final Map<String, List<String>> customParams) {

		super(uri);

		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		this.clientID = clientID;

		this.scope = scope;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = Collections.unmodifiableMap(customParams);
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Returns the registered (standard) OAuth 2.0 device authorization request
	 * parameter names.
	 *
	 * @return The registered OAuth 2.0 device authorization request parameter
	 *         names, as a unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code client_id} parameter.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return clientID;
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
	 * Returns the additional custom parameters.
	 *
	 * @return The additional custom parameters as a unmodifiable map, empty map if
	 *         none.
	 */
	public Map<String, List<String>> getCustomParameters() {

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
	 * Returns the URI query parameters for this device authorization request. Query
	 * parameters which are part of the device authorization endpoint are not
	 * included.
	 *
	 * <p>
	 * Example parameters:
	 *
	 * <pre>
	 * client_id     = s6BhdRkqt3
	 * scope         = profile
	 * </pre>
	 * 
	 * @return The parameters.
	 */
	public Map<String, List<String>> toParameters() {

		Map<String, List<String>> params = new LinkedHashMap<>();

		// Put custom params first, so they may be overwritten by std params
		params.putAll(customParams);

		params.put("client_id", Collections.singletonList(clientID.getValue()));

		if (scope != null)
			params.put("scope", Collections.singletonList(scope.toString()));

		return params;
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
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(toParameters()));
		return httpRequest;
	}


	/**
	 * Parses an device authorization request from the specified HTTP request.
	 *
	 * <p>
	 * Example HTTP request (GET):
	 *
	 * <pre>
	* POST /device_authorization HTTP/1.1
	* Host: server.example.com
	* Content-Type: application/x-www-form-urlencoded
	*
	* client_id=459691054427
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The device authorization request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an device
	 *                        authorization request.
	 */
	public static DeviceAuthorizationRequest parse(final HTTPRequest httpRequest) throws ParseException {

		// Only HTTP POST accepted
		URI uri;

		try {
			uri = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}

		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

		// No fragment! May use query component!
		Map<String, List<String>> params = httpRequest.getQueryParameters();

		// Parse mandatory client ID first
		String v = MultivaluedMapUtils.getFirstValue(params, "client_id");

		if (StringUtils.isBlank(v)) {
			String msg = "Missing \"client_id\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		ClientID clientID = new ClientID(v);

		// Parse optional scope
		v = MultivaluedMapUtils.getFirstValue(params, "scope");

		Scope scope = null;

		if (StringUtils.isNotBlank(v))
			scope = Scope.parse(v);

		// Parse custom parameters
		Map<String, List<String>> customParams = null;

		for (Map.Entry<String, List<String>> p : params.entrySet()) {

			if (!REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}

		return new DeviceAuthorizationRequest(uri, clientID, scope, customParams);
	}
}
