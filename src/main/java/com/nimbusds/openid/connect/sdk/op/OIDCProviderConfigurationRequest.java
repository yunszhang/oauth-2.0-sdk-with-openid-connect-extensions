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

package com.nimbusds.openid.connect.sdk.op;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import net.jcip.annotations.Immutable;


/**
 * OpenID Connect provider configuration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /.well-known/openid-configuration HTTP/1.1
 * Host: example.com
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0, section 4.1.
 * </ul>
 */
@Immutable
public class OIDCProviderConfigurationRequest extends AbstractRequest {
	
	
	/**
	 * The well-known path for OpenID Connect provider metadata.
	 */
	public static final String OPENID_PROVIDER_WELL_KNOWN_PATH = "/.well-known/openid-configuration";
	
	
	/**
	 * Creates a new OpenID Connect provider configuration request.
	 *
	 * @param issuer The OpenID issuer. Must represent a valid URL.
	 */
	public OIDCProviderConfigurationRequest(final Issuer issuer) {
		super(URI.create(URIUtils.removeTrailingSlash(URI.create(issuer.getValue())) + OPENID_PROVIDER_WELL_KNOWN_PATH));
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		URL url;
		
		try {
			url = getEndpointURI().toURL();
			
		} catch (IllegalArgumentException | MalformedURLException e) {
			
			throw new SerializeException(e.getMessage(), e);
		}
		
		return new HTTPRequest(HTTPRequest.Method.GET, url);
	}
}
