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

package com.nimbusds.openid.connect.sdk.federation;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Federation entity configuration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /.well-known/openid-federation HTTP/1.1
 * Host: example.com
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.
 * </ul>
 */
@Immutable
public class FederationEntityConfigurationRequest extends AbstractRequest {
	
	
	/**
	 * The well-known path for federation entity metadata.
	 */
	public static final String OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH = "/.well-known/openid-federation";
	
	
	/**
	 * Creates a new federation entity configuration request.
	 *
	 * @param entityID The entity ID. Must represent a valid URL. Must not
	 *                 be {@code null}.
	 */
	public FederationEntityConfigurationRequest(final EntityID entityID) {
		super(URI.create(URIUtils.removeTrailingSlash(entityID.toURI()) + OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH));
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
