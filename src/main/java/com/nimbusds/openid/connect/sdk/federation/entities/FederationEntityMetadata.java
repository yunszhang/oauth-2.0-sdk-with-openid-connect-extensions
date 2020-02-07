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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.net.URI;
import java.util.List;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Federation entity metadata.
 */
public class FederationEntityMetadata implements JSONAware {
	
	
	/**
	 * The federation API endpoint, required for trust anchors and
	 * intermediate entities.
	 */
	private URI federationAPIEndpoint;
	
	
	/**
	 * The optional trust anchor.
	 */
	private EntityID trustAnchorID;
	
	
	/**
	 * The optional entity name.
	 */
	private String name;
	
	
	/**
	 * The optional contacts.
	 */
	private List<String> contacts;
	
	
	/**
	 * The policy URI.
	 */
	private URI policyURI;
	
	
	/**
	 * The homepage URI.
	 */
	private URI homepageURI;
	
	
	/**
	 * Creates a new federation entity metadata.
	 *
	 * @param federationEndpoint The federation API endpoint, required for
	 *                           trust anchors and intermediate entities,
	 *                           optional for leaf entities.
	 */
	public FederationEntityMetadata(final URI federationEndpoint) {
		this.federationAPIEndpoint = federationEndpoint;
	}
	
	
	/**
	 * Gets the federation API endpoint.
	 *
	 * @return The federation API endpoint, {@code null} if not specified.
	 */
	public URI getFederationAPIEndpointURI() {
		return federationAPIEndpoint;
	}
	
	
	/**
	 * Gets the trust anchor.
	 *
	 * @return The trust anchor, {@code null} if not specified.
	 */
	public EntityID getTrustAnchorID() {
		return trustAnchorID;
	}
	
	
	/**
	 * Sets the trust anchor.
	 *
	 * @param trustAnchorID The trust anchor, {@code null} if not
	 *                      specified.
	 */
	public void setTrustAnchorID(final EntityID trustAnchorID) {
		this.trustAnchorID = trustAnchorID;
	}
	
	
	/**
	 * Gets the entity name.
	 *
	 * @return The entity name, {@code null} if not specified.
	 */
	public String getName() {
		return name;
	}
	
	
	/**
	 * Sets the entity name.
	 *
	 * @param name The entity name, {@code null} if not specified.
	 */
	public void setName(final String name) {
		this.name = name;
	}
	
	
	/**
	 * Gets the entity contacts.
	 *
	 * @return The contacts, such as names, e-mail addresses and phone
	 *         numbers, {@code null} if not specified.
	 */
	public List<String> getContacts() {
		return contacts;
	}
	
	
	/**
	 * Sets the entity contacts.
	 *
	 * @param contacts The contacts, such as names, e-mail addresses and
	 *                 phone numbers, {@code null} if not specified.
	 */
	public void setContacts(final List<String> contacts) {
		this.contacts = contacts;
	}
	
	
	/**
	 * Gets the conditions and policies documentation URI.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URI getPolicyURI() {
		return policyURI;
	}
	
	
	/**
	 * Sets the conditions and policies documentation URI.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URI policyURI) {
		this.policyURI = policyURI;
	}
	
	
	/**
	 * Gets the entity homepage URI.
	 *
	 * @return The entity homepage URI, {@code null} if not specified.
	 */
	public URI getHomepageURI() {
		return homepageURI;
	}
	
	
	/**
	 * Sets the entity homepage URI.
	 *
	 * @param homepageURI The entity homepage URI, {@code null} if not
	 *                    specified.
	 */
	public void setHomepageURI(final URI homepageURI) {
		this.homepageURI = homepageURI;
	}
	
	
	/**
	 * Returns a JSON object representation of this federation entity
	 * metadata.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "federation_api_endpoint" : "https://example.com/federation_api_endpoint",
	 *   "name"                    : "The example cooperation",
	 *   "homepage_uri"            : "https://www.example.com"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getFederationAPIEndpointURI() != null) {
			o.put("federation_api_endpoint", getFederationAPIEndpointURI().toString());
		}
		if (getTrustAnchorID() != null) {
			o.put("trust_anchor_id", getTrustAnchorID().getValue());
		}
		if (getName() != null) {
			o.put("name", getName());
		}
		if (getContacts() != null) {
			o.put("contacts", getContacts());
		}
		if (getPolicyURI() != null) {
			o.put("policy_uri", getPolicyURI().toString());
		}
		if (getHomepageURI() != null) {
			o.put("homepage_uri", getHomepageURI().toString());
		}
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	/**
	 * Parses a federation entity metadata from the specified a JSON object
	 * string.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "federation_api_endpoint" : "https://example.com/federation_api_endpoint",
	 *   "name"                    : "The example cooperation",
	 *   "homepage_uri"            : "https://www.example.com"
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The entity metadata.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FederationEntityMetadata parse(final JSONObject jsonObject)
		throws ParseException {
		
		URI federationAPIEndpoint = JSONObjectUtils.getURI(jsonObject, "federation_api_endpoint", null);
		
		FederationEntityMetadata metadata = new FederationEntityMetadata(federationAPIEndpoint);
		
		if (jsonObject.get("trust_anchor_id") != null) {
			metadata.setTrustAnchorID(new EntityID(JSONObjectUtils.getString(jsonObject, "trust_anchor_id")));
		}
		
		metadata.setName(JSONObjectUtils.getString(jsonObject, "name", null));
		
		metadata.setContacts(JSONObjectUtils.getStringList(jsonObject, "contacts", null));
		
		metadata.setPolicyURI(JSONObjectUtils.getURI(jsonObject, "policy_uri", null));
		
		metadata.setHomepageURI(JSONObjectUtils.getURI(jsonObject, "homepage_uri", null));
		
		return metadata;
	}
	
	
	/**
	 * Parses a federation entity metadata from the specified JSON object
	 * string.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "federation_api_endpoint" : "https://example.com/federation_api_endpoint",
	 *   "name"                    : "The example cooperation",
	 *   "homepage_uri"            : "https://www.example.com"
	 * }
	 * </pre>
	 *
	 * @param json The JSON object string. Must not be {@code null}.
	 *
	 * @return The entity metadata.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FederationEntityMetadata parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
