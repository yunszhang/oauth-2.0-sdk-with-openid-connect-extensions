/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Identity evidence attachment.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 5.1.2.
 * </ul>
 */
public abstract class Attachment {
	
	
	/**
	 * The optional description.
	 */
	private final String description;
	
	
	/**
	 * Creates a new attachment with the specified description.
	 *
	 * @param description The description, {@code null} if not specified.
	 */
	protected Attachment(final String description) {
		this.description = description;
	}
	
	
	/**
	 * Returns the description.
	 *
	 * @return The description string.
	 */
	public String getDescriptionString() {
		return description;
	}
	
	
	/**
	 * Returns a JSON object representation of this attachment.
	 *
	 * @return The JSON object.
	 */
	protected JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getDescriptionString() != null) {
			o.put("desc", getDescriptionString());
		}
		return o;
	}
	
	
	/**
	 * Casts this attachment to an embedded attachment.
	 *
	 * @return The embedded attachment.
	 *
	 * @throws ClassCastException If the cast failed.
	 */
	public EmbeddedAttachment toEmbeddedAttachment() {
		
		return (EmbeddedAttachment) this;
	}
	
	
	/**
	 * Casts this attachment to an external attachment.
	 *
	 * @return The external attachment.
	 *
	 * @throws ClassCastException If the cast failed.
	 */
	public ExternalAttachment toExternalAttachment() {
		
		return (ExternalAttachment) this;
	}
	
	
	/**
	 * Parses an identity evidence attachment from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity evidence attachment.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Attachment parse(final JSONObject jsonObject)
		throws ParseException {
		
		if (jsonObject.get("content") != null) {
			return EmbeddedAttachment.parse(jsonObject);
		} else if (jsonObject.get("url") != null) {
			return ExternalAttachment.parse(jsonObject);
		} else {
			throw new ParseException("Missing required attachment parameter(s)");
		}
	}
}
