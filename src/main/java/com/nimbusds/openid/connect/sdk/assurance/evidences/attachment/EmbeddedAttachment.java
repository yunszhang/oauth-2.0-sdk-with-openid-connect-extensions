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


import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Embedded attachment.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 5.1.2.1.
 * </ul>
 */
@Immutable
public class EmbeddedAttachment extends Attachment {
	
	
	/**
	 * The content type.
	 */
	private final ContentType contentType;
	
	
	/**
	 * The content.
	 */
	private final Base64 content;
	
	
	/**
	 * Creates a new embedded attachment.
	 *
	 * @param contentType The content type. Must not be {@code null}.
	 * @param content     The content. Must not be {@code null}.
	 * @param description The description, {@code null} if not specified.
	 */
	public EmbeddedAttachment(final ContentType contentType,
				  final Base64 content,
				  final String description) {
		
		super(description);
		
		Objects.requireNonNull(contentType, "The content type must not be null");
		this.contentType = contentType;
		
		Objects.requireNonNull(content, "The content must not be null");
		this.content = content;
	}
	
	
	/**
	 * Returns the content type.
	 *
	 * @return The content type.
	 */
	public ContentType getContentType() {
		return contentType;
	}
	
	
	/**
	 * Returns the content.
	 *
	 * @return The content.
	 */
	public Base64 getContent() {
		return content;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		JSONObject o = super.toJSONObject();
		o.put("content_type", getContentType().toString());
		o.put("content", getContent().toString());
		return o;
	}
	
	
	/**
	 * Parses an embedded attachment from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The embedded attachment.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EmbeddedAttachment parse(final JSONObject jsonObject)
		throws ParseException {
		
		String description = JSONObjectUtils.getString(jsonObject, "desc", null);
		
		ContentType contentType;
		try {
			contentType = ContentType.parse(JSONObjectUtils.getString(jsonObject, "content_type"));
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid content_type: " + e.getMessage(), e);
		}
		
		Base64 content = Base64.from(JSONObjectUtils.getString(jsonObject, "content"));
		
		if (content.toString().trim().isEmpty()) {
			throw new ParseException("Empty or blank content");
		}
		
		return new EmbeddedAttachment(contentType, content, description);
	}
}
