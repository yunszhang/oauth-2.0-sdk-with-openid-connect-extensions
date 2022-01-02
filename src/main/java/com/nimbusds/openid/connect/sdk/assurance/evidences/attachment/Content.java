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

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.util.Base64;


/**
 * Content with type and optional description.
 */
public class Content {
	
	
	/**
	 * The content type.
	 */
	private final ContentType type;
	
	
	/**
	 * The BASE64-encoded content.
	 */
	private final Base64 base64;
	
	
	/**
	 * The optional description.
	 */
	private final String description;
	
	
	/**
	 * Creates a new content instance.
	 *
	 * @param type        The content type. Must not be {@code null}.
	 * @param base64      The BASE64-encoded content. Must not be
	 *                    {@code null}.
	 * @param description The optional description, {@code null} if not
	 *                    specified.
	 */
	public Content(final ContentType type,
		       final Base64 base64,
		       final String description) {
		
		Objects.requireNonNull(type);
		this.type = type;
		
		Objects.requireNonNull(base64);
		this.base64 = base64;
		
		this.description = description;
	}
	
	
	/**
	 * Returns the content type.
	 *
	 * @return The content type.
	 */
	public ContentType getType() {
		return type;
	}
	
	
	/**
	 * Returns the BASE64-encoded content.
	 *
	 * @return The BASE64-encoded content.
	 */
	public Base64 getBase64() {
		return base64;
	}
	
	
	/**
	 * Returns the optional description.
	 *
	 * @return The optional description, {@code null} if not specified.
	 */
	public String getDescription() {
		return description;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Content)) return false;
		Content content = (Content) o;
		return getType().equals(content.getType()) &&
			getBase64().equals(content.getBase64()) &&
			Objects.equals(getDescription(), content.getDescription());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getType(), getBase64(), getDescription());
	}
}
