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

package com.nimbusds.oauth2.sdk.http;


import javax.mail.internet.ContentType;

import net.jcip.annotations.Immutable;


/**
 * Resource with optional associated content type.
 */
@Immutable
@Deprecated
public class Resource {


	/**
	 * The content.
	 */
	private final String content;


	/**
	 * The content type.
	 */
	private final ContentType contentType;


	/**
	 * Creates a new resource with optional associated content type.
	 *
	 * @param content     The resource content, empty string if none. Must 
	 *                    not be {@code null}.
	 * @param contentType The resource content type, {@code null} if not
	 *                    specified.
	 */
	public Resource(final String content, final ContentType contentType) {

		if (content == null) {
			throw new IllegalArgumentException("The resource content must not be null");
		}

		this.content = content;
		this.contentType = contentType;
	}


	/**
	 * Gets the content of this resource.
	 *
	 * @return The content, empty string if none.
	 */
	public String getContent() {

		return content;
	}


	/**
	 * Gets the content type of this resource.
	 *
	 * @return The content type, {@code null} if not specified.
	 */
	public ContentType getContentType() {

		return contentType;
	}
}
