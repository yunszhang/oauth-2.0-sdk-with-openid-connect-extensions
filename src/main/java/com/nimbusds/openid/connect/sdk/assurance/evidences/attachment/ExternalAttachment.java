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


import java.net.URI;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.token.AccessToken;


@Immutable
public class ExternalAttachment extends Attachment {


	private final URI url;
	
	
	private final AccessToken accessToken;
	
	
	private final int expiresIn;
	
	
	public ExternalAttachment(final String description, final URI url, final AccessToken accessToken, final int expiresIn) {
		super(description);
		this.url = url;
		this.accessToken = accessToken;
		this.expiresIn = expiresIn;
	}
	
	
	public URI getURL() {
		return url;
	}
	
	
	public AccessToken getAccessToken() {
		return accessToken;
	}
	
	
	public int getExpiresIn() {
		return expiresIn;
	}
}
