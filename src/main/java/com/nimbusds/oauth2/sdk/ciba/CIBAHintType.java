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

package com.nimbusds.oauth2.sdk.ciba;


/**
 * The hint type in a CIBA request.
 */
public enum CIBAHintType {
	
	
	/**
	 * Login hint token ({@code login_hint_token}).
	 */
	LOGIN_HINT_TOKEN,
	
	
	/**
	 * ID token hint ({@code id_token_hint}).
	 */
	ID_TOKEN_HINT,
	
	
	/**
	 * Login hint ({@code login_hint}).
	 */
	LOGIN_HINT;
	
	
	@Override
	public String toString() {
		return super.toString().toLowerCase();
	}
}
