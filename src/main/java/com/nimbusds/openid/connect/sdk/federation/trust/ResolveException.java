/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.util.Collections;
import java.util.List;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;


/**
 * Resolve exception.
 */
public class ResolveException extends GeneralException {
	
	
	/**
	 * For multiple causes.
	 */
	private List<Throwable> causes;
	
	
	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The message.
	 */
	public ResolveException(final String message) {
		super(message);
	}
	
	
	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The message.
	 * @param cause   The cause.
	 */
	public ResolveException(final String message, final Throwable cause) {
		super(message, cause);
	}
	
	
	/**
	 * Creates a new resolve exception with potentially multiple causes.
	 *
	 * @param message The message.
	 * @param causes  The causes, empty list or {@code null} if none.
	 */
	public ResolveException(final String message, final List<Throwable> causes) {
		super(message);
		this.causes = causes;
	}
	
	
	/**
	 * Creates a new resolve exception.
	 *
	 * @param message     The message.
	 * @param errorObject The error object.
	 */
	public ResolveException(final String message, final ErrorObject errorObject) {
		super(message, errorObject);
	}
	
	
	/**
	 * Returns the exception causes.
	 *
	 * @return The exception causes, empty list if none.
	 */
	public List<Throwable> getCauses() {
		if (causes != null) {
			return causes;
		} else if (getCause() != null){
			return Collections.singletonList(getCause());
		} else {
			return Collections.emptyList();
		}
	}
}
