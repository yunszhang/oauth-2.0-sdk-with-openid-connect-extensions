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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Identity verification method.
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 4.1.1.1.
 * </ul>
 */
@Immutable
public final class IdentityVerificationMethod extends Identifier {
	
	
	/**
	 * Physical In-Person Proofing.
	 */
	public static final IdentityVerificationMethod PIPP = new IdentityVerificationMethod("pipp");
	
	
	/**
	 * Supervised remote In-Person Proofing.
	 */
	public static final IdentityVerificationMethod SRIPP = new IdentityVerificationMethod("sripp");
	
	
	/**
	 * Online verification of an electronic ID card.
	 */
	public static final IdentityVerificationMethod EID = new IdentityVerificationMethod("eid");
	
	
	/**
	 * Unsupervised remote in-person proofing with video capture of the ID
	 * document, user self-portrait video and liveness checks.
	 */
	public static final IdentityVerificationMethod URIPP = new IdentityVerificationMethod("uripp");
	
	
	/**
	 * Creates a new identity verification method.
	 *
	 * @param value The verification method value. Must not be
	 *              {@code null}.
	 */
	public IdentityVerificationMethod(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof IdentityVerificationMethod &&
			this.toString().equals(object.toString());
	}
}
