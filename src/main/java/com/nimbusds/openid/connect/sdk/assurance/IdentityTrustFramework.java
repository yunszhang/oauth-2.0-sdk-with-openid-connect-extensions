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

package com.nimbusds.openid.connect.sdk.assurance;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Identity trust framework identifiers.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, sections 4.1.1 and 11.1.
 * </ul>
 */
@Immutable
public final class IdentityTrustFramework extends Identifier {
	
	
	/**
	 * The OP verifies and maintains user identities in conforms with the
	 * German Anti-Money Laundering Law.
	 */
	public static final IdentityTrustFramework DE_AML = new IdentityTrustFramework("de_aml");
	
	
	/**
	 * The OP is able to attest user identities in accordance with the EU
	 * regulation No 910/2014 (eIDAS) at the identification assurance
	 * level "Substantial".
	 */
	public static final IdentityTrustFramework EIDAS_IAL_SUBSTANTIAL = new IdentityTrustFramework("eidas_ial_substantial");
	
	
	/**
	 * The OP is able to attest user identities in accordance with the EU
	 * regulation No 910/2014 (eIDAS) at the identification assurance
	 * level "High".
	 */
	public static final IdentityTrustFramework EIDAS_IAL_HIGH = new IdentityTrustFramework("eidas_ial_high");
	
	
	/**
	 * The OP is able to attest user identities in accordance with the NIST
	 * Special Publication 800-63A at the Identity Assurance Level 2.
	 */
	public static final IdentityTrustFramework NIST_800_63A_IAL_2 = new IdentityTrustFramework("nist_800_63A_ial_2");
	
	
	/**
	 * The OP is able to attest user identities in accordance with the NIST
	 * Special Publication 800-63A at the Identity Assurance Level 3.
	 */
	public static final IdentityTrustFramework NIST_800_63A_IAL_3 = new IdentityTrustFramework("nist_800_63A_ial_3");
	
	
	/**
	 * The OP verifies and maintains user identities in conforms with the
	 * Japanese Act on Prevention of Transfer of Criminal Proceeds.
	 */
	public static final IdentityTrustFramework JP_AML = new IdentityTrustFramework("jp_aml");
	
	
	/**
	 * The OP verifies and maintains user identities in conformance with
	 * the Japanese Act for Identification, etc. by Mobile Voice
	 * Communications Carriers of Their Subscribers, etc. and for
	 * Prevention of Improper Use of Mobile Voice Communications Services.
	 */
	public static final IdentityTrustFramework JP_MPIUPA = new IdentityTrustFramework("jp_mpiupa");
	
	
	/**
	 * Creates a new identity trust framework.
	 *
	 * @param value The identity trust framework value. Must not be
	 *              {@code null}.
	 */
	public IdentityTrustFramework(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof IdentityTrustFramework &&
			this.toString().equals(object.toString());
	}
}
