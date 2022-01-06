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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.assurance.Policy;
import com.nimbusds.openid.connect.sdk.assurance.Procedure;
import com.nimbusds.openid.connect.sdk.assurance.Status;


/**
 * Common attributes in a {@link ValidationMethod} and
 * {@link VerificationMethod}.
 */
class CommonMethodAttributes {
	
	
	/**
	 * The policy.
	 */
	private final Policy policy;
	
	
	/**
	 * The procedure.
	 */
	private final Procedure procedure;
	
	
	/**
	 * The status.
	 */
	private final Status status;
	
	
	/**
	 * Creates the common attributes for a validation or verification
	 * method.
	 *
	 * @param policy    The policy, {@code null} if not specified.
	 * @param procedure The procedure, {@code null} if not specified.
	 * @param status    The status, {@code null} if not specified.
	 */
	CommonMethodAttributes(final Policy policy, final Procedure procedure, final Status status) {
		this.policy = policy;
		this.procedure = procedure;
		this.status = status;
	}
	
	
	/**
	 * Returns the policy.
	 *
	 * @return The policy, {@code null} if not specified.
	 */
	public Policy getPolicy() {
		return policy;
	}
	
	
	/**
	 * Returns the procedure.
	 *
	 * @return The procedure, {@code null} if not specified.
	 */
	public Procedure getProcedure() {
		return procedure;
	}
	
	
	/**
	 * Returns the status.
	 *
	 * @return The status, {@code null} if not specified.
	 */
	public Status getStatus() {
		return status;
	}
	
	
	/**
	 * Returns a JSON object representation of the attributes.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getPolicy() != null) {
			o.put("policy", getPolicy().getValue());
		}
		if (getProcedure() != null) {
			o.put("procedure", getProcedure().getValue());
		}
		if (getStatus() != null) {
			o.put("status", getStatus().getValue());
		}
		return o;
	}
}
