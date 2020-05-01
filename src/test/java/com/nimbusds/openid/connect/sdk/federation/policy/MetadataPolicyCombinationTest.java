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

package com.nimbusds.openid.connect.sdk.federation.policy;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class MetadataPolicyCombinationTest extends TestCase {
	
	
	// https://openid.net/specs/openid-connect-federation-1_0.html#rfc.section.4.1.3.1
	public void testExample() throws ParseException, PolicyViolationException {
	
		String federationPolicyJSON = "{" +
			"  \"scopes\": {" +
			"    \"subset_of\": [" +
			"      \"openid\"," +
			"      \"eduperson\"," +
			"      \"phone\"" +
			"    ]," +
			"    \"superset_of\": [" +
			"      \"openid\"" +
			"    ]," +
			"    \"default\": [" +
			"      \"openid\"," +
			"      \"eduperson\"" +
			"    ]" +
			"  }," +
			"  \"id_token_signed_response_alg\": {" +
			"    \"one_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"," +
			"      \"ES512\"" +
			"    ]" +
			"  }," +
			"  \"contacts\": {" +
			"    \"add\": \"helpdesk@federation.example.org\"" +
			"  }," +
			"  \"application_type\": {" +
			"    \"value\": \"web\"" +
			"  }" +
			"}";
		
		String rpPolicyJSON = "{" +
			"  \"scopes\": {" +
			"    \"subset_of\": [" +
			"      \"openid\"," +
			"      \"eduperson\"," +
			"      \"address\"" +
			"    ]," +
			"    \"default\": [" +
			"      \"openid\"," +
			"      \"eduperson\"" +
			"    ]" +
			"  }," +
			"  \"id_token_signed_response_alg\": {" +
			"    \"one_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"" +
			"    ]," +
			"    \"default\": \"ES256\"" +
			"  }," +
			"  \"contacts\": {" +
			"    \"add\": \"helpdesk@org.example.org\"" +
			"  }" +
			"}";
		
		MetadataPolicy federationPolicy = MetadataPolicy.parse(federationPolicyJSON);
		MetadataPolicy rpPolicy = MetadataPolicy.parse(rpPolicyJSON);
		
		MetadataPolicy combinedPolicy = MetadataPolicyCombination.combine(federationPolicy, rpPolicy);
		
		System.out.println(combinedPolicy.toJSONObject());
	}
}
