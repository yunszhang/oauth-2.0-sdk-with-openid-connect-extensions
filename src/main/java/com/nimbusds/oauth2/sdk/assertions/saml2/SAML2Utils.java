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

package com.nimbusds.oauth2.sdk.assertions.saml2;


import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;


/**
 * OpenSAML 3.0 utilities.
 */
final class SAML2Utils {
	
	
	/**
	 * Builds a new OpenSAML object.
	 *
	 * @param clazz The object class. Must not be {@code null}.
	 *
	 * @return The OpenSAML object.
	 */
	public static <T> T buildSAMLObject(final Class<T> clazz) {
		
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			
			QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			
			return (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
			
		} catch (IllegalAccessException | NoSuchFieldException e) {
			throw new IllegalArgumentException("Couldn't create SAML object with class " + clazz.getCanonicalName() + ": " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private SAML2Utils() {}
}
