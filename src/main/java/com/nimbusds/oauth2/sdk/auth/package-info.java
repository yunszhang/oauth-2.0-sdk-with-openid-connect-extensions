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

/**
 * Implementations of OAuth 2.0 client authentication methods at the Token 
 * endpoint.
 *
 * <p>The following authentication methods are supported:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic} (the default)
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretPost}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretJWT}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication}
 * </ul>
 */
package com.nimbusds.oauth2.sdk.auth;