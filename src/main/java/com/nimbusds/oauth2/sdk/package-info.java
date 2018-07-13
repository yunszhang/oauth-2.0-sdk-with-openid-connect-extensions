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
 * Classes for representing, serialising and parsing OAuth 2.0 client requests
 * and authorisation server responses.
 *
 * <p>Authorisation endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.AuthorizationRequest} The client
 *         requests the end-user's authorisation to access a protected
 *         resource.
 *     <li>{@link com.nimbusds.oauth2.sdk.AuthorizationResponse} The server
 *         grants the authorisation or returns an error:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse}
 *                 The server responds with an authorisation grant.
 *             <li>{@link com.nimbusds.oauth2.sdk.AuthorizationErrorResponse}
 *                 The server responds with an authorisation error.
 *         </ul>
 *     </li>
 * </ul>
 *
 * <p>Token endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenRequest} The client requests an
 *         access token and optional refresh token using a previously issued
 *         authorisation code or other valid grant.
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenResponse} The server responds
 *         with an access token or returns an error:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.AccessTokenResponse} The
 *                 server responds with an access token and optional refresh
 *                 token.
 *             <li>{@link com.nimbusds.oauth2.sdk.TokenErrorResponse} The
 *                 server responds with a token error.
 *         </ul>
 * </ul>
 *
 * <p>Token introspection endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenIntrospectionRequest} The
 *         resource server requests an access token to be introspected.
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenIntrospectionResponse} The
 *         server responds with a token metadata or returns an error:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse}
 *                 The server responds with the token metadata.
 *             <li>{@link com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse}
 *                 The server responds with an error.
 *         </ul>
 * </ul>
 *
 * <p>Token revocation endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenRevocationRequest} The client
 *         request revocation of a previously issued access or refresh
 *         token.
 * </ul>
 * 
 * <p>Protected resource messages:
 * 
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.ProtectedResourceRequest} The client
 *         makes a request to a protected resource using an OAuth 2.0 access
 *         token.
 * </ul>
 */
package com.nimbusds.oauth2.sdk;