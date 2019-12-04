Nimbus OAuth 2.0 SDK with OpenID Connect extensions

Copyright (c) Connect2id Ltd., 2012 - 2019


README

This open source SDK is your starting point for developing OAuth 2.0 and OpenID
Connect based applications in Java.

OAuth 2.0

Supported endpoint requests and responses:

    * Authorisation Server Metadata

    * Authorisation Endpoint

    * Token Endpoint

    * Token Introspection Endpoint

    * Token Revocation Endpoint

    * Client Registration and Management Endpoint

    * Request Object Endpoint

    * Resource protected with an OAuth 2.0 access token


OpenID Connect

Supported endpoint requests and responses:

    * OpenID Provider Metadata

    * Authorisation Endpoint for OpenID Authentication requests

    * Token Endpoint

    * UserInfo Endpoint

    * End-Session (Logout) Endpoint

    * Back-Channel Logout Endpoint


Features:

	* Process plain, signed and encrypted JSON Web Tokens (JWTs) with help 
	  of the Nimbus JOSE+JWT library.

	* OpenID Connect UserInfo i10n and l10n support with help of the Nimbus
	  Language Tags (RFC 5646) library.

	* Java Servlet integration.


This SDK version implements the following standards and drafts:

	* The OAuth 2.0 Authorization Framework (RFC 6749)

	* The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)

	* OAuth 2.0 Token Introspection (RFC 7662)

	* OAuth 2.0 Token Revocation (RFC 7009)

	* OAuth 2.0 Authorization Server Metadata (draft-ietf-oauth-discovery-10)

	* OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)

	* OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)

	* Assertion Framework for OAuth 2.0 Client Authentication and Authorization
	  Grants (RFC 7521)

	* JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
      Authorization Grants (RFC 7523)

    * SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization
      Grants (RFC 7522)

    * Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)

    * Authentication Method Reference Values (RFC 8176)

    * OAuth 2.0 Authorization Server Metadata (RFC 8414)

    * OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access
      Tokens (draft-ietf-oauth-mtls-15)

    * Resource Indicators for OAuth 2.0
      (draft-ietf-oauth-resource-indicators-00)

    * OAuth 2.0 Incremental Authorization
      (draft-ietf-oauth-incremental-authz-00)

    * OAuth 2.0 Device Authorization Grant (draft-ietf-oauth-device-flow-15)

    * The OAuth 2.0 Authorization Framework: JWT Secured Authorization Request
      (JAR) (draft-ietf-oauth-jwsreq-17)

    * OAuth 2.0 Pushed Authorization Requests (draft-lodderstedt-oauth-par-01)

	* OpenID Connect Core 1.0 (2014-02-25)

	* OpenID Connect Core Unmet Authentication Requirements 1.0 (2019-05-08)

	* OpenID Connect Discovery 1.0 (2014-02-25)

	* OpenID Connect Dynamic Registration 1.0 (2014-02-25)

	* OpenID Connect Session Management 1.0 (2017-01-25)

	* OpenID Connect Front-Channel Logout 1.0 (2017-01-25)

	* OpenID Connect Back-Channel Logout 1.0 (2017-01-25)

	* OpenID Connect Extended Authentication Profile (EAP) ACR Values 1.0 -
	  draft 00

	* OpenID Connect for Identity Assurance 1.0 - draft 08

	* OAuth 2.0 Multiple Response Type Encoding Practices 1.0 (2014-02-25)

    * Financial Services – Financial API - Part 1: Read Only API Security
      Profile (2018-10-17)

    * Financial Services – Financial API - Part 2: Read and Write API Security
      Profile (2018-10-17)

    * Financial-grade API: JWT Secured Authorization Response Mode for OAuth
      2.0 (JARM) (2018-10-17)


This SDK is provided under the terms of the Apache 2.0 licence.


Questions or comments? Email support@connect2id.com


2019-12-04
