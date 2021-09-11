package com.nimbusds.oauth2.sdk.token;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Introduced to represent token types(URI) used in TokenExchangeGrant
 */
public class TokenTypeURI {

  /**
   * Indicates that the token is an OAuth 2.0 access token issued by the given
   * authorization server.
   */
  public static final TokenTypeURI ACCESS_TOKEN = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:access_token"));
  /**
   * Indicates that the token is an OAuth 2.0 refresh token issued by the given
   * authorization server.
   */
  public static final TokenTypeURI REFRESH_TOKEN = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:refresh_token"));
  /**
   * Indicates that the token is an ID Token as defined in Section 2 of OpenID.Core.
   */
  public static final TokenTypeURI ID_TOKEN = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:id_token"));
  /**
   *  Indicates that the token is a base64url-encoded SAML 1.1
   *  OASIS.saml-core-1.1 assertion.
   */
  public static final TokenTypeURI SAML1 = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:saml1"));
  /**
   *  Indicates that the token is a base64url-encoded SAML 2.0
   *  OASIS.saml-core-2.0-os assertion.
   */
  public static final TokenTypeURI SAML2 = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:saml2"));

  private static final Map<String, TokenTypeURI> KNOWN_TOKEN_TYPE_URIS;

  static {
    Map<String, TokenTypeURI> knownTokenTypeUris = new HashMap<>();
    knownTokenTypeUris.put(ACCESS_TOKEN.getUri().toString(), ACCESS_TOKEN);
    knownTokenTypeUris.put(REFRESH_TOKEN.getUri().toString(), REFRESH_TOKEN);
    knownTokenTypeUris.put(ID_TOKEN.getUri().toString(), ID_TOKEN);
    knownTokenTypeUris.put(SAML1.getUri().toString(), SAML1);
    knownTokenTypeUris.put(SAML2.getUri().toString(), SAML2);
    KNOWN_TOKEN_TYPE_URIS = Collections.unmodifiableMap(knownTokenTypeUris);
  }

  private final URI uri;

  private TokenTypeURI(URI uri) {
    if (uri == null) {
      throw new IllegalArgumentException("The uri must not be null");
    }

    this.uri = uri;
  }

  public URI getUri() {
    return uri;
  }

  /**
   * Parses TokenTypeURI from a string value
   *
   * @param uriValue uri in string type
   * @return Parsed token type uri
   * @throws URISyntaxException if uriValue is an invalid uri
   */
  public static TokenTypeURI parse(String uriValue) throws URISyntaxException {
    if (uriValue == null) {
      throw new IllegalArgumentException("The uri value must not be null");
    }

    if (KNOWN_TOKEN_TYPE_URIS.containsKey(uriValue)) {
      return KNOWN_TOKEN_TYPE_URIS.get(uriValue);
    }

    URI uri = new URI(uriValue);
    return new TokenTypeURI(uri);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    TokenTypeURI that = (TokenTypeURI) o;

    return uri.equals(that.getUri());
  }

  @Override
  public int hashCode() {
    return uri.hashCode();
  }
}
