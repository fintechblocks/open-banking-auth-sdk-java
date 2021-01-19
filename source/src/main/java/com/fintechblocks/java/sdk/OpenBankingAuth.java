package com.fintechblocks.java.sdk;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

import io.jsonwebtoken.Claims;

public class OpenBankingAuth {
  private static String HEADER_CONTENT_TYPE ="Content-Type";
  private static String HEADER_CONTENT_TYPE_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
  private static String OIDC_GRANT_TYPE = "grant_type";
  private static String OIDC_GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
  private static String OIDC_GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
  private static String OIDC_SCOPE = "scope";
  private static String OIDC_CLIENT_ASSERTION_TYPE = "client_assertion_type";
  private static String OIDC_CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  private static String OIDC_CLIENT_ASSERTION = "client_assertion";
  private static String OIDC_REFRESH_TOKEN = "refresh_token";

  private String clientId;
  private String privateKey;
  private String keyID;
  private String redirectUri;
  private String scope;
  private String authorizationEndpointURI;
  private String tokenEndpointURI;

  public OpenBankingAuth(String clientId, String privateKey, String keyID, String redirectUri, String tokenEndpointURI,
      String authorizationEndpointURI, String scope) {
    this.clientId = clientId;
    this.privateKey = privateKey;
    this.keyID = keyID;
    this.redirectUri = redirectUri;
    this.scope = scope;
    this.tokenEndpointURI = tokenEndpointURI;
    this.authorizationEndpointURI = authorizationEndpointURI;
  }

  public String getAccessToken() throws Exception {
    URL url = new URL(this.tokenEndpointURI);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("POST");
    connection.setRequestProperty(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_X_WWW_FORM_URLENCODED);
    connection.setDoOutput(true);

    HashMap<String, String> params = new HashMap<>();
    params.put(OIDC_GRANT_TYPE, OIDC_GRANT_TYPE_CLIENT_CREDENTIALS);
    params.put(OIDC_SCOPE, this.scope);
    params.put(OIDC_CLIENT_ASSERTION_TYPE, OIDC_CLIENT_ASSERTION_TYPE_JWT_BEARER);

    Map<String, Object> clientAssertionClaims = new HashMap<>();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", Utils.createExpirationDate(1));

    params.put(OIDC_CLIENT_ASSERTION, Utils.createJWT(this.privateKey, clientAssertionClaims));
    Utils.setFormUrlParameters(connection, params);

    JsonNode tokensJson = Utils.stringToJson(Utils.responseToString(connection));
    return tokensJson.get("access_token").asText();
  }

  public String generateAuthorizationUrl(String intentId) throws Exception {
    StringBuilder url = new StringBuilder();
    url.append(this.authorizationEndpointURI).append("?");
    url.append("response_type=code&");
    url.append("client_id=").append(this.clientId).append("&");
    url.append("redirect_uri=").append(this.redirectUri).append("&");
    url.append("scope=").append(this.scope).append("&");

    Map<String, Object> payload = new HashMap<>();
    payload.put("client_id", this.clientId);
    payload.put("redirect_uri", this.redirectUri);

    Map<String, Object> openbankingIntentId = new HashMap<>();
    openbankingIntentId.put("value", intentId);

    Map<String, Object> userInfo = new HashMap<>();
    userInfo.put("openbanking_intent_id", openbankingIntentId);

    Map<String, Object> idToken = new HashMap<>();
    idToken.put("openbanking_intent_id", openbankingIntentId);

    Map<String, Object> claims = new HashMap<>();
    claims.put("userinfo", userInfo);
    claims.put("id_token", idToken);

    payload.put("claims", claims);

    url.append("request=").append(Utils.createJWT(this.privateKey, payload));
    return url.toString();
  }

  public JsonNode exchangeToken(String code) throws Exception {
    URL url = new URL(this.tokenEndpointURI);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("POST");
    connection.setRequestProperty(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_X_WWW_FORM_URLENCODED);
    connection.setDoOutput(true);

    HashMap<String, String> params = new HashMap<>();
    params.put(OIDC_GRANT_TYPE, OIDC_GRANT_TYPE_AUTHORIZATION_CODE);
    params.put("code", code);
    params.put("redirect_uri", this.redirectUri);
    params.put(OIDC_CLIENT_ASSERTION_TYPE, OIDC_CLIENT_ASSERTION_TYPE_JWT_BEARER);

    Map<String, Object> clientAssertionClaims = new HashMap<>();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", Integer.MAX_VALUE);
    params.put(OIDC_CLIENT_ASSERTION, Utils.createJWT(this.privateKey, clientAssertionClaims));

    Utils.setFormUrlParameters(connection, params);
    return Utils.stringToJson(Utils.responseToString(connection));
  }

  public String createSignatureHeader(String body, String issuer) throws Exception {
    Map<String, Object> jwtHeaders = new HashMap<>();
    jwtHeaders.put("alg", "RS256");
    jwtHeaders.put("kid", this.keyID);
    jwtHeaders.put("b64", false);
    jwtHeaders.put("http://openbanking.org.uk/iat", new Date().getTime() - 1000);
    jwtHeaders.put("http://openbanking.org.uk/iss", issuer);
    String[] crit = { "b64", "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss" };
    jwtHeaders.put("crit", crit);

    String jwt = Utils.sign(this.privateKey, body, jwtHeaders);
    String[] jwtParts = jwt.split("\\.");
    return jwtParts[0] + ".." + jwtParts[2];
  }

  public boolean isTokenExpired(String token, Long expiredAfterSeconds) {
    Claims claims = Utils.decodeJwt(token);
    long expiration = claims.getExpiration().getTime();
    long now = new Date().getTime();
    if (expiredAfterSeconds == null)
      now += expiredAfterSeconds;
    return expiration < now;
  }

  public JsonNode refreshToken(String refreshToken) throws Exception {
    URL url = new URL(this.tokenEndpointURI);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("POST");
    connection.setRequestProperty(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_X_WWW_FORM_URLENCODED);
    connection.setDoOutput(true);

    HashMap<String, String> params = new HashMap<>();
    params.put(OIDC_GRANT_TYPE, OIDC_REFRESH_TOKEN);
    params.put(OIDC_REFRESH_TOKEN, refreshToken);
    params.put(OIDC_CLIENT_ASSERTION_TYPE, OIDC_CLIENT_ASSERTION_TYPE_JWT_BEARER);
    
    Map<String, Object> clientAssertionClaims = new HashMap<>();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", Utils.createExpirationDate(1));

    params.put(OIDC_CLIENT_ASSERTION, Utils.createJWT(this.privateKey, clientAssertionClaims));
    Utils.setFormUrlParameters(connection, params);

    return Utils.stringToJson(Utils.responseToString(connection));
  }
}
