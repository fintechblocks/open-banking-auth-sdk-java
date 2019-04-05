package com.fintechblocks.java.sdk;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

import io.jsonwebtoken.Claims;

public class OpenBankingAuth {

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
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    connection.setDoOutput(true);

    HashMap<String, String> params = new HashMap<String, String>();
    params.put("grant_type", "client_credentials");
    params.put("scope", this.scope);
    params.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

    Map<String, Object> clientAssertionClaims = new HashMap<String, Object>();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", Utils.createExpirationDate(1));

    params.put("client_assertion", Utils.createJWT(this.privateKey, clientAssertionClaims));
    Utils.setFormUrlParameters(connection, params);

    JsonNode tokensJson = Utils.stringToJson(Utils.responseToString(connection));
    return tokensJson.get("access_token").asText();
  }

  public String generateAuthorizationUrl(String intentId, String state, String nonce) throws Exception {
    StringBuilder url = new StringBuilder();
    url.append(this.authorizationEndpointURI).append("?");
    url.append("response_type=code&");
    url.append("client_id=").append(this.clientId).append("&");
    url.append("redirect_uri=").append(this.redirectUri).append("&");
    url.append("scope=").append(this.scope).append("&");

    Map<String, Object> clientAssertionClaims = new HashMap<String, Object>();
    long now = System.currentTimeMillis();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", (now / 1000) + 60);

    Map<String, Object> payload = new HashMap<String, Object>();
    payload.put("client_id", this.clientId);
    payload.put("redirect_uri", this.redirectUri);

    Map<String, Object> openbankingIntentId = new HashMap<String, Object>();
    openbankingIntentId.put("value", intentId);

    Map<String, Object> userInfo = new HashMap<String, Object>();
    userInfo.put("openbanking_intent_id", openbankingIntentId);

    Map<String, Object> idToken = new HashMap<String, Object>();
    idToken.put("openbanking_intent_id", openbankingIntentId);

    Map<String, Object> claims = new HashMap<String, Object>();
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
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    connection.setDoOutput(true);

    HashMap<String, String> params = new HashMap<String, String>();
    params.put("grant_type", "authorization_code");
    params.put("code", code);
    params.put("redirect_uri", this.redirectUri);
    params.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

    Map<String, Object> clientAssertionClaims = new HashMap<String, Object>();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", Integer.MAX_VALUE);
    params.put("client_assertion", Utils.createJWT(this.privateKey, clientAssertionClaims));

    Utils.setFormUrlParameters(connection, params);
    return Utils.stringToJson(Utils.responseToString(connection));
  }

  public String createSignatureHeader(String body, String issuer) throws Exception {
    Map<String, Object> jwtHeaders = new HashMap<String, Object>();
    jwtHeaders.put("alg", "RS256");
    jwtHeaders.put("kid", this.keyID);
    jwtHeaders.put("b64", false);
    jwtHeaders.put("http://openbanking.org.uk/iat", new Date().getTime());
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
    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    connection.setDoOutput(true);

    HashMap<String, String> params = new HashMap<String, String>();
    params.put("grant_type", "refresh_token");
    params.put("refresh_token", refreshToken);
    params.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    
    Map<String, Object> clientAssertionClaims = new HashMap<String, Object>();
    clientAssertionClaims.put("sub", this.clientId);
    clientAssertionClaims.put("aud", this.tokenEndpointURI);
    clientAssertionClaims.put("exp", Utils.createExpirationDate(1));

    params.put("client_assertion", Utils.createJWT(this.privateKey, clientAssertionClaims));
    Utils.setFormUrlParameters(connection, params);

    return Utils.stringToJson(Utils.responseToString(connection));
  }
}
