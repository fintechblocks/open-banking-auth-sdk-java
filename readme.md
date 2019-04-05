# Java-SDK #

## What is Java-SDK? ##

This SDK provides tools for the integration of the Open Banking authorization flow into your Java server application.

This repository contains two subfolders:
* */source* contains the SDK source code
* */example* contains an example on how to use the SDK

## How to use SDK ##

First read throught the Authorization part of API documentation.

Account-information API documentation: https://<sandbox_portal_host_of_the_bank>/api-documentation/account-info-1.0

Payment-initiation API documentation: https://<sandbox_portal_host_of_the_bank>/api-documentation/payment-init-1.0

### Create an OpenBankingAuth istance ###

**OpenBankingAuth(String clientId, String privateKey, String keyID, String redirectUri, String tokenEndpointUri, String authEndpointUri, String scope) - constructor**

*Required parameters*

* clientId (e.g. myApp@account-info.1.0)
* privateKey (your private key, the public key has to be uploded on the developer portal)
* keyID (the id of the keypair in your keystore, can be any string)
* redirectUri (the OAuth2 callback url of your application)
* tokenEndpointUri (token endpoint uri of OIDC server)
* authEndpointUri (authentication endpoint uri of OIDC server)
* scope (depends on API, read documentation)

**Usage**

```java
import com.fintechblocks.java.sdk.OpenBankingAuth;
import com.fintechblocks.java.sdk.Utils;
...
OpenBankingAuth accountInfoAuth = new OpenBankingAuth(clientId, privateKey, keyID, redirectUri, tokenEndpointUri, authEndpointUri, scope);
```

### Get an access-token ###

**getAccessToken():String**

**Usage**

```java
String accessToken = accountInfoAuth.getAccessToken();
```

### Generate authorization url ###

**generateAuthorizationUrl(String intentId, String state, String nonce):String**

*Required parameters*

* intentId (identification of previously created intent, e.g. ConsentId)
* state (random string)
* nonce (random string)

**Usage**

```java
String authUrl = accountInfoAuth.generateAuthorizationUrl(intentId, state, nonce);
```

### Exhange authorization code to tokens ###

**exchangeToken(String code):object**

*Required parameters*

* code (the authorization code received from the authorization server)

**Usage**

```java
JsonNode newAccessTokenJson = accountInfoAuth.exchangeToken(request.getParameter("code"));
```

## Extra functionality ##

### Create signature header ###

**createSignatureHeader(String body, String issuer):String**

*Required parameters*

* body (intent, e.g. an account-request)
* issuer

**Usage**
```java
Map<String, String> headers = new HashMap<String, String>();
headers.put("x-jws-signature", accountInfoAuth.createSignatureHeader(body, issuer));
```

### Check if a token is expired ###

**isTokenExpired(String token [, Long expiredAfterSeconds]):boolean**

*Required parameters*

* token (jwt)

*Optional parameters*

* expiredAfterSeconds (number of seconds * 1000)

**Usage**

```java
boolean isExpired = accountInfoAuth.isTokenExpired(token, 5000); // will token expire after five seconds?
```

### Use a refresh token ###

**refreshToken(String refreshToken):String**

*Required parameters*

* token (refresh token)

**Usage**

```java
JsonNode newTokens = accountInfoAuth.refreshToken(refreshToken);
```

## How to run the example ##

Open *example/src/main/webapp/accountinfo_example.jsp*/*example/src/main/webapp/paymentinit_example.jsp* and replace <sandbox_api_host_of_the_bank> with correct value (e.g. api.sandbox.bank.hu).
First build the *source*.

```shell
cd source
mvn clean install
```

Build the *example*.

```shell
cd example
mvn clean install
```

Run example on a web-server (e.g. tomcat).