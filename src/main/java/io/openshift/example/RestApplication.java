/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.openshift.example;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
//import io.vertx.ext.auth.authorization.AuthorizationProvider;
//import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
//import io.vertx.ext.auth.jwt.authorization.MicroProfileAuthorization;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.JWTAuthHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.openshift.example.service.Greeting;

import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;

public class RestApplication extends AbstractVerticle {
  private static String PUBLIC_KEY;// = System.getenv("REALM_PUBLIC_KEY");
  private long counter;

  @Override
  public void start(Promise<Void> done) {
    loadPublicKey();
    // Create a router object.
    Router router = Router.router(vertx);
    router.get("/health").handler(rc -> rc.response().setStatusCode(200).end("OK"));
    router.get().handler(StaticHandler.create());

    JsonObject keycloakJson = new JsonObject()
      .put("realm", System.getenv("REALM"))
      .put("auth-server-url", System.getenv("SSO_AUTH_SERVER_URL"))
      .put("ssl-required", "external")
      .put("resource", System.getenv("CLIENT_ID"))
      .put("credentials", new JsonObject()
        .put("secret", System.getenv("SECRET")));

    JsonObject config = new JsonObject()
      // since we're consuming keycloak JWTs we need
      // to locate the permission claims in the token
      .put("permissionsClaimKey", "realm_access/roles");
    // Configure the AuthHandler to process JWT's
    router.route("/api/greeting").handler(JWTAuthHandler.create(
//      JWTAuth.create(vertx, new JWTAuthOptions(config)
      JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
          .setAlgorithm("RS256")
//                        .setBuffer(PUBLIC_KEY)))));
          .setPublicKey(System.getenv("REALM_PUBLIC_KEY")))
        // since we're consuming keycloak JWTs we need to locate the permission claims in the token
        .setPermissionsClaimKey("realm_access/roles"))));

    // This is how one can do RBAC, e.g.: only admin is allowed
    router.get("/api/greeting").handler(ctx -> {
//      AuthorizationProvider authorizationProvider = MicroProfileAuthorization.create();
//      authorizationProvider.getAuthorizations(ctx.user(), voidAsyncResult -> {
//        if(voidAsyncResult.succeeded() & PermissionBasedAuthorization.create("booster-admin").match(ctx.user())) {
      ctx.user().isAuthorized("booster-admin", authz -> {
        if (authz.succeeded() && authz.result()) {
          ctx.next();
        } else {
          System.err.println("AuthZ failed!");
          ctx.fail(403);
        }
      });
    });

    router.get("/api/greeting").handler(ctx -> {
      String name = ctx.request().getParam("name");
      if (name == null) {
        name = "World";
      }
      ctx.response()
        .putHeader(CONTENT_TYPE, "application/json; charset=utf-8")
        .end(new Greeting(++counter, name).encode());
    });

    // serve the dynamic config so the web client
    // can also connect to the SSO server
    router.get("/keycloak.json").handler(ctx ->
      ctx.response()
        .putHeader(CONTENT_TYPE, "application/json; charset=utf-8")
        .end(keycloakJson.encode()));

    // serve static files (web client)
    router.get().handler(StaticHandler.create());

    // Create the HTTP server and pass the "accept" method to the request handler.
    vertx
      .createHttpServer()
      .requestHandler(router)
      .listen(
        // Retrieve the port from the configuration,
        // default to 8080.
        config().getInteger("http.port", 8080),
        ar -> done.handle(ar.mapEmpty()));
  }

  public static void loadPublicKey() {
    PUBLIC_KEY = System.getenv("REALM_PUBLIC_KEY");
    if (PUBLIC_KEY == null) {
      System.err.println("PUBLIC_KEY loaded from REALM_PUBLIC_KEY is null, reading PEM file.");
//      try {
//        PUBLIC_KEY = IOUtils.toString(Paths.get("target", "test-classes", "public.pem").toFile().toURI(), Charset.defaultCharset());
//        PUBLIC_KEY = IOUtils.toString(Paths.get("src","test","resources", "public.pem").toFile().toURI(), Charset.defaultCharset());
        PUBLIC_KEY = "-----BEGIN CERTIFICATE-----\n" +
          "MIICmzCCAYMCBgFav/9NbDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMTcwMzEyMDA0OTI0WhcNMjcwMzEyMDA1MTA0WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgROc+Y3nnEEmNHM39yzfQ7Mn2iWS14tU1GPN1PEU7JG1Lai8N/N2GE71fNRxMxsiwI4Bm1K3wr7rK8FfKk5Ji8jvkRR3KmaRwrUqim2pjkoQFDUrCFa4/shZDR+yFTAPqMjVBYN8bF8z+HfgW8Sf/S0nvXE3Y/xMjZhqfC4NmCix2hvH88C+UZEQEa6TgGCZ7FM6QB2cXEhRBwKSIRnYLjW4KvGJLgIR7k5f3Vor0cplXhklfq+eoweZ0Oewx075QW3E4FhmKj5rWM/hbd3snl8Z6I5peNAI6mK8qc/bJTYM91aYMzJVvruXwNED6OHQ4kUpnkfZ82ATcgjn292xHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA+RuEoZiOQGfYfXVT3dE6Th3INnR3nStNuP5AQv/cNyDBwC5yLUdBABDOUaPSb6OWIY8pxGs457Fct0gzQsPuE99Zk3GDfRNOqkMA952O4Gh+Hc27NbzYfLmhPyTSTe1oKBxoYmsmBw57Vix+rOKbhLAHyVh5QXl4hhbtruLdqP6EMwL11eWykBCJ1b7gCuYjCGKpYbLKpStg2xXo9rPTd3NmmPYnpCYNrEwl76P++a4w9IcsUn2EmBu0P3njYgtxWucTq9LD5I0h4uoknZEirERkX11SjQnTzanpq8nKphRV0RdGnWWSEN438Hl1XR4zrSRlClFlN3McF4C4U4MVE=\n" +
          "-----END CERTIFICATE-----";
//      } catch (IOException e) {
//        System.err.println("Unable to load PUBLIC_KEY from PEM file!");
//      }
    }
  }
}
