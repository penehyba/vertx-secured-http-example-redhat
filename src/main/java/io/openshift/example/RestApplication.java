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

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.authorization.MicroProfileAuthorization;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.JWTAuthHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.openshift.example.service.Greeting;
import org.apache.commons.io.IOUtils;

import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;

public class RestApplication extends AbstractVerticle {

  private long counter;

  private static final String CLIENT_ID = System.getenv("CLIENT_ID");
  private static final String CLIENT_SECRET = System.getenv("SECRET");
  private static final String SITE = System.getenv("SSO_AUTH_SERVER_URL");
  private static final String REALM = System.getenv("REALM");
  private static String PUBLIC_KEY;

  public static void loadPublicKey() {
    PUBLIC_KEY = System.getenv("REALM_PUBLIC_KEY");
    if (PUBLIC_KEY == null) {
      System.err.println("PUBLIC_KEY loaded from REALM_PUBLIC_KEY is null, reading PEM file.");
      try {
        PUBLIC_KEY = IOUtils.toString(Paths.get("target", "test-classes", "public.pem").toFile().toURI(), Charset.defaultCharset());
      } catch (IOException e) {
        System.err.println("Unable to load PUBLIC_KEY from PEM file!");
      }
    }
  }

  @Override
  public void start(Promise<Void> done) {

    loadPublicKey();
    Router router = initRouter();
    initJwtRouter(router);
    initKeycloakJsonRoute(router);

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

  private Router initRouter(){
    Router router = Router.router(getVertx());
    router.get("/health").handler(routingContext -> {
      routingContext.response().setStatusCode(200).end("OK");
    });
    router.get().handler(StaticHandler.create());
    return router;
  }

  private void initJwtRouter(Router router){
    JsonObject config = new JsonObject()
      // since we're consuming keycloak JWTs we need
      // to locate the permission claims in the token
      .put("permissionsClaimKey", "realm_access/roles");
    JWTAuthHandler jwtAuthHandler = JWTAuthHandler.create(JWTAuth.create(vertx,
       new JWTAuthOptions(config).addPubSecKey(new PubSecKeyOptions().setAlgorithm("RS256").setBuffer(PUBLIC_KEY))));
    router.route("/api/greeting").handler(jwtAuthHandler);
    router.get("/api/greeting").handler(ctx -> {
      AuthorizationProvider authorizationProvider = MicroProfileAuthorization.create();
      authorizationProvider.getAuthorizations(ctx.user(), voidAsyncResult -> {
        if(voidAsyncResult.succeeded() & PermissionBasedAuthorization.create("booster-admin").match(ctx.user())) {
          ctx.next();
        } else {
          System.err.println("AuthZ failed for JWT!");
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
  }

  private void initKeycloakJsonRoute(Router router){
    JsonObject keycloakJson = new JsonObject()
      .put("realm", REALM)
      .put("realm-public-key", PUBLIC_KEY)
      .put("auth-server-url", SITE)
      .put("ssl-required", "external")
      .put("resource", CLIENT_ID)
      .put("credentials", new JsonObject()
        .put("secret", CLIENT_SECRET));
    router.get("/keycloak.json").handler(ctx ->
      ctx.response()
        .putHeader(CONTENT_TYPE, "application/json; charset=utf-8")
        .end(keycloakJson.encode()));
  }
}
