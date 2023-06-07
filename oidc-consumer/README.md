# OIDC-Consumer (TS)

This module provides and OpenId Connect Consumer that takes care of managing the OAuth-flow between your servers and your IDP.

## Table of Contents

<!-- toc -->

- [Installation](#installation)
- [How to use](#how-to-use)
  - [Initiate](#initiate)
  - [Consume](#consume)
    - [For OAuth-Flow](#oauth-flow)
      - [with sessions](#with-sessions)
      - [without sessions](#without-sessions)
    - [For Token Management](#token-management)
      - [Refresh a Token](#refresh-token)
      - [Revoke a Token](#revoke-token)

<!-- tocstop -->

## Installation

```sh
npm install @fundwave/oidc-consumer # comes prepackaged with types
```

## How to use

1. ### Initiate

   Initiate an consumer-client by passing a configuration:

   ```js
   const oidcConsumer = new OidcConsumer({
     scope: "openid profile email",
     callback_route: "/register",
     clientConfig: {
       client: {
         id: CLIENT_ID,
         secret: CLIENT_SECRET,
       },
       auth: {
         tokenHost: "https://example.site.com",
         tokenPath: "/auth/realms/realm-example/protocol/openid-connect/token",
         revokePath: "/auth/realms/realm-example/protocol/openid-connect/logout",
         authorizePath: "/auth/realms/realm-example/protocol/openid-connect/auth",
       },
       options: {
         authorizationMethod: "body",
       },
     },
   });
   ```

2. ### Consume

   1. #### OAuth-Flow

      1. For initiating an oauth-login flow we need to supply an entry-point on the server. You simply need to add **oidcConsumer.serve** method and it will handle the rest!

         ```js
         router.get("/authorize", oidcConsumer.serve());
         ```

         A successful login should redirect the user back to your server with their auth-code. We don't need to worry about the exchange as the library will handle that too.

         - ##### with sessions

           1. ensure that you pass in a configuration for managing your sessions; checkout [express-session](https://www.npmjs.com/package/express-session)

              ```js
                const oidcConsumer = new OidcConsumer({
                  ...
                  sessionOptions: {
                    name: "yodlee.oidc",
                    secret: SESSION_SECRETS,
                    resave: false,
                    saveUninitialized: true,
                    store: new FirestoreStore({
                      dataset: new Firestore({
                        kind: "express-sessions",
                      }),
                    }) as unknown as Store,
                  },
                });
              ```

           2. Add **oidcConsumer.parseCallback** as a middleware to the route supplied earlier @ callback_route

              ```js
              router.get("/register", oidcConsumer.parseCallback(), authenticateToken, ...);
              ```

         - ##### without sessions

           Add **oidcConsumer.parseCallback** as a middleware to the route supplied earlier @ callback_route

           ```js
           router.get("/register", oidcConsumer.authCallback, authenticateToken, ...);
           ```

      Other middlewares and handlers can be chained in the call e.g. **authenticateToken**.

      Once these handler have been prefixed, you may access the updated token at `request.headers.token`

   2. #### Token Management

      1. ##### Refresh Token

         to refresh a token, use the **.refresh** utility and pass-in the scope that the token needs to be refreshed to

         ```js
         oidcConsumer.refresh(token);
         ```

         **Note**: you may also supply a scope and the token will be refreshed to that scope only, by default it refreshed to the scope that the client was initiated with

      2. ##### Revoke Token

         to revoke a token you may use the **.revoke** by passing in the whole auth-token and wether access/refresh token are to be revoked

         ```js
         oidcConsumer.revoke(token, "all");
         ```

   3. #### Miscellaneous

      You may pass in additional **http payload** (headers, body) for token exchange calls e.g. create, refresh, revoke by passing in those options in their respective methods (.authCallback, .refresh, .revoke) as optional last params

      we use [@hapi/wreck](https://hapi.dev/module/wreck/) as our underlying http library so options being passed should conform to their standards (see "options" variable under advanced usage)

Refer to the [documentation](DOCUMENTATION.md) for more
