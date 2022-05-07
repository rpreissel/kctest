/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.e2.kctest.identityprovider;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.*;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.vault.VaultStringSecret;
import twitter4j.Twitter;
import twitter4j.TwitterFactory;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;
import twitter4j.conf.ConfigurationBuilder;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.*;
import java.net.URI;

public class TKIdentityProvider extends AbstractIdentityProvider<TKIdentityProviderModel> {

    protected static final Logger logger = Logger.getLogger(TKIdentityProvider.class);

    private static final String TWITTER_TOKEN = "twitter_token";
    private static final String TWITTER_TOKENSECRET = "twitter_tokenSecret";

    public TKIdentityProvider(KeycloakSession session, TKIdentityProviderModel config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(realm, callback, event);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
            URI authenticationUrl = URI.create("http://localhost:9090/");
            return Response.seeOther(authenticationUrl).build();
    }

    protected class Endpoint {
        protected RealmModel realm;
        protected AuthenticationCallback callback;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        public Endpoint(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
            this.realm = realm;
            this.callback = callback;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam("state") String state,
                                     @QueryParam("denied") String denied,
                                     @QueryParam("oauth_verifier") String verifier) {
             return callback.cancelled();
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        authSession.setUserSessionNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, (String)context.getContextData().get(IdentityProvider.FEDERATED_ACCESS_TOKEN));

    }

}
