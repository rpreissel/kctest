package de.kctest.plugins

import com.auth0.jwt.JWT
import de.kctest.applicationHttpClient
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.html.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.html.*

fun Application.oAuthClientModule(context: String, name: String, secret: String) {
    data class UserSession(val name: String, val idToken: String)

    authentication {
        oauth("auth-oauth-$context") {
            urlProvider = { "http://localhost:9090/$context/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "kc",
                    authorizeUrl = "http://localhost:8080/auth/realms/tk-ext/protocol/openid-connect/auth",
                    accessTokenUrl = "http://localhost:8080/auth/realms/tk-ext/protocol/openid-connect/token",
                    requestMethod = HttpMethod.Post,
                    clientId = context,
                    clientSecret = secret,
                    defaultScopes = listOf("openid profile"),
                )
            }
            skipWhen { call -> call.sessions.get<UserSession>()!=null }
            client = applicationHttpClient
        }
    }


    routing {
        route(context) {
            install(Sessions) {
                cookie<UserSession>("user_session_$context")
            }

            authenticate("auth-oauth-$context") {
                get {
                    val userSession: UserSession = call.sessions.get() ?: throw IllegalStateException("Not logged in")
                    call.respondHtml {
                        body {
                            h1 {
                                text(name)
                            }

                            h2 {
                                text("Login Data")
                            }
                            div {
                                text(userSession.name)
                            }
                            div {
                                form(action = "/$context/close", method = FormMethod.get) {
                                    button(type = ButtonType.submit) {
                                        text("Close Client")
                                    }
                                }
                            }

                            div {
                                form(action = "/$context/logout", method = FormMethod.get) {
                                    button(type = ButtonType.submit) {
                                        text("Logout session")
                                    }
                                }
                            }
                        }
                    }
                }

                get("/callback") {
                    val principal: OAuthAccessTokenResponse.OAuth2 = call.principal() ?: throw IllegalStateException()
                    val idToken = principal.extraParameters["id_token"]?:throw IllegalStateException()
                    val username = JWT.decode(idToken).getClaim("preferred_username").asString()
                    call.sessions.set(UserSession(username, idToken))
                    call.respondRedirect("/$context")
                }

                get("/close") {
                    call.sessions.clear<UserSession>()
                    call.respondRedirect("/$context/home")
                }

                get("/logout") {
                    val userSession: UserSession = call.sessions.get() ?: throw IllegalStateException("Not logged in")
                    call.sessions.clear<UserSession>()

                    call.respondRedirect {
                        takeFrom("http://localhost:8080/auth/realms/tk-ext/protocol/openid-connect/logout")
                        parameters.append("post_logout_redirect_uri", "http://localhost:9090/$context/home")
                        parameters.append("id_token_hint", userSession.idToken)
                    }
                }
            }

            get("home") {
                call.respondRedirect("/")
            }

            get("start") {
                call.sessions.clear<UserSession>()
                call.respondRedirect("/$context")
            }
        }
    }


}
