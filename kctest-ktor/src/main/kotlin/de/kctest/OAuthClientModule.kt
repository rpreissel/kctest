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
                    defaultScopes = listOf("openid profile")
                )
            }
            client = applicationHttpClient
        }
    }

    data class UserSession(val token: String)

    routing {
        route(context) {
            install(Sessions) {
                cookie<UserSession>("user_session_$context")
            }

            authenticate("auth-oauth-$context") {
                get("/login") {
                    // Redirects to 'authorizeUrl' automatically
                }

                get("/callback") {
                    val principal: OAuthAccessTokenResponse.OAuth2 = call.principal() ?: throw IllegalStateException()
                    val username = JWT.decode(principal.extraParameters["id_token"]).getClaim("preferred_username").asString()
                    call.sessions.set(UserSession(username))
                    call.respondRedirect("/$context/hello")
                }
            }
            get {
                call.respondHtml {
                    body {
                        h1 {
                            text(name)
                        }

                        h2 {
                            text("Login")
                        }
                        div {
                            form(action = "/$context/login", method = FormMethod.get) {
                                button(type = ButtonType.submit) {
                                    text("Login")
                                }
                            }
                        }
                    }
                }
            }

            get("/hello") {
                val userSession: UserSession? = call.sessions.get()
                if (userSession != null) {
                    call.respondText("Hello, ${userSession.token}!")
                } else {
                    call.respondRedirect("/$context")
                }
            }
        }
    }


}
