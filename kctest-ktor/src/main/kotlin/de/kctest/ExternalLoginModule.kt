package de.kctest.plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.fasterxml.jackson.annotation.JsonProperty
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.html.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.html.*
import java.time.Instant
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

fun Application.externalLoginModule() {
    data class AuthSession(
        val clientId: String,
        val redirectUri: String,
        val state: String,
        val nonce: String
    )

    data class LoginSession(
        val user: String,
        val id: String = UUID.randomUUID().toString(),
        val expiresAt: Long = System.currentTimeMillis() + 1.hours.inWholeMilliseconds
    ) {
        val isValid: Boolean get() = System.currentTimeMillis() < expiresAt
    }

    class TokenResponse(
        @JsonProperty("access_token")
        val token: String? = null,

        @JsonProperty("expires_in")
        val expiresIn: Long = 0,

        @JsonProperty("refresh_expires_in")
        val refreshExpiresIn: Long = 0,

        @JsonProperty("refresh_token")
        val refreshToken: String? = null,

        @JsonProperty("token_type")
        val tokenType: String? = null,

        @JsonProperty("id_token")
        val idToken: String? = null
    )

    val loginSessionMap = ConcurrentHashMap<String, LoginSession>()
    val authCodeMap = ConcurrentHashMap<String, TokenResponse>()
    val signSecret = "geheim"
    val issuer = "tk-login"

    install(Sessions) {
        cookie<AuthSession>("auth_session", SessionStorageMemory()) {
            cookie.httpOnly = true
            cookie.maxAge = 5.minutes
        }
        cookie<LoginSession>("login_session", SessionStorageMemory()) {
            cookie.httpOnly = true
            cookie.maxAge = 1.hours
        }
    }
    install(ContentNegotiation) {
        jackson()
    }

    fun createAccessToken(audience: String, user: String, timeout: Duration) = JWT.create()
        .withAudience(audience)
        .withIssuer(issuer)
        .withClaim("username", user)
        .withExpiresAt(Date(System.currentTimeMillis() + timeout.inWholeMilliseconds))
        .sign(Algorithm.HMAC256(signSecret))

    fun createIdToken(sid: String, audience: String, user: String, nonce: String, timeout: Duration) = JWT.create()
        .withAudience(audience)
        .withIssuer(issuer)
        .withSubject(user)
        .withClaim("sid", sid)
        .withClaim("nonce", nonce)
        .withClaim("name", "name $user")
        .withClaim("given_name", "given $user")
        .withClaim("family_name", "family $user")
        .withClaim("preferred_username", user)
        .withClaim("email", "email@$user")
        .withExpiresAt(Date(System.currentTimeMillis() + timeout.inWholeMilliseconds))
        .sign(Algorithm.HMAC256(signSecret))


    fun newLoginSession(user: String): LoginSession {
        val loginSession = LoginSession(user)
        loginSessionMap[loginSession.id] = loginSession

        loginSessionMap.values.removeIf { !it.isValid}

        return loginSession
    }

    suspend fun ApplicationCall.redirectAuthCodeToClient(authSession: AuthSession, loginSession: LoginSession) {
        val tokens = TokenResponse(
            token = createAccessToken(authSession.clientId, loginSession.user, 5.minutes),
            tokenType = "Bearer",
            expiresIn = Instant.now().toEpochMilli() + 10.minutes.inWholeMilliseconds,
            idToken = createIdToken(loginSession.id, authSession.clientId, loginSession.user, authSession.nonce, 60.minutes)
        )
        val code = UUID.randomUUID().toString()
        authCodeMap[code] = tokens

        respondRedirect {
            takeFrom(authSession.redirectUri)
            parameters.append("code", code)
            parameters.append("state", authSession.state)
        }
    }

    routing {
         get("/auth") {
            val clientId = call.parameters.required("client_id")
            val redirectUri = call.parameters.required("redirect_uri")
            val state = call.parameters.required("state")
            val nonce = call.parameters.required("nonce")
            val authSession = AuthSession(clientId, redirectUri, state, nonce)
            val loginSession = call.sessions.get<LoginSession>()
            if (loginSession != null && loginSessionMap.get(loginSession.id)?.isValid ?: false) {
                this@externalLoginModule.log.info("SSO login")
                call.redirectAuthCodeToClient(authSession, loginSession)
            } else {
                call.sessions.set(authSession)
                call.respondHtml {
                    body {
                        h1 {
                            text("TK Login")
                        }

                        h2 {
                            text("Parameter")
                        }
                        div {
                            p {
                                text("Redirect-Uri: $redirectUri")
                            }

                            p {
                                text("state: $state")
                            }
                        }

                        h2 {
                            text("Login")
                        }
                        div {
                            form(action = "login", method = FormMethod.post) {
                                select {
                                    name = "user"
                                    option {
                                        label = "Max"
                                        value = "Max"
                                        selected = true
                                    }

                                    option {
                                        label = "Anne"
                                        value = "Anne"
                                    }
                                }
                                button(type = ButtonType.submit) {
                                    text("Login")
                                }
                            }
                        }
                    }
                }
            }

        }

        post("/login") {
            val parameters = call.receiveParameters()
            val user = parameters.required("user")
            val authSession = call.sessions.get<AuthSession>() ?: throw IllegalStateException("AuthSession Missing")
            call.sessions.clear<AuthSession>()
            val loginSession = newLoginSession(user)
            call.sessions.set(loginSession)
            this@externalLoginModule.log.info("login success ${loginSession.id} ${loginSession.user}")
            call.redirectAuthCodeToClient(authSession, loginSession)
        }

        post("/token") {
            val code = call.receiveParameters().required("code")
            val tokenResponse = authCodeMap.remove(code) ?: throw IllegalStateException("Code invalid")

            call.respond(tokenResponse)
        }

        get("/logout") {
            val idTokenHint = call.parameters.required("id_token_hint")
            val decodedIdToken = JWT.decode(idTokenHint)
            val sessionIdFromToken =
                decodedIdToken.getClaim("sid")?.asString() ?: throw IllegalStateException("sid missing")
            val redirectUri = call.parameters.get("post_logout_redirect_uri")
            val state = call.parameters.required("state")
            val loginSessionFromCookie = call.sessions.get<LoginSession>()
            if (loginSessionFromCookie != null) {
                if (sessionIdFromToken != loginSessionFromCookie.id) {
                    throw IllegalStateException("Wrong sid")
                }
                if (decodedIdToken.subject != loginSessionFromCookie.user) {
                    throw IllegalStateException("Wrong User Id")
                }
                call.sessions.clear<LoginSession>()
            }
            val loginSessionFromMap = loginSessionMap.remove(sessionIdFromToken)
            if (loginSessionFromMap != null) {
                this@externalLoginModule.log.info("logout $sessionIdFromToken ${loginSessionFromMap.user}")
            }

            if (redirectUri != null) {
                call.respondRedirect {
                    takeFrom(redirectUri)
                    parameters.append("state", state)
                }
            } else {
                call.respond(HttpStatusCode.OK)
            }

        }


    }


}


private fun Parameters.required(name: String) =
    this[name] ?: throw IllegalStateException("Parameter Missing")
