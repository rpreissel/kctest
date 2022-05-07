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
import kotlin.time.Duration.Companion.minutes

fun Application.configureRouting() {
    data class AuthSession(
        val clientId: String,
        val redirectUri: String,
        val state: String,
        val nonce: String
    )

    data class LoginSession(
        val user: String
    )

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

    data class CodeStorage(
        val user: String,
        val code: String,
        val tokens: TokenResponse
    )


    val codeMap = ConcurrentHashMap<String, CodeStorage>()
    val signSecret = "geheim"
    val issuer = "tk-login"

    install(Sessions) {
        cookie<AuthSession>("auth_session", SessionStorageMemory())
        cookie<LoginSession>("login_session", SessionStorageMemory())
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

    fun createIdToken(audience: String, user: String, nonce: String, timeout: Duration) = JWT.create()
        .withAudience(audience)
        .withIssuer(issuer)
        .withSubject(user)
        .withClaim("nonce", nonce)
        .withClaim("name", "name $user")
        .withClaim("given_name", "given $user")
        .withClaim("family_name", "family $user")
        .withClaim("preferred_username", user)
        .withClaim("email", "email@$user")
        .withExpiresAt(Date(System.currentTimeMillis() + timeout.inWholeMilliseconds))
        .sign(Algorithm.HMAC256(signSecret))


    suspend fun ApplicationCall.redirectToClient(authSession: AuthSession, user: String) {
        val result = TokenResponse(
            token = createAccessToken(authSession.clientId, user, 5.minutes),
            tokenType = "Bearer",
            expiresIn = Instant.now().toEpochMilli() + 10.minutes.inWholeMilliseconds,
            idToken = createIdToken(authSession.clientId, user, authSession.nonce, 60.minutes)
        )
        val codeStorage = CodeStorage(user, UUID.randomUUID().toString(), result)
        codeMap[codeStorage.code] = codeStorage

        sessions.set(LoginSession(user))

        respondRedirect {
            takeFrom(authSession.redirectUri)
            parameters.append("code", codeStorage.code)
            parameters.append("state", authSession.state)
        }
    }

    // Starting point for a Ktor app:
    routing {
        get("/") {
            call.respondText("Hello World!")
        }

        get("/auth") {
            val clientId = call.parameters.required("client_id")
            val redirectUri = call.parameters.required("redirect_uri")
            val state = call.parameters.required("state")
            val nonce = call.parameters.required("nonce")
            val authSession = AuthSession(clientId, redirectUri, state, nonce)
            val loginSession = call.sessions.get<LoginSession>()
            if(loginSession!= null) {
                call.redirectToClient(authSession, "test")
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
            val authSession = call.sessions.get<AuthSession>() ?: throw IllegalStateException("AuthSession Missing")
            call.redirectToClient(authSession, "test")
        }

        post("/token") {
            val code = call.receiveParameters().required("code")
            val codeStorage = codeMap.remove(code) ?: throw IllegalStateException("Code invalid")

            call.respond(codeStorage.tokens)
        }


    }



}



private fun Parameters.required(name: String) =
    this[name] ?: throw IllegalStateException("Parameter Missing")
