package de.kctest.plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import de.kctest.required
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.html.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.pipeline.*
import kotlinx.html.*
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

fun Application.externalLoginModule() {

    class AuthErrorRedirectException(override val message: String, val redirectUri: String, val state: String) :
        RuntimeException(message)

    data class AuthSession(
        val clientId: String,
        val redirectUri: String,
        val codeChallenge: String,
        val state: String,
        val nonce: String,
        val tabId: String = UUID.randomUUID().toString(),
        val authCode: String? = null,
        val authCodeExpiresAt: Long? = null,
        val sessionId: String? = null
    ) {
        fun matchesCodeChallenge(codeVerifier: String): Boolean {
            val bytes = codeVerifier.toByteArray(Charsets.US_ASCII)
            val messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.size);
            val digest = messageDigest.digest();
            val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return this.codeChallenge == codeChallenge
        }


        val isValid: Boolean get() = System.currentTimeMillis() < (authCodeExpiresAt ?: 0)
    }


    data class LoginSession(
        val user: String,
        val id: String = UUID.randomUUID().toString(),
        val expiresAt: Long = System.currentTimeMillis() + 1.hours.inWholeMilliseconds
    ) {
        val isValid: Boolean get() = System.currentTimeMillis() < expiresAt
    }


    val loginSessionMap = ConcurrentHashMap<String, LoginSession>()
    val authCodeMap = ConcurrentHashMap<String, AuthSession>()
    val signSecret = "geheim"
    val issuer = "tk-login"


    install(ContentNegotiation) {
        jackson()
    }

    install(StatusPages) {
        exception { call: ApplicationCall, cause: AuthErrorRedirectException ->
            call.respondRedirect {
                takeFrom(cause.redirectUri)
                parameters.append("error", cause.message)
                parameters.append("state", cause.state)
            }
        }

        exception { call: ApplicationCall, cause: IllegalStateException ->
            call.respond(HttpStatusCode.BadRequest, cause.message ?: "unknown")
        }
    }

    fun pruneMaps() {
        loginSessionMap.values.removeIf { !it.isValid }
        authCodeMap.values.removeIf { !it.isValid }
    }

    fun createAccessToken(audience: String, user: String, timeout: Long) = JWT.create()
        .withAudience(audience)
        .withIssuer(issuer)
        .withClaim("username", user)
        .withExpiresAt(Date(System.currentTimeMillis() + timeout))
        .sign(Algorithm.HMAC256(signSecret))

    fun createIdToken(sid: String, audience: String, user: String, nonce: String, timeout: Long) = JWT.create()
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
        .withExpiresAt(Date(System.currentTimeMillis() + timeout))
        .sign(Algorithm.HMAC256(signSecret))


    suspend fun ApplicationCall.redirectAuthCodeToClient(authSession: AuthSession, loginSession: LoginSession) {

        val code = UUID.randomUUID().toString()
        authCodeMap[code] = authSession.copy(
            authCode = code,
            authCodeExpiresAt = System.currentTimeMillis() + 1.minutes.inWholeMilliseconds,
            sessionId = loginSession.id
        )

        respondRedirect {
            takeFrom(authSession.redirectUri)
            parameters.append("code", code)
            parameters.append("state", authSession.state)
        }
    }

    routing {
        route("tk") {

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
            intercept(ApplicationCallPipeline.Call) {
                pruneMaps()
            }
            get("/auth") {
                val clientId = call.parameters.required("client_id")
                val redirectUri = call.parameters.required("redirect_uri")
                val state = call.parameters.required("state")
                val nonce = call.parameters.required("nonce")
                val codeChallenge = call.parameters.required("code_challenge")
                val codeChallengeMethod = call.parameters.required("code_challenge_method")
                val responseType = call.parameters.required("response_type")

                assert(codeChallengeMethod == "S256")
                assert(responseType == "Code")


                val authSession = AuthSession(clientId, redirectUri, codeChallenge, state, nonce)
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
                                    input {
                                        name = "TabId"
                                        type = InputType.hidden
                                        value = authSession.tabId
                                    }
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
                val tabId = parameters.required("tabId")
                val user = parameters.required("user")
                val authSession = call.sessions.get<AuthSession>() ?: throw IllegalStateException("AuthSession Missing")
                if (authSession.tabId != tabId) {
                    throw AuthErrorRedirectException("Invalid_tabId", authSession.redirectUri, authSession.state)
                }
                call.sessions.clear<AuthSession>()
                val loginSession = LoginSession(user)
                loginSessionMap[loginSession.id] = loginSession
                call.sessions.set(loginSession)

                this@externalLoginModule.log.info("login success ${loginSession.id} ${loginSession.user}")
                call.redirectAuthCodeToClient(authSession, loginSession)
            }

            post("/token") {
                val parameters = call.receiveParameters()
                val code = parameters.required("code")
                val codeVerifier = parameters.required("code_verifier")
                val authSession = authCodeMap.remove(code) ?: throw IllegalStateException("Code invalid")
                if (!authSession.isValid) {
                    throw IllegalStateException("Code timeout")
                }
                if (!authSession.matchesCodeChallenge(codeVerifier)) {
                    throw IllegalStateException("PKCE failure")
                }

                val loginSession =
                    loginSessionMap.get(authSession.sessionId) ?: throw IllegalStateException("Session not found")
                if (!loginSession.isValid) {
                    throw IllegalStateException("Session timeout")
                }

                val accessExpiresIn = 5.minutes.inWholeMilliseconds
                val accessToken = createAccessToken(
                    authSession.clientId,
                    loginSession.user,
                    accessExpiresIn
                )
                val idToken = createIdToken(
                    loginSession.id,
                    authSession.clientId,
                    loginSession.user,
                    authSession.nonce,
                    60.minutes.inWholeMilliseconds
                )

                val tokens = mapOf<String, Any>(
                    "access_token" to accessToken,
                    "expires_in" to accessExpiresIn,

                    "token_type" to "Bearer",
                    "id_token" to idToken
                )

                call.respond(tokens)
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

}
