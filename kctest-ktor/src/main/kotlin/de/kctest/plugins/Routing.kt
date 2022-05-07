package de.kctest.plugins

import io.ktor.server.routing.*
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.html.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*
import kotlinx.html.*
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.minutes

fun Application.configureRouting() {
    data class AuthSession(val redirectUri: String, val state: String)
    data class CodeStorage(val code: String, val tokens: OAuthAccessTokenResponse.OAuth2)

    val codeMap = ConcurrentHashMap<String, CodeStorage>()


    install(Sessions) {
        cookie<AuthSession>("auth_session", SessionStorageMemory())
    }
    install(ContentNegotiation) {
        jackson()
    }
    // Starting point for a Ktor app:
    routing {
        get("/") {
            call.respondText("Hello World!")
        }

        get("/auth") {
            val redirectUri = call.parameters.required("redirect_uri")
            val state = call.parameters.required("state")
            call.sessions.set(AuthSession(redirectUri, state))
            call.respondHtml {
                body {
                    h1 {
                        text("TK Login")
                    }

                    h2{
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

                    h2{
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

        post("/login") {
            val authSession = call.sessions.get<AuthSession>() ?: throw IllegalStateException("AuthSession Missing")

            val result = OAuthAccessTokenResponse.OAuth2(
                accessToken = "token",
                tokenType = "Bearer",
                expiresIn = Instant.now().toEpochMilli() + 10.minutes.inWholeMilliseconds,
                refreshToken = null
            )
            val codeStorage =  CodeStorage(UUID.randomUUID().toString(), result)
            codeMap[codeStorage.code] = codeStorage

            call.respondRedirect {
                takeFrom(authSession.redirectUri)
                parameters.append("code", codeStorage.code)
                parameters.append("state", authSession.state)
            }
        }

        post("/token") {
            val code = call.receiveParameters().required("code")
            val codeStorage = codeMap.remove(code) ?: throw IllegalStateException("Code invalid")
            call.respond(codeStorage.tokens)
        }
    }
    routing {
    }
}

private fun Parameters.required(name: String) =
    this[name] ?: throw IllegalStateException("Parameter Missing")
