package de.kctest

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import de.kctest.plugins.*
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.html.*
import io.ktor.server.routing.*
import kotlinx.html.*

val applicationHttpClient = HttpClient(CIO) {
    install(ContentNegotiation) {
        json()
    }
}
fun main() {
    embeddedServer(Netty, port = 9090, host = "0.0.0.0") {
        externalLoginModule()
        oAuthClientModule("client1","Client 1", "iJfGmUCHhjOj9FXeLwGizChcqcbhBTAZ")
        oAuthClientModule("client2","Client 2", "RG85Ok6H35XcM6allFx5rHr31aH6ZWcp")

        routing {
            get {
                call.respondHtml {
                    body {
                        h1 {
                            text("Clients: Fordern automatisch Login an")
                        }
                        ul {
                            li {
                                a(href = "client1/start") {
                                    text("Client 1")
                                }
                            }
                            li {
                                a(href = "client2/start") {
                                    text("Client 2")
                                }
                            }
                        }
                    }
                }
            }
        }
    }.start(wait = true)
}
