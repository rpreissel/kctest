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
    }.start(wait = true)
}
