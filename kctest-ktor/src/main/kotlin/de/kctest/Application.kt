package de.kctest

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import de.kctest.plugins.*

fun main() {
    embeddedServer(Netty, port = 9090, host = "0.0.0.0") {
        configureRouting()
    }.start(wait = true)
}
