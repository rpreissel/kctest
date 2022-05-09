package de.kctest

import io.ktor.http.*

fun Parameters.required(name: String) =
    this[name] ?: throw IllegalStateException("Parameter Missing $name")
