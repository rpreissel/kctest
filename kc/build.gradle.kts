plugins {
    id("org.springframework.boot") version "2.6.4"
    id("io.spring.dependency-management") version "1.0.11.RELEASE"
    id("java")
}

repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencyManagement {
    imports {
        mavenBom("com.github.thomasdarimont.embedded-spring-boot-keycloak-server:embedded-keycloak-server-spring-boot-parent:7.0.2")
    }
}

dependencies {
    implementation("com.github.thomasdarimont.embedded-spring-boot-keycloak-server:embedded-keycloak-server-spring-boot-starter:7.0.2")
}