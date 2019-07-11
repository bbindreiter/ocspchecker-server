package com.ocspchecker

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class OCSPCheckerApplication

fun main(args: Array<String>) {
	runApplication<OCSPCheckerApplication>(*args)
}
