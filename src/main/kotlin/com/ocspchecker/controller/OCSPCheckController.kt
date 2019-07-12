package com.ocspchecker.controller

import com.ocspchecker.dao.OCSPCheck
import com.ocspchecker.db.CheckRepository
import com.ocspchecker.network.AcceptAllHostnameVerifier
import com.ocspchecker.network.AcceptAllTrustManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.*
import java.net.URL
import java.util.*
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext


@RestController
class OCSPCheckController {

    private val logger: Logger = LoggerFactory.getLogger(javaClass)

    @Autowired
    lateinit var repository: CheckRepository

    @PostMapping("/check")
    fun post(@RequestBody check: OCSPCheck): OCSPCheck {

        logger.debug("sent JSON $check")

        val check = OCSPCheck(
                publicId = UUID.randomUUID().toString(),
                domain = check.domain,
                startTime = System.currentTimeMillis())

        val sc = SSLContext.getInstance("SSL")
        sc.init(null, arrayOf(AcceptAllTrustManager { certs, trusted ->
            check.trusted = trusted
            check.certificates = certs
        }), java.security.SecureRandom())

        HttpsURLConnection.setDefaultSSLSocketFactory(sc.socketFactory)
        HttpsURLConnection.setDefaultHostnameVerifier(AcceptAllHostnameVerifier())

        val url = URL("https://" + check.domain)
        val con = url.openConnection() as HttpsURLConnection
        con.requestMethod = "GET"
        con.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36")
        con.connectTimeout = 5000
        con.readTimeout = 5000
        con.instanceFollowRedirects = false

        try {
            logger.debug("response code ${con.responseCode}")
        }
        catch(e:Exception) {
            logger.error("could not connect to server: $e")
        }
        finally {
            con.disconnect()
        }

        check.endTime = System.currentTimeMillis()
        logger.debug("request took " + (check.endTime - check.startTime))

        repository.save(check)

        return check
    }

    @GetMapping("/check/{id}")
    fun get(@PathVariable("id") id: String): OCSPCheck {
        return repository.findByPublicId(id)
    }



}

