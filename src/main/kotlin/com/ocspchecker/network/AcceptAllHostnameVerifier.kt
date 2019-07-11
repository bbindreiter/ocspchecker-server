package com.ocspchecker.network

import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSession


class AcceptAllHostnameVerifier: HostnameVerifier {

    override fun verify(hostname: String?, session: SSLSession?): Boolean = true
}

