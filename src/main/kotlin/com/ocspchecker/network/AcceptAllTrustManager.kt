package com.ocspchecker.network

import com.ocspchecker.dao.Certificate
import com.ocspchecker.dao.OCSPRevocationState
import com.ocspchecker.util.toCertificate
import com.ocspchecker.util.toHexString
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.ocsp.*
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.BufferedOutputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.security.KeyStore
import java.security.Principal
import java.security.Security
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

class AcceptAllTrustManager(private val certListener: (certs: List<Certificate>, trusted: Boolean) -> Unit) : X509ExtendedTrustManager() {

    private val logger: Logger = LoggerFactory.getLogger(javaClass)
    private val trustManager: X509TrustManager

    init {
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as KeyStore?)
        trustManager = trustManagerFactory.trustManagers.find { it is X509TrustManager } as X509TrustManager?
                ?: throw CertificateException("No X509TrustManager found")
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, engine: Socket?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?, engine: Socket?) {

        val trusted = try {
            trustManager.checkServerTrusted(chain, authType)
            true
        } catch (e: CertificateException) {
            false
        }


        //find root certificate
        val root= trustManager.acceptedIssuers.find { chain?.last()?.issuerDN == it.subjectDN }


        val deferredOcspState = mutableListOf<Deferred<OCSPRevocationState>>()
        val certificates = chain?.map {
            val cert = it.toCertificate()
            deferredOcspState.add(GlobalScope.async { ocspRequest(it, findIssuerCert(it.issuerDN, chain, root), cert.ocspResponderUrl) })
            cert
        } ?: emptyList()


        runBlocking {
            certificates.forEachIndexed { i, cert ->
                cert.ocspRevocationState = deferredOcspState[i].await()
            }
        }

        certListener(certificates, trusted)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }


    private fun findIssuerCert(issuerDN: Principal, chain: Array<X509Certificate>, root: X509Certificate?): X509Certificate? {
        val issuerCert = chain.find { issuerDN == it.subjectDN }
        return if (issuerCert == null && root?.subjectDN == issuerDN) root else issuerCert
    }


    private fun ocspRequest(userCert: X509Certificate, issuerCert: X509Certificate?, url: String): OCSPRevocationState {
        if (issuerCert == null || url.isBlank()) return OCSPRevocationState.UNKNOWN

        val startTime = System.currentTimeMillis()

        logger.debug("OCSP request for cert " + userCert.signature.toHexString() + ", issuer cert: " + issuerCert.signature.toHexString())

        val certID = this.generateCertificateIdForRequest(userCert.serialNumber, issuerCert)
        val builder = OCSPReqBuilder()
        builder.addRequest(certID)


        val request = builder.build()
        val response = try {
            this.sendOCSPReq(request, url)
        } catch (e: Exception) {
            null
        }

        logger.debug("ocsp response took " + (System.currentTimeMillis() - startTime))

        return when (response?.status) {
            OCSPResponseStatus.INTERNAL_ERROR -> {
                logger.debug("INTERNAL ERROR")
                OCSPRevocationState.UNKNOWN
            }
            OCSPResponseStatus.MALFORMED_REQUEST -> {
                logger.debug("MALFORMED_REQUEST")
                OCSPRevocationState.UNKNOWN
            }
            OCSPResponseStatus.SIG_REQUIRED -> {
                logger.debug("SIG_REQUIRED")
                OCSPRevocationState.UNKNOWN
            }
            OCSPResponseStatus.TRY_LATER -> {
                logger.debug("TRY_LATER")
                OCSPRevocationState.UNKNOWN
            }
            OCSPResponseStatus.UNAUTHORIZED -> {
                logger.debug("UNAUTHORIZED")
                OCSPRevocationState.UNKNOWN
            }
            OCSPResponseStatus.SUCCESSFUL -> {
                logger.debug("SUCCESSFUL")

                val basicOCSPResponse = response.responseObject as BasicOCSPResp

                val singleResponse = Arrays.stream(basicOCSPResponse.responses)
                        .filter { singleResp -> singleResp.certID.equals(request.requestList[0].certID) }
                        .findFirst()


                if (singleResponse.get().certStatus == null) {
                    logger.debug("CERTIFICATE NOT REVOKED")
                    OCSPRevocationState.GOOD
                } else {
                    val certificateStatus = singleResponse.get().certStatus as RevokedStatus
                    if (certificateStatus.hasRevocationReason())
                        logger.debug("REVOKED " + certificateStatus.revocationReason)
                    else
                        logger.debug("REVOKED NO REASON")

                    OCSPRevocationState.REVOKED
                }

            }
            else -> OCSPRevocationState.UNKNOWN
        }


    }


    private fun generateCertificateIdForRequest(userCertSerialNumber: BigInteger, issuerCert: X509Certificate): CertificateID {
        Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        return CertificateID(
                JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                JcaX509CertificateHolder(issuerCert), userCertSerialNumber)
    }


    private fun sendOCSPReq(request: OCSPReq, url: String): OCSPResp {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.setRequestProperty("Content-Type", "application/ocsp-request")
        connection.setRequestProperty("Accept", "application/ocsp-response")
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        connection.doOutput = true

        logger.debug("Sending OCSP request to $url")


        val outputStream = DataOutputStream(BufferedOutputStream(connection.outputStream))
        outputStream.write(request.encoded)
        outputStream.flush()
        outputStream.close()

        logger.debug("OCSP request response code and msg " + connection.responseCode + " " + connection.responseMessage)
        if (connection.responseCode != HttpURLConnection.HTTP_OK) {
            logger.debug("OCSP request has been failed (HTTP ${connection.responseCode}) - {${connection.responseMessage}")
        }

        //return (connection.content as InputStream).use { OCSPResp(it) }
        return connection.inputStream.use { OCSPResp(it) }
    }
}

