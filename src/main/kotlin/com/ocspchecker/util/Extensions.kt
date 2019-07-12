package com.ocspchecker.util

import com.ocspchecker.dao.Certificate
import com.ocspchecker.dao.CertificateType
import com.ocspchecker.dao.OCSPRevocationState
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.AccessDescription
import java.security.Principal
import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName


fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

private fun X509Certificate.getOcspUrl(): String {
    getExtensionValue("1.3.6.1.5.5.7.1.1")?.let {
        val aiaExtensionSeq = ASN1InputStream(it.inputStream())
        val derObjectString = aiaExtensionSeq.readObject() as DEROctetString
        aiaExtensionSeq.close()

        val asn1InputStream = ASN1InputStream(derObjectString.octets)
        val asn1Sequence = asn1InputStream.readObject() as ASN1Sequence
        asn1InputStream.close()

        asn1Sequence.objects.toList().forEach {
            val accessDescription = AccessDescription.getInstance(it)
            if (accessDescription.accessMethod.toString() == "1.3.6.1.5.5.7.48.1")
                return accessDescription.accessLocation.name.toString()
        }
    }

    return ""
}

fun X509Certificate.toCertificate(): Certificate =
        Certificate(
                subject = subjectDN.getField("CN"),
                alternativeNames = subjectAlternativeNames?.map { item -> item[1].toString() } ?: emptyList(),
                serialNumber = serialNumber.toString(),
                validFrom = notBefore.time,
                validTo = notAfter.time,
                keyAlgorithm = publicKey.algorithm,
                issuer = issuerDN.getField("CN"),
                signatureAlgorithm = sigAlgName,
                type = when {
                    isDV() -> CertificateType.DV
                    isOV() -> CertificateType.OV
                    isEV() -> CertificateType.EV
                    else -> CertificateType.UNKNOWN
                },
                mustStaple = getExtensionValue("1.3.6.1.5.5.7.1.24")?.isNotEmpty() ?: false,
                ocspResponderUrl = getOcspUrl(),
                ocspRevocationState = OCSPRevocationState.UNKNOWN)



fun X509Certificate.isSelfSigned(): Boolean = subjectDN == issuerDN

fun X509Certificate.isDV(): Boolean = subjectDN.getField("O").isEmpty()

fun X509Certificate.isOV(): Boolean = !isEV() && !isDV()

fun X509Certificate.isEV(): Boolean =
        !isDV() &&
                subjectDN.getField("SERIALNUMBER").isNotEmpty() &&
                subjectDN.getField("OID.1.3.6.1.4.1.311.60.2.1.3").isNotEmpty() &&
                subjectDN.getField("OID.2.5.4.15").isNotEmpty()


fun Principal.getField(fieldName: String): String =
        LdapName(name).rdns.find { it.type.equals(fieldName, true) }?.value?.toString() ?: ""

