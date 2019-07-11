package com.ocspchecker.dao

import com.fasterxml.jackson.annotation.JsonIgnore
import java.net.URI
import java.security.cert.X509Certificate
import javax.persistence.*
import javax.persistence.FetchType



@Entity
@Table(name = "OCSP_CHECK", indexes = [Index(name = "OCSP_CHECK_INDEX_PUBLIC_ID", columnList = "publicId")])
data class OCSPCheck(
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @JsonIgnore
        val id: Long = 0,
        val publicId: String = "",
        val domain: String = "",
        @OneToMany(cascade = [CascadeType.ALL])
        @JoinColumn(name="OCSP_CHECK_ID")
        var certificates: List<Certificate> = emptyList(),
        var trusted: Boolean = false,
        var startTime: Long = 0,
        var endTime: Long = 0)

@Entity
@Table(name = "CERTIFICATE")
data class Certificate(
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @JsonIgnore
        val id: Long = 0,
        val subject: String = "",
        @ElementCollection
        @CollectionTable(name="ALTERNATIVE_NAME")
        val alternativeNames: List<String> = emptyList(),
        val serialNumber: String = "",
        val validFrom: Long = 0,
        val validTo: Long = 0,
        val keyAlgorithm: String = "",
        val issuer: String = "",
        val signatureAlgorithm: String = "",
        val type: CertificateType = CertificateType.UNKNOWN,
        val mustStaple: Boolean = false,
        val ocspResponderUrl: String = "",
        var ocspRevocationState: OCSPRevocationState = OCSPRevocationState.UNKNOWN
) {
    @JsonIgnore
    @ManyToOne
    lateinit var ocspCheck: OCSPCheck
}

@Embeddable
enum class OCSPRevocationState {
    GOOD,
    REVOKED,
    UNKNOWN
}


@Embeddable
enum class CertificateType {
    UNKNOWN,
    DV,
    EV,
    OV
}