package com.ocspchecker.dao

import com.fasterxml.jackson.annotation.JsonIgnore
import javax.persistence.*


@Entity
@Table(name = "ocsp_check", indexes = [Index(name = "ocsp_check_index_public_id", columnList = "publicId")])
data class OCSPCheck(
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @JsonIgnore
        val id: Long = 0,
        val publicId: String = "",
        val domain: String = "",
        @OneToMany(cascade = [CascadeType.ALL])
        @JoinColumn(name="ocsp_check_id")
        var certificates: List<Certificate> = emptyList(),
        var trusted: Boolean = false,
        var startTime: Long = 0,
        var endTime: Long = 0)

@Entity
@Table(name = "certificate", indexes = [Index(name = "certificate_index_ocsp_revocation_state", columnList = "ocspRevocationState")])
data class Certificate(
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @JsonIgnore
        val id: Long = 0,
        val subject: String = "",
        @ElementCollection
        @CollectionTable(name="alternative_name", joinColumns = [JoinColumn(name = "certificate_id")])
        val alternativeNames: List<String> = emptyList(),
        val serialNumber: String = "",
        val validFrom: Long = 0,
        val validTo: Long = 0,
        val keyAlgorithm: String = "",
        val issuer: String = "",
        val signatureAlgorithm: String = "",
        @Enumerated(EnumType.STRING)
        val type: CertificateType = CertificateType.UNKNOWN,
        val mustStaple: Boolean = false,
        val ocspResponderUrl: String = "",
        @Enumerated(EnumType.STRING)
        var ocspRevocationState: OCSPRevocationState = OCSPRevocationState.UNKNOWN
) {
    @JsonIgnore
    @ManyToOne
    lateinit var ocspCheck: OCSPCheck
}