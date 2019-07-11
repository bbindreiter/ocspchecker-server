package com.ocspchecker.db

import com.ocspchecker.dao.OCSPCheck
import org.springframework.data.repository.CrudRepository

interface CheckRepository: CrudRepository<OCSPCheck, Long> {
    fun findByPublicId(id: String): OCSPCheck
}