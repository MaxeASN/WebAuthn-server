package com.mih.webauthn.demo.domain;

import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import org.springframework.data.repository.CrudRepository;

public interface CustomCredentialsRepository extends CrudRepository<JpaWebAuthnCredentials, Long> {
    void deleteByAppUserIdAndPublicKeyCose(Long appUserId, byte[] publicKeyCose);

}
