package com.mih.webauthn.demo.service.impl;

import com.mih.webauthn.demo.domain.CustomCredentialsRepository;
import com.mih.webauthn.demo.service.CredentialService;
import io.github.webauthn.jpa.JpaWebAuthnCredentials;
import io.github.webauthn.jpa.WebAuthnCredentialsSpringDataRepository;
import org.java_websocket.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CredentialServiceImpl implements CredentialService {
    @Autowired
    private CustomCredentialsRepository customCredentialsRepository;

    @Autowired
    private WebAuthnCredentialsSpringDataRepository credentialsSpringDataRepository;

    @Override
    public List<String> findAllByAppUserId(long appUserId) {
        return credentialsSpringDataRepository.findAllByAppUserId(appUserId).stream()
                .map((JpaWebAuthnCredentials credential) -> Numeric.toHexString(credential.getPublicKeyCose()))
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void deleteCredential(long appUserId, String publicKeyCose) throws IOException {
        customCredentialsRepository.deleteByAppUserIdAndPublicKeyCose(appUserId, Numeric.hexStringToByteArray(publicKeyCose));
    }
}
