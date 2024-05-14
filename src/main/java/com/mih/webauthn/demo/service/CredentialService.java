package com.mih.webauthn.demo.service;

import java.io.IOException;
import java.util.List;

public interface CredentialService {
    List<String> findAllByAppUserId(long appUserId);

    void deleteCredential(long appUserId, String publicKeyCose) throws IOException;
}
