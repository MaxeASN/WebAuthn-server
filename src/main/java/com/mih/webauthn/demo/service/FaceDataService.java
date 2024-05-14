package com.mih.webauthn.demo.service;

import java.util.List;

public interface FaceDataService {
    void importFaceDate(long userId, String faceData);

    List<String> queryAllFaceData();

    boolean isImported(long userId);

    String queryOneFaceData(Long id);
}
