package com.mih.webauthn.demo.service.impl;

import com.mih.webauthn.demo.domain.UserFaceData;
import com.mih.webauthn.demo.domain.UserFaceDataRepo;
import com.mih.webauthn.demo.service.FaceDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class FaceDataServiceImpl implements FaceDataService {
    @Autowired
    private UserFaceDataRepo faceDataRepo;

    @Override
    public void importFaceDate(long userId, String faceData) {
        UserFaceData faceDataEntity = new UserFaceData();
        faceDataEntity.setAppUserId(userId);
        faceDataEntity.setFaceData(faceData);
        faceDataEntity.setCreateTime(LocalDateTime.now());
        faceDataRepo.save(faceDataEntity);
    }

    @Override
    public List<String> queryAllFaceData() {
        List<String> resultList = new ArrayList<>();
        faceDataRepo.findAll().forEach((UserFaceData faceData)-> resultList.add(faceData.getFaceData()));
        return resultList;
    }

    @Override
    public boolean isImported(long userId) {
        return false;
    }

    @Override
    public String queryOneFaceData(Long id) {
        UserFaceData userFaceData = faceDataRepo.findUserFaceDataByAppUserId(id);
        if(userFaceData == null){
            return "";
        }
        return userFaceData.getFaceData();
    }
}
