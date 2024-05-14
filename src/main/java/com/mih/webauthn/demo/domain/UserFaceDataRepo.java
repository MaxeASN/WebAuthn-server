package com.mih.webauthn.demo.domain;

import org.springframework.data.repository.CrudRepository;

public interface UserFaceDataRepo extends CrudRepository<UserFaceData, Long> {
    UserFaceData findUserFaceDataByAppUserId(Long appUserId);
}
