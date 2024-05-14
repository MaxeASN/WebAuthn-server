package com.mih.webauthn.demo.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "user_face_data")
public class UserFaceData {
    @Id
    @GeneratedValue
    private Long id;

    private Long appUserId;

    private String faceData;

    private LocalDateTime createTime;
}
