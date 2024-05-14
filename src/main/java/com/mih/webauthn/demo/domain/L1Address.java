package com.mih.webauthn.demo.domain;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "l1_address")
public class L1Address {
    @Id
    @GeneratedValue
    private Long id;

    private Long appUserId;

    @Column(name = "l1_address")
    private String l1Address;

    private LocalDateTime createTime;

    private Boolean deleted;
}
