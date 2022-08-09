package com.example.sociallogin.entity.user;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.hibernate.annotations.DynamicUpdate;

import com.example.sociallogin.constants.Auth;
import com.example.sociallogin.constants.LoginType;
import com.example.sociallogin.entity.common.BaseEntity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@DynamicUpdate
public class User extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Long userId;

	@Column(name = "user_name")
	private String username;

	@Column(name = "user_password")
	private String password;

	@Column(name = "user_role")
	@Enumerated(EnumType.STRING)
	private Auth role;

	@Column(name = "user_login_type")
	@Enumerated(EnumType.STRING)
	private LoginType loginType;

	@Column(name = "refresh_token")
	private String refreshToken;
}
