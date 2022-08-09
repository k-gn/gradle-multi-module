package com.example.sociallogin.repository.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.example.sociallogin.entity.user.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findUserByUsername(String username);

	Optional<User> findUserByUserId(Long userId);

	@Modifying
	@Transactional
	@Query("UPDATE User u SET u.refreshToken = :refreshToken WHERE u.userId = :userId")
	void updateUserRefreshTokenByUserId(
		@Param("userId") Long userId,
		@Param("refreshToken") String refreshToken
	);

	Optional<User> findUserByRefreshToken(String refreshToken);
}
