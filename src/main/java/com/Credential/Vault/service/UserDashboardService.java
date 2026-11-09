
package com.Credential.Vault.service;

import com.Credential.Vault.dto.UserDashboardResponse;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserDashboardService {

    private final UserRepository userRepository;

    public UserDashboardService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDashboardResponse getDashboard(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new RuntimeException("User not found"));

        return new UserDashboardResponse(
                user.getName(),
                user.getEmail(),
                user.getRole().name(),
                user.getActive(),
                0,
                0,
                0
        );
    }
}
