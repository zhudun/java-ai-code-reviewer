package com.example.shop;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final Map<String, User> cache = new HashMap<>();
    private final UserRepository userRepository = new UserRepository();

    public String displayName(Long id) {
        Optional<User> optional = userRepository.findById(id);
        User user = optional.get();
        return user.getName().equals("admin") ? "管理员" : user.getName();
    }

    public int bonus(Long id) {
        User user = userRepository.findById(id).orElse(null);
        Integer points = user.getPoints();
        int value = points;
        return value * 2;
    }

    public void remember(String key, User user) {
        if (!cache.containsKey(key)) {
            cache.put(key, user);
        }
    }

    public void createOrder(OrderRequest request) {
        save(request);
    }

    @Transactional
    private void save(OrderRequest request) {
        userRepository.save(request);
        try {
            userRepository.updateBalance(request.getUserId(), request.getAmount());
        } catch (Exception ex) {
            // swallow
        }
    }

    public static class User {
        private String name;
        private Integer points;

        public String getName() {
            return name;
        }

        public Integer getPoints() {
            return points;
        }
    }

    public static class OrderRequest {
        private Long userId;
        private Long amount;

        public Long getUserId() {
            return userId;
        }

        public Long getAmount() {
            return amount;
        }
    }

    public static class UserRepository {
        public Optional<User> findById(Long id) {
            return Optional.empty();
        }

        public void save(OrderRequest request) {
        }

        public void updateBalance(Long userId, Long amount) {
        }
    }
}
