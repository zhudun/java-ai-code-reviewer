package com.example.shop;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class PaymentDao {

    public long findBalance(String userId) throws Exception {
        Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/shop", "root", "root");
        Statement statement = connection.createStatement();
        String sql = "SELECT balance FROM account WHERE user_id = '" + userId + "'";
        ResultSet rs = statement.executeQuery(sql);
        if (rs.next()) {
            return rs.getLong(1);
        }
        return 0L;
    }

    public void nativeSearch(String keyword, javax.persistence.EntityManager em) {
        String jpql = String.format("SELECT p FROM Payment p WHERE p.note = '%s'", keyword);
        em.createNativeQuery("SELECT * FROM payment WHERE note = '" + keyword + "'").getResultList();
        em.createQuery(jpql).getResultList();
    }
}
