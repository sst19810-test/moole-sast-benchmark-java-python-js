package com.infigroup.vulnapp.repository;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Data-access layer. The string-building query methods are terminal SINKs for
 * SQL-injection taint that originates in the controllers and is forwarded by
 * the service layer (cross-file flow).
 */
@Repository
public class UserRepository {

    private final DataSource dataSource;
    private final JdbcTemplate jdbc;

    public UserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
        this.jdbc = new JdbcTemplate(dataSource);
    }

    /** SINK (CWE-89): builds a Statement from a concatenated SQL string. */
    public List<String> searchByName(String name) {
        List<String> out = new ArrayList<>();
        String sql = "SELECT username FROM users WHERE username LIKE '%" + name + "%'";
        try (Connection c = dataSource.getConnection();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                out.add(rs.getString("username"));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    /** SINK (CWE-89): tainted id concatenated into the WHERE clause. */
    public String findEmailById(String id) {
        String sql = "SELECT email FROM users WHERE id = " + id;
        try (Connection c = dataSource.getConnection();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString("email") : null;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /** Control sample: parameterized query (should NOT be flagged). */
    public List<String> searchByNameSafe(String name) {
        return jdbc.queryForList(
                "SELECT username FROM users WHERE username LIKE ?",
                String.class, "%" + name + "%");
    }
}
