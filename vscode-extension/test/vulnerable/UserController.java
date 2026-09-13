// Ch3ck3r SAST Vulnerable Test — Java Spring Boot
// Deliberate security flaws for detection testing

package com.ch3ck3r.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import java.sql.ResultSet;
import java.sql.Statement;

@RestController
@RequestMapping("/api")
public class UserController {

    // 🔴 CWE-798 Hardcoded secret
    private final String JWT_SECRET = "my_secret_key_123";

    @Autowired
    private JdbcTemplate jdbc;

    // 🔴 CWE-285 Missing authorization
    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUser(@PathVariable String id) {
        // 🔴 CWE-89 SQL Injection
        String query = "SELECT * FROM users WHERE id = " + id;
        Statement stmt = null;
        ResultSet rs = stmt.executeQuery(query);

        // 🔴 CWE-200 Expose sensitive data
        return ResponseEntity.ok(new UserResponse(
            rs.getString("username"),
            rs.getString("password"),  // 🔴 password exposed
            rs.getString("ssn")         // 🔴 SSN exposed
        ));
    }

    // 🔴 CWE-639 IDOR — no ownership check
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id) {
        jdbc.execute("DELETE FROM users WHERE id = " + id);
        return ResponseEntity.ok().build();
    }

    // 🔴 CWE-918 SSRF
    @PostMapping("/proxy")
    public ResponseEntity<?> proxy(@RequestBody ProxyRequest req) {
        RestTemplate rest = new RestTemplate();
        String result = rest.getForObject(req.getUrl(), String.class);
        return ResponseEntity.ok(result);
    }

    // 🔴 CWE-915 Mass assignment
    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable String id, @RequestBody User user) {
        jdbc.update("UPDATE users SET ? WHERE id = ?", user, id);
        return ResponseEntity.ok().build();
    }

    // 🔴 CWE-78 Command injection
    @GetMapping("/exec")
    public ResponseEntity<?> exec(@RequestParam String cmd) throws Exception {
        Runtime rt = Runtime.getRuntime();
        Process pr = rt.exec(cmd);
        return ResponseEntity.ok(new String(pr.getInputStream().readAllBytes()));
    }

    // 🔴 CWE-22 Path traversal
    @GetMapping("/files")
    public ResponseEntity<?> readFile(@RequestParam String path) throws Exception {
        java.io.File file = new java.io.File("/data/" + path);
        // No validation
        return ResponseEntity.ok(new String(java.nio.file.Files.readAllBytes(file.toPath())));
    }
}
