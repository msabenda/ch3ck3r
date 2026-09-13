// Ch3ck3r SAST Vulnerable Test — Go
// Deliberate security flaws for detection testing

package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os/exec"
    "strings"

    "github.com/gorilla/mux"
    _ "github.com/lib/pq"
)

// 🔴 CWE-798 Hardcoded credentials
const (
    DB_USER     = "admin"
    DB_PASSWORD = "password123"
    JWT_SECRET  = "secret"
    API_KEY     = "sk-live-abcdef123456"
)

var db *sql.DB

// 🔴 CWE-285 Missing auth + CWE-862 No auth check
func GetUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["id"]

    // 🔴 CWE-89 SQL Injection
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
    rows, _ := db.Query(query)

    // 🔴 CWE-200 Expose sensitive fields
    type User struct {
        ID       int    `json:"id"`
        Username string `json:"username"`
        Password string `json:"password"`
        SSN      string `json:"ssn"`
    }
    var users []User
    for rows.Next() {
        var u User
        rows.Scan(&u.ID, &u.Username, &u.Password, &u.SSN)
        users = append(users, u)
    }
    json.NewEncoder(w).Encode(users)
}

// 🔴 CWE-918 SSRF
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
    var body struct{ URL string }
    json.NewDecoder(r.Body).Decode(&body)

    // 🔴 CWE-918 No validation on URL
    resp, _ := http.Get(body.URL)
    defer resp.Body.Close()
    data, _ := ioutil.ReadAll(resp.Body)
    w.Write(data)
}

// 🔴 CWE-78 Command injection
func ExecHandler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    // 🔴 CWE-78 Shell=True via sh -c
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}

// 🔴 CWE-22 Path traversal
func ReadFileHandler(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("path")
    data, _ := ioutil.ReadFile("/data/" + path)
    w.Write(data)
}

// 🔴 CWE-639 IDOR — no ownership check
func DeleteUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["id"]
    db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %s", userID))
    w.Write([]byte("deleted"))
}

// 🔴 CWE-215 Debug mode enabled via Gin
func main() {
    r := mux.NewRouter()
    r.HandleFunc("/api/users/{id}", GetUser).Methods("GET")
    r.HandleFunc("/api/users/{id}", DeleteUser).Methods("DELETE")
    r.HandleFunc("/api/proxy", ProxyHandler).Methods("POST")
    r.HandleFunc("/api/exec", ExecHandler).Methods("GET")
    r.HandleFunc("/api/read", ReadFileHandler).Methods("GET")
    r.HandleFunc("/api/admin/export", AdminExport).Methods("GET")
    http.ListenAndServe(":8080", r)
}

func AdminExport(w http.ResponseWriter, r *http.Request) {
    // 🔴 CWE-285 No role check on admin endpoint
    rows, _ := db.Query("SELECT * FROM users")
    json.NewEncoder(w).Encode(rows)
}
