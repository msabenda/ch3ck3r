# Ch3ck3r SAST Vulnerable Test — Ruby
# Deliberate security flaws for detection testing

require 'sinatra'
require 'pg'
require 'json'
require 'open-uri'

# 🔴 CWE-798 Hardcoded secrets
API_KEY = 'sk-live-abcdefghijklmnopqrstuvwxyz'
DB_PASSWORD = 'password123'
JWT_SECRET = 'my_jwt_secret'

# 🔴 CWE-285 Missing auth check
get '/api/users/:id' do
  user_id = params[:id]

  # 🔴 CWE-89 SQL Injection
  result = db.exec("SELECT * FROM users WHERE id = #{user_id}")

  # 🔴 CWE-200 Expose sensitive fields
  result.map { |u| { username: u['username'], password: u['password'], ssn: u['ssn'] } }.to_json
end

# 🔴 CWE-639 IDOR — no ownership check
delete '/api/users/:id' do
  db.exec("DELETE FROM users WHERE id = #{params[:id]}")
  { deleted: true }.to_json
end

# 🔴 CWE-918 SSRF
post '/api/proxy' do
  body = JSON.parse(request.body.read)
  url = body['url']

  # No URL validation — SSRF risk
  open(url) { |f| f.read }
end

# 🔴 CWE-78 Command injection
post '/api/exec' do
  cmd = params[:cmd]
  `#{cmd}`  # Backtick execution
end

# 🔴 CWE-22 Path traversal
get '/api/read' do
  path = params[:path]
  File.read("/data/#{path}")
end

# 🔴 CWE-915 Mass assignment
post '/api/users' do
  body = JSON.parse(request.body.read)
  # Directly passes all params
  User.create(body).to_json
end

# 🔴 CWE-215 Debug mode
set :show_exceptions, true
