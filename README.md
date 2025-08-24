# Go Authentication Server 🔐

Hello! 👋
I'm currently learning Golang and building this **authentication server** as a hands-on project to understand backend development with  **Golang**, the **Gin framework**, and **GORM** for database interactions.
It’s designed to help me (and others) learn backend development while implementing real-world authentication flows.

---

## 🎯 Why an Authentication Server?

An **authentication server** is a crucial component in modern web applications.  
It acts as a **gatekeeper**, verifying the identity of users before granting access to protected resources or data.  

Without it, any user could potentially access sensitive information or perform unauthorized actions.  

This server provides:

- **User Registration & Login** → Securely handles user creation and sign-in.  
- **Password Hashing** → Protects user passwords by storing them in an encrypted (hashed) format, not plain text.  
- **Token-Based Authentication** → Issues **JWTs** (access & refresh tokens) upon successful login.  
- **Multi-Factor Authentication (MFA)** → Adds an extra layer of security by requiring OTP verification.  

---

## 🚀 How This Auth Server Works

This server implements a robust authentication flow, supporting both **standard login** and **Multi-Factor Authentication (MFA)**.

### 1. Initial Login Request
- A requesting server (or frontend) sends:
  - **email & password**
  - **application name**
  - **access payload & refresh payload**  
- The auth server verifies credentials against the database.  

If valid:
- If **MFA = false** → Responds with `access token + refresh token`.  
- If **MFA = true** → Responds with `temp_code` and sends an **OTP** to the user’s email.  

---

### 2. MFA Flow
If MFA is enabled:
1. Auth server responds with a `temp_code` and sends an OTP to the user’s email.  
2. The frontend sends back the **OTP + temp_code** for verification.  
3. If OTP is valid → Auth server issues a **new temp_code**.  
4. The requesting server exchanges this new `temp_code` for **access & refresh tokens**.  

If MFA is **not** enabled:
- The server directly responds with tokens on the first successful login.  

---

## ▶️ Getting Started

Here's how to get your Go authentication server up and running:

1. Clone the repository
git clone <your-repository-url>
cd <your-project-directory>

2. Initialize Go modules
go mod init <your-module-name> # e.g., go mod init auth-server

3. Install dependencies
go get ./...

4. Create a .env file
At the root of your project. This file will hold your critical configuration:

- PORT=8080
- DB_URL="Your Database URL"
- JWT_SECRET="YOUR_ACCESS_TOKEN_SECRET"
- REFRESH_SECRET="YOUR_REFRESH_TOKEN_SECRET"
- EMAIL="YOUR_SENDER_EMAIL@example.com"
- EMAIL_PASSWORD="YOUR_EMAIL_APPLICATION_PASSWORD" # For Google, use an App Password

**Important**: Remember to replace placeholder values with your actual credentials. For Google, you'll need to generate an App Password as your EMAIL_PASSWORD if you're using Gmail SMTP, as direct password access is often disabled.

5. Run the server
go run main.go
