# RSLogin License Verification Server

Dedicated License Validation API Server for the **RSLogin** Minecraft authentication plugin.
Built for zero-config, 1-click deployment on **[Render](https://render.com/)**.

---

## 🚀 Quick Deploy to Render

### Option A: Via Render Dashboard (Recommended)

1. Go to your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** -> **Web Service**.
3. Select **Build and deploy from a Git repository**.
4. Connect and choose your private repository: `redsignalofficial/RSLOGIN-LICENSE`.
5. Configure the service settings:
   - **Name**: `rslogin-license`
   - **Region**: Choose closest to your server (e.g., Singapore, Frankfurt, Oregon)
   - **Branch**: `main`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Instance Type**: `Free`
6. Under **Environment Variables**, add:
   - `ADMIN_SECRET`: A secure password for your admin endpoints (e.g., `MySecretAdminPass2026!`)
   - `SECRET_SIGN_KEY`: A random string used for cryptographic signing.
7. Click **Create Web Service**.
8. Once deployed, Render will provide your public URL (e.g. `https://rslogin-license.onrender.com`).

---

## 🔑 Default Master License

On first launch, the server initializes with a default key:
```
RS-DEFAULT-PREMIUM-KEY-2026
```

You can use this immediately or create new ones using the Admin API below.

---

## 📡 API Endpoints

### 1. Health Check
* **`GET /health`** or **`GET /`**
  * Verifies server is online.

### 2. Validate License (Used by RSLogin Plugin)
* **`POST /api/license/validate`**
  * **Headers**: `Content-Type: application/json`
  * **Body**:
    ```json
    {
      "license_key": "RS-DEFAULT-PREMIUM-KEY-2026",
      "product": "rslogin-paper",
      "server_ip": "1.2.3.4",
      "port": 25565
    }
    ```
  * **Response (Valid)**:
    ```json
    {
      "valid": true,
      "status": "ACTIVE",
      "license_key": "RS-DEFAULT-PREMIUM-KEY-2026",
      "owner": "ServerOwner",
      "tier": "PREMIUM",
      "expires_at": null,
      "timestamp": 1730620000,
      "signature": "...",
      "message": "License is valid and verified."
    }
    ```

---

## 🛠 Admin Management API
All admin routes require the header:
`Authorization: Bearer <YOUR_ADMIN_SECRET>`

### 1. Generate a New Random License Key
```bash
curl -X POST https://your-app.onrender.com/api/admin/licenses/generate \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "CustomerName",
    "tier": "PREMIUM",
    "ip_lock": false,
    "expires_at": null,
    "note": "Purchased Nov 2026"
  }'
```

### 2. List All Licenses
```bash
curl -X GET https://your-app.onrender.com/api/admin/licenses \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

### 3. Suspend or Update a License
```bash
curl -X PUT https://your-app.onrender.com/api/admin/licenses/RS-XXXX-XXXX-XXXX-XXXX \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "SUSPENDED"
  }'
```

### 4. Delete a License
```bash
curl -X DELETE https://your-app.onrender.com/api/admin/licenses/RS-XXXX-XXXX-XXXX-XXXX \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

---

## ⚙️ Connecting to RSLogin Plugin

In your `rslogin-paper` `config.yml` (and/or Velocity `config.properties`):
```yaml
license:
  enabled: true
  key: "RS-DEFAULT-PREMIUM-KEY-2026"
  server-url: "https://your-license-server.onrender.com"
  disable-on-invalid: true
  check-interval-hours: 12
```
