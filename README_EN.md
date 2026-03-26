# CF-M365-Admin

A community-friendly **Microsoft 365 (Office 365) self-service provisioning and lightweight admin panel** powered by **Cloudflare Workers + Microsoft Graph API**.  
Serverless, fast to deploy, and practical for labs, internal self-service, demos, or small-to-mid teams.

> Note: This is a technical tool, not an “account distribution service”. You are responsible for compliance (see Disclaimer).

---

## 📸 Screenshots / Demo

### Example 1: Main Interface / Function Demonstration
![Homepage Example](img/首页示例.png)
*Note: This is the default homepage example (invitation code registration interface) displayed to users.

### Example 2: Backend Interface / Management Display
![Management Example](img/管理示例.png)
*Note: This is an example of the management interface, used for managing existing users, global settings, invitation codes, and other functions.

---

## ✨ What’s New (Current Release)

### ✅ Frontend (User Side)
- Self-service Microsoft 365 user registration
- Subscription options show remaining quantity, e.g. `E1 (Remaining: 200)`
- Subscription list automatically sorted by remaining quantity (highest first)
- **Password policy**: Uppercase / lowercase / numbers / symbols — **3 of 4**, length ≥ 8  
  - Real-time frontend validation; blocked if invalid (saves compute/API calls)
- **Reserved/protected usernames are forbidden** (local-part level, e.g. `admin`, `root`)  
  - Hard-blocked with a strong warning modal
- Mobile-first UX: no horizontal scrolling, no overflow tables, viewport-safe modals

### ✅ Admin Panel
- Custom admin path (reduce scanning/noise)
- Admin login with **username + password** (session cookie)
- “Globals” management (Tenant / Client / Secret / domain / SKU mapping)
- “Fetch SKU” button becomes available only after TenantId/ClientId/ClientSecret are provided
- User management: search/pagination/sorting, bulk reset password, bulk delete
- Invitation codes: generate/export/delete, restrict by Global+SKU, usage limits
- License view: total/used/remaining; optionally shows subscription lifecycle/expiration date (if permitted)
- **Protected usernames**: reserved for security; **cannot be registered or deleted** via UI/API
- Fully responsive UI; modals and toolbars optimized for mobile

---

## 🧩 Legacy vs Current & Migration Guide (Read This)

This section explains what changed and how to migrate smoothly.

### 1) Configuration model (Legacy env vars → Current KV + setup wizard)
Legacy versions are typically configured via Workers environment variables like `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `DEFAULT_DOMAIN`, `ADMIN_TOKEN`, `SKU_MAP`, etc.  
Current version introduces **a setup wizard + KV-based configuration**, which is better for multiple globals, invitations, and settings.

**Migration tips:**
- If you only have one tenant: create a single Global in the admin panel and copy values from your legacy env vars.
- If you used `SKU_MAP`: use “Fetch SKU” to rebuild and manage SKU mapping in the admin panel (no need to store large JSON in env vars).

### 2) Admin authentication (Legacy token query → Current username/password login)
Legacy admin entry is often ` /admin?token=ADMIN_TOKEN `.  
Current version uses `/{adminPath}/login` with **username + password** and a session cookie.

**Migration tips:**
- Run the setup wizard once to set admin credentials and admin path.
- For production environments, consider placing the admin path behind Cloudflare Access or WAF rules.

### 3) Protection rules (Legacy full UPN protection → Current reserved usernames / local-part protection)
Legacy `HIDDEN_USER` typically protects a full UPN (exact match).  
Current version standardizes to **reserved usernames** (local-part, e.g. `admin`). This prevents “first deploy got hijacked” scenarios.

**Migration tips:**
- If you previously protected `admin@tenant.onmicrosoft.com`, add `admin` to the protected username list.
- If you have multiple domains: local-part protection protects all `admin@*` automatically.

### 4) Subscription UX (Legacy “type only” → Current “remaining + sort”)
Legacy versions emphasize SKU mapping and license usage queries.  
Current version shows remaining quantity on the homepage and sorts the list by availability.

**Security note:**
- Remaining quantity is rendered server-side without exposing admin querying APIs to the frontend.

### 5) Mobile UX (Legacy overflow risk → Current responsive/viewport-safe)
Current release fixes: overflow tables, oversized modals, huge close buttons, and bulky toolbar layout on mobile.

---

## 🛠️ Prerequisites (Kept from Legacy)

You will need (same as legacy):  
1. A **Cloudflare account** (Workers + KV / variables)  
2. **Microsoft 365 Global Admin** privilege (to create an App Registration)  
3. An **Azure AD / Entra ID App Registration**:
   - `Client ID`, `Tenant ID`
   - `Client Secret` (use the Value, not the Secret ID)  
   - Graph API **Application permissions** + Admin consent  

> Start with minimal permissions: `User.ReadWrite.All`.  
> For subscription lifecycle/expiration display you may also need `Directory.Read.All` or `Organization.Read.All`.

---

## ⚙️ Deploy to Cloudflare Workers (Current)

### 1) Create KV Namespace
Workers → KV → Create namespace  
Recommended:
- `CONFIG_KV`

### 2) Create Durable Object
Workers → Durable Objects → Create namespace  
Recommended class/binding:
- `InviteCoordinator`
- `INVITE_COORDINATOR`

### 3) Create/Update Worker
Paste `worker.js`  script into your Worker and deploy.

### 4) Bind Resources
Worker Settings → Bindings  
- KV namespace bindings:
  - `CONFIG_KV`
- Durable Object bindings:
  - `INVITE_COORDINATOR` → `InviteCoordinator`

### 5) Optional env var (hard “silent protection”)
- `HIDDEN_USER`: comma-separated **reserved usernames** (local-part only)  
  - Example: `admin,root,superadmin`

> Legacy releases rely heavily on env vars (e.g. `SKU_MAP`, `ADMIN_TOKEN`, etc.).  
> Current release recommends managing config in KV via the setup wizard and admin panel.

---

## 🚀 Quick Start

1. Deploy Worker and bind both `CONFIG_KV` and `INVITE_COORDINATOR`
2. Visit your Worker domain to open the setup wizard
3. Configure:
   - Admin username
   - Admin password
   - Admin path (e.g. `/admin` or `/console`)
4. Open admin panel → create a Global (Tenant) and fill Tenant/Client/Secret/domain
5. Click “Fetch SKU” to build SKU mapping
6. (Optional) Enable invitation-only mode and generate invite codes
7. Test the homepage registration flow (including on mobile)

---

## 📖 Usage

### User Side
- Visit the homepage
- Select a subscription (shows remaining; sorted by availability)
- Enter username & password (3-of-4 rule enforced client-side)
- Reserved usernames are blocked with a strong warning modal

### Admin Side
- Visit `https://your-domain/{adminPath}/login`
- Manage globals, users, invites, settings, and security controls

---

## 🧯 Troubleshooting

- **404 on admin pages**: you probably changed the admin path — use the new one
- **“Fetch SKU” disabled**: ensure TenantId/ClientId/ClientSecret are filled
- **No subscription expiration date**: permissions likely missing — verify Graph app permissions + Admin consent
- **Remaining quantity looks stale**: it is server-rendered; switching globals triggers refresh

---

## ⚠️ Disclaimer

This project is provided as an open-source technical tool. You are responsible for ensuring your deployment and usage comply with applicable laws and the terms/policies of Microsoft, Cloudflare, and any other relevant providers.  
The authors and contributors are not liable for any direct or indirect damages arising from the use, misuse, or abuse of this project, including account suspension, tenant restrictions, service disruption, data loss, licensing/compliance risks, or legal consequences.  
If you plan to use it in an organization or commercial context, we recommend performing a security review, applying least-privilege permissions, and protecting admin routes with additional access controls (e.g., Cloudflare Access).

---

## License

MIT License
