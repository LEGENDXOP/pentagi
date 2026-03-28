package providers

import "strings"

// Remediation holds a structured fix suggestion for a vulnerability type.
type Remediation struct {
	VulnType     string        // Canonical vulnerability type key matching ComplianceMappings
	Title        string        // Short human-readable title
	Description  string        // General fix approach
	CodeExamples []CodeExample // Language-specific fix patterns
	References   []string      // Links to OWASP, CWE, and other authoritative docs
}

// CodeExample provides a before/after code pattern in a specific language/framework.
type CodeExample struct {
	Language    string // "python", "node", "go", "php", "java"
	Framework   string // e.g. "django", "express", "gin", "laravel", "spring"
	BadCode     string // Vulnerable code example
	FixedCode   string // Secure code example
	Explanation string // Why the fix works
}

// RemediationDB maps canonical vulnerability type keys to their remediation guidance.
// Every key in ComplianceMappings should have a corresponding entry here.
var RemediationDB = map[string]Remediation{

	// ─── A01:2021 – Broken Access Control ───────────────────────────────

	"idor": {
		VulnType:    "idor",
		Title:       "Insecure Direct Object Reference (IDOR)",
		Description: "Always verify that the authenticated user is authorized to access the requested resource. Never rely solely on client-supplied identifiers. Implement ownership checks at the data-access layer.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `def get_invoice(request, invoice_id):
    invoice = Invoice.objects.get(id=invoice_id)
    return JsonResponse(invoice.to_dict())`,
				FixedCode: `def get_invoice(request, invoice_id):
    invoice = get_object_or_404(
        Invoice, id=invoice_id, owner=request.user
    )
    return JsonResponse(invoice.to_dict())`,
				Explanation: "Filter by owner so users can only access their own resources.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});`,
				FixedCode: `app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});`,
				Explanation: "Query includes userId from the authenticated session, preventing access to other users' orders.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/639.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
		},
	},

	"auth_bypass": {
		VulnType:    "auth_bypass",
		Title:       "Authentication / Authorization Bypass",
		Description: "Enforce authentication and authorization checks on every request, including API endpoints. Use middleware or decorators consistently. Never rely on client-side checks or hidden URLs.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# Admin page with no auth check
def admin_dashboard(request):
    users = User.objects.all()
    return render(request, 'admin.html', {'users': users})`,
				FixedCode: `from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required

@login_required
@staff_member_required
def admin_dashboard(request):
    users = User.objects.all()
    return render(request, 'admin.html', {'users': users})`,
				Explanation: "Stack decorators to enforce both authentication and role-based authorization.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `// Missing auth middleware
app.get('/admin/users', async (req, res) => {
  const users = await User.find();
  res.json(users);
});`,
				FixedCode: `const { authenticate, authorize } = require('./middleware/auth');

app.get('/admin/users',
  authenticate,
  authorize('admin'),
  async (req, res) => {
    const users = await User.find();
    res.json(users);
  }
);`,
				Explanation: "Apply authentication and role-checking middleware before the route handler.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/287.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		},
	},

	"privilege_escalation": {
		VulnType:    "privilege_escalation",
		Title:       "Privilege Escalation",
		Description: "Implement role-based access control (RBAC) at the server side. Never allow users to set their own role or privilege level via request parameters. Validate permissions on every state-changing operation.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `def update_profile(request):
    data = json.loads(request.body)
    # User can set role=admin in the request body!
    request.user.role = data.get('role', request.user.role)
    request.user.name = data.get('name')
    request.user.save()`,
				FixedCode: `ALLOWED_FIELDS = {'name', 'email', 'bio'}

def update_profile(request):
    data = json.loads(request.body)
    for field, value in data.items():
        if field in ALLOWED_FIELDS:
            setattr(request.user, field, value)
    request.user.save()`,
				Explanation: "Whitelist editable fields so privileged attributes like 'role' cannot be modified by the user.",
			},
			{
				Language:  "go",
				Framework: "gin",
				BadCode: `func UpdateUser(c *gin.Context) {
    var input map[string]interface{}
    c.BindJSON(&input)
    db.Model(&user).Updates(input) // allows role override
}`,
				FixedCode: `type ProfileUpdate struct {
    Name  string ` + "`" + `json:"name" binding:"required"` + "`" + `
    Email string ` + "`" + `json:"email" binding:"required,email"` + "`" + `
}

func UpdateUser(c *gin.Context) {
    var input ProfileUpdate
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    db.Model(&user).Updates(input)
}`,
				Explanation: "Use a typed struct with only allowed fields instead of a generic map to prevent mass assignment of privileged attributes.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/269.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		},
	},

	"path_traversal": {
		VulnType:    "path_traversal",
		Title:       "Path / Directory Traversal",
		Description: "Canonicalize file paths and verify they remain within the allowed base directory. Never concatenate user input directly into file paths. Use allowlists when possible.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `@app.route('/files/<path:filename>')
def download(filename):
    return send_file(f'/data/uploads/{filename}')`,
				FixedCode: `import os

UPLOAD_DIR = os.path.realpath('/data/uploads')

@app.route('/files/<path:filename>')
def download(filename):
    safe_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not safe_path.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    return send_file(safe_path)`,
				Explanation: "Resolve the real path and verify it starts with the allowed base directory to block ../ sequences.",
			},
			{
				Language:  "go",
				Framework: "net/http",
				BadCode: `func serveFile(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    http.ServeFile(w, r, "/data/uploads/"+name)
}`,
				FixedCode: `func serveFile(w http.ResponseWriter, r *http.Request) {
    name := filepath.Clean(r.URL.Query().Get("file"))
    fullPath := filepath.Join("/data/uploads", name)
    absPath, _ := filepath.Abs(fullPath)
    if !strings.HasPrefix(absPath, "/data/uploads/") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, absPath)
}`,
				Explanation: "Clean and resolve the path, then verify it stays within the upload directory.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/22.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
		},
	},

	"cors_misconfiguration": {
		VulnType:    "cors_misconfiguration",
		Title:       "CORS Misconfiguration",
		Description: "Never reflect the Origin header as-is into Access-Control-Allow-Origin. Maintain an explicit allowlist of trusted origins. Avoid using wildcards with credentials.",
		CodeExamples: []CodeExample{
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});`,
				FixedCode: `const cors = require('cors');

const ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com'];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      cb(null, true);
    } else {
      cb(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));`,
				Explanation: "Validate the Origin against a whitelist instead of reflecting it blindly.",
			},
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# settings.py
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True`,
				FixedCode: `# settings.py
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com',
]
CORS_ALLOW_CREDENTIALS = True`,
				Explanation: "Explicitly list allowed origins instead of allowing all origins with credentials.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/942.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
		},
	},

	"mass_assignment": {
		VulnType:    "mass_assignment",
		Title:       "Mass Assignment",
		Description: "Define explicit allowlists of fields that can be set via user input. Never bind raw request bodies directly to database models. Use DTOs or form objects.",
		CodeExamples: []CodeExample{
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.put('/api/users/:id', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body);
  res.json({ success: true });
});`,
				FixedCode: `const pick = (obj, keys) => Object.fromEntries(
  keys.filter(k => k in obj).map(k => [k, obj[k]])
);

app.put('/api/users/:id', async (req, res) => {
  const allowed = pick(req.body, ['name', 'email', 'bio']);
  await User.findByIdAndUpdate(req.params.id, allowed);
  res.json({ success: true });
});`,
				Explanation: "Pick only allowed fields from the request body before updating the model.",
			},
			{
				Language:  "php",
				Framework: "laravel",
				BadCode: `public function update(Request $request, $id) {
    $user = User::findOrFail($id);
    $user->update($request->all());
}`,
				FixedCode: `public function update(Request $request, $id) {
    $user = User::findOrFail($id);
    $user->update($request->only(['name', 'email', 'bio']));
}

// Also in User model:
// protected $fillable = ['name', 'email', 'bio'];`,
				Explanation: "Use $request->only() and define $fillable on the model to restrict writable attributes.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/915.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
		},
	},

	// ─── A02:2021 – Cryptographic Failures ──────────────────────────────

	"cryptographic_failure": {
		VulnType:    "cryptographic_failure",
		Title:       "Cryptographic Failure",
		Description: "Use strong, modern cryptographic algorithms (AES-256-GCM, ChaCha20-Poly1305). Never use MD5, SHA1, DES, or RC4 for security purposes. Use well-tested libraries rather than custom implementations.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "stdlib",
				BadCode: `import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()`,
				FixedCode: `from argon2 import PasswordHasher

ph = PasswordHasher()
password_hash = ph.hash(password)

# Verification:
# ph.verify(password_hash, password)`,
				Explanation: "Use Argon2 (or bcrypt/scrypt) for password hashing — they include salt and are computationally expensive to brute-force.",
			},
			{
				Language:  "node",
				Framework: "crypto",
				BadCode: `const crypto = require('crypto');
const hash = crypto.createHash('sha1').update(password).digest('hex');`,
				FixedCode: `const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

const hash = await bcrypt.hash(password, SALT_ROUNDS);
// Verification:
// const match = await bcrypt.compare(password, hash);`,
				Explanation: "bcrypt auto-salts and uses adaptive cost factor making brute-force attacks impractical.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
			"https://cwe.mitre.org/data/definitions/327.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		},
	},

	"sensitive_data_exposure": {
		VulnType:    "sensitive_data_exposure",
		Title:       "Sensitive Data Exposure",
		Description: "Encrypt sensitive data at rest and in transit. Use TLS 1.2+ for all communications. Never log passwords, tokens, or PII. Mask sensitive fields in API responses.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# API response exposing all fields
def get_user(request, user_id):
    user = User.objects.get(id=user_id)
    return JsonResponse({
        'id': user.id, 'name': user.name,
        'email': user.email, 'ssn': user.ssn,
        'password_hash': user.password,
    })`,
				FixedCode: `SAFE_FIELDS = {'id', 'name', 'email'}

def get_user(request, user_id):
    user = User.objects.get(id=user_id)
    data = {f: getattr(user, f) for f in SAFE_FIELDS}
    return JsonResponse(data)`,
				Explanation: "Explicitly whitelist public fields. Never return password hashes, SSNs, or internal identifiers.",
			},
			{
				Language:  "go",
				Framework: "gin",
				BadCode: `type User struct {
    ID       int    ` + "`" + `json:"id"` + "`" + `
    Name     string ` + "`" + `json:"name"` + "`" + `
    Password string ` + "`" + `json:"password"` + "`" + `
    SSN      string ` + "`" + `json:"ssn"` + "`" + `
}
func getUser(c *gin.Context) { c.JSON(200, user) }`,
				FixedCode: `type UserResponse struct {
    ID   int    ` + "`" + `json:"id"` + "`" + `
    Name string ` + "`" + `json:"name"` + "`" + `
}
func getUser(c *gin.Context) {
    resp := UserResponse{ID: user.ID, Name: user.Name}
    c.JSON(200, resp)
}`,
				Explanation: "Use a separate response struct that excludes sensitive fields from serialization.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
			"https://cwe.mitre.org/data/definitions/311.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
		},
	},

	// ─── A03:2021 – Injection ───────────────────────────────────────────

	"sqli": {
		VulnType:    "sqli",
		Title:       "SQL Injection",
		Description: "Always use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use ORM query builders when available.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `@app.route('/users')
def search():
    name = request.args.get('name')
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return jsonify(cursor.fetchall())`,
				FixedCode: `@app.route('/users')
def search():
    name = request.args.get('name')
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return jsonify(cursor.fetchall())`,
				Explanation: "Parameterized queries ensure user input is treated as data, not SQL code.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.get('/users', async (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  const result = await pool.query(q);
  res.json(result.rows);
});`,
				FixedCode: `app.get('/users', async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM users WHERE name = $1',
    [req.query.name]
  );
  res.json(result.rows);
});`,
				Explanation: "Use $1 placeholders with a parameter array so the driver handles escaping.",
			},
			{
				Language:  "go",
				Framework: "database/sql",
				BadCode: `func getUser(db *sql.DB, name string) {
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    db.Query(query)
}`,
				FixedCode: `func getUser(db *sql.DB, name string) {
    db.Query("SELECT * FROM users WHERE name = $1", name)
}`,
				Explanation: "Use placeholder parameters — the database driver escapes values safely.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/89.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
	},

	"xss_stored": {
		VulnType:    "xss_stored",
		Title:       "Stored Cross-Site Scripting (XSS)",
		Description: "Sanitize and encode all user-generated content before storing and rendering. Use contextual output encoding (HTML, JS, URL, CSS). Set Content-Security-Policy headers.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# Template renders raw HTML from user
# template: {{ comment.body|safe }}
def post_comment(request):
    Comment.objects.create(body=request.POST['body'])`,
				FixedCode: `import bleach

ALLOWED_TAGS = ['b', 'i', 'a', 'p', 'br']
ALLOWED_ATTRS = {'a': ['href']}

def post_comment(request):
    clean = bleach.clean(
        request.POST['body'],
        tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS
    )
    Comment.objects.create(body=clean)
# Template: {{ comment.body }}  (auto-escaped by Django)`,
				Explanation: "Sanitize HTML on input with bleach, and rely on Django's auto-escaping on output.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.post('/comments', (req, res) => {
  db.comments.insert({ body: req.body.comment });
});
// Template: <%- comment.body %>  (unescaped EJS)`,
				FixedCode: `const DOMPurify = require('isomorphic-dompurify');

app.post('/comments', (req, res) => {
  const clean = DOMPurify.sanitize(req.body.comment);
  db.comments.insert({ body: clean });
});
// Template: <%= comment.body %>  (escaped EJS)`,
				Explanation: "Sanitize with DOMPurify before storage and use escaped template output (<%=).",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/79.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
	},

	"xss_reflected": {
		VulnType:    "xss_reflected",
		Title:       "Reflected Cross-Site Scripting (XSS)",
		Description: "Never render user-supplied URL parameters or form values without encoding. Use framework auto-escaping. Set Content-Security-Policy to restrict inline scripts.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `@app.route('/search')
def search():
    q = request.args.get('q', '')
    return f'<h1>Results for {q}</h1>'`,
				FixedCode: `from markupsafe import escape

@app.route('/search')
def search():
    q = escape(request.args.get('q', ''))
    return render_template('search.html', query=q)`,
				Explanation: "Use escape() and template auto-escaping to neutralize HTML special characters.",
			},
			{
				Language:  "php",
				Framework: "vanilla",
				BadCode: `<?php echo "Search: " . $_GET['q']; ?>`,
				FixedCode: `<?php echo "Search: " . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); ?>`,
				Explanation: "htmlspecialchars with ENT_QUOTES and UTF-8 encodes all dangerous characters.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/79.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
	},

	"xss_dom": {
		VulnType:    "xss_dom",
		Title:       "DOM-Based Cross-Site Scripting (XSS)",
		Description: "Avoid using innerHTML, document.write, or eval with untrusted data. Use textContent or safe DOM APIs. Sanitize on the client side with DOMPurify if HTML rendering is needed.",
		CodeExamples: []CodeExample{
			{
				Language:  "node",
				Framework: "browser-js",
				BadCode: `// Vulnerable DOM manipulation
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello ' + name;`,
				FixedCode: `const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').textContent = 'Hello ' + name;`,
				Explanation: "textContent sets text safely without parsing HTML, preventing script injection.",
			},
			{
				Language:  "node",
				Framework: "browser-js",
				BadCode: `// Rendering user HTML unsafely
el.innerHTML = userProvidedHTML;`,
				FixedCode: `import DOMPurify from 'dompurify';
el.innerHTML = DOMPurify.sanitize(userProvidedHTML);`,
				Explanation: "DOMPurify strips dangerous tags and attributes while preserving safe HTML.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/79.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
		},
	},

	"command_injection": {
		VulnType:    "command_injection",
		Title:       "OS Command Injection",
		Description: "Never pass user input to shell commands. Use safe APIs that accept argument lists instead of shell strings. If shell interaction is unavoidable, use strict allowlists and escape all inputs.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "stdlib",
				BadCode: `import os
def ping(host):
    os.system(f"ping -c 1 {host}")`,
				FixedCode: `import subprocess
def ping(host):
    subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, timeout=10
    )`,
				Explanation: "subprocess.run with a list avoids shell interpretation — each element is a separate argument.",
			},
			{
				Language:  "go",
				Framework: "os/exec",
				BadCode: `func ping(host string) {
    cmd := exec.Command("sh", "-c", "ping -c1 "+host)
    cmd.Run()
}`,
				FixedCode: `func ping(host string) {
    cmd := exec.Command("ping", "-c", "1", host)
    cmd.Run()
}`,
				Explanation: "Pass arguments as separate strings to exec.Command — no shell is invoked.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/78.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
		},
	},

	"ssti": {
		VulnType:    "ssti",
		Title:       "Server-Side Template Injection (SSTI)",
		Description: "Never render user input as template code. Use templates with auto-escaping and pass user data as context variables only. Use sandboxed template engines when possible.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `@app.route('/greet')
def greet():
    name = request.args.get('name')
    template = f"Hello {name}!"
    return render_template_string(template)`,
				FixedCode: `@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string("Hello {{ name }}!", name=name)`,
				Explanation: "Pass user input as a context variable so the template engine escapes it, never as template source.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `const nunjucks = require('nunjucks');
app.get('/greet', (req, res) => {
  const output = nunjucks.renderString(
    `+"`"+`Hello ${req.query.name}!`+"`"+`, {}
  );
  res.send(output);
});`,
				FixedCode: `const nunjucks = require('nunjucks');
nunjucks.configure({ autoescape: true });

app.get('/greet', (req, res) => {
  const output = nunjucks.renderString(
    'Hello {{ name }}!',
    { name: req.query.name }
  );
  res.send(output);
});`,
				Explanation: "Enable autoescape and pass user data through template variables, not string interpolation.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/1336.html",
			"https://portswigger.net/web-security/server-side-template-injection",
		},
	},

	"ldap_injection": {
		VulnType:    "ldap_injection",
		Title:       "LDAP Injection",
		Description: "Escape LDAP special characters in user input before constructing queries. Use frameworks with built-in LDAP escaping. Validate input against strict patterns.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "ldap3",
				BadCode: `from ldap3 import Connection
def find_user(conn, username):
    conn.search('dc=example,dc=com',
        f'(uid={username})')`,
				FixedCode: `from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars

def find_user(conn, username):
    safe = escape_filter_chars(username)
    conn.search('dc=example,dc=com',
        f'(uid={safe})')`,
				Explanation: "escape_filter_chars encodes LDAP meta-characters (*, (, ), \\, NUL) preventing query manipulation.",
			},
			{
				Language:  "java",
				Framework: "spring",
				BadCode: `String filter = "(uid=" + username + ")";
ctx.search("dc=example,dc=com", filter, controls);`,
				FixedCode: `import org.springframework.ldap.support.LdapEncoder;

String safe = LdapEncoder.filterEncode(username);
String filter = "(uid=" + safe + ")";
ctx.search("dc=example,dc=com", filter, controls);`,
				Explanation: "LdapEncoder.filterEncode escapes special characters per RFC 4515.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/90.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
		},
	},

	"xpath_injection": {
		VulnType:    "xpath_injection",
		Title:       "XPath Injection",
		Description: "Use parameterized XPath queries when available. Escape XPath special characters in user input. Avoid building XPath expressions via string concatenation.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "lxml",
				BadCode: `from lxml import etree
def find_user(doc, name):
    return doc.xpath(f"//user[@name='{name}']")`,
				FixedCode: `from lxml import etree
import re

def escape_xpath(value):
    return re.sub(r"['\"]", lambda m: "'" if m.group() == '"' else '"', value)

def find_user(doc, name):
    safe = escape_xpath(name)
    return doc.xpath("//user[@name=$n]", n=safe)`,
				Explanation: "Use XPath variables ($n) with lxml's parameter support to prevent injection.",
			},
			{
				Language:  "java",
				Framework: "javax.xml",
				BadCode: `String expr = "//user[@name='" + name + "']";
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.evaluate(expr, doc);`,
				FixedCode: `XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(v ->
    v.getLocalPart().equals("name") ? name : null
);
xpath.evaluate("//user[@name=$name]", doc);`,
				Explanation: "Use XPath variable resolver to bind user values safely without string concatenation.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/643.html",
			"https://owasp.org/www-community/attacks/XPATH_Injection",
		},
	},

	// ─── A04:2021 – Insecure Design ────────────────────────────────────

	"business_logic": {
		VulnType:    "business_logic",
		Title:       "Business Logic Flaw",
		Description: "Enforce business rules on the server side. Never trust client-side calculations for pricing, discounts, or workflow steps. Implement state machines for multi-step processes and validate transitions.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `def checkout(request):
    # Price comes from client-side hidden field
    total = float(request.POST['total'])
    charge_card(request.user, total)`,
				FixedCode: `def checkout(request):
    cart = Cart.objects.get(user=request.user)
    total = sum(item.product.price * item.qty for item in cart.items.all())
    charge_card(request.user, total)`,
				Explanation: "Always recalculate prices server-side from the source of truth (database) — never trust client-submitted totals.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.post('/apply-coupon', async (req, res) => {
  const { discount } = req.body; // client sends discount amount
  order.total -= discount;
  await order.save();
});`,
				FixedCode: `app.post('/apply-coupon', async (req, res) => {
  const coupon = await Coupon.findOne({
    code: req.body.code, active: true,
    expiresAt: { $gt: new Date() }
  });
  if (!coupon) return res.status(400).json({ error: 'Invalid coupon' });
  order.discount = Math.min(coupon.maxDiscount, order.total * coupon.rate);
  await order.save();
});`,
				Explanation: "Validate the coupon server-side and compute the discount from stored rules, not client input.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A04_2021-Insecure_Design/",
			"https://cwe.mitre.org/data/definitions/840.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html",
		},
	},

	"missing_rate_limit": {
		VulnType:    "missing_rate_limit",
		Title:       "Missing Rate Limiting",
		Description: "Implement rate limiting on authentication, password reset, OTP, and API endpoints. Use token bucket or sliding window algorithms. Return 429 with Retry-After header when limits are hit.",
		CodeExamples: []CodeExample{
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.post('/api/login', async (req, res) => {
  const user = await authenticate(req.body);
  res.json(user ? { token: signJWT(user) } : { error: 'bad creds' });
});`,
				FixedCode: `const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // 5 attempts per window
  standardHeaders: true,
  message: { error: 'Too many login attempts, try again later' },
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const user = await authenticate(req.body);
  res.json(user ? { token: signJWT(user) } : { error: 'bad creds' });
});`,
				Explanation: "express-rate-limit enforces per-IP request limits with automatic 429 responses.",
			},
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# No rate limiting on login view
def login_view(request):
    if authenticate(request.POST['user'], request.POST['pass']):
        login(request, user)`,
				FixedCode: `from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/15m', method='POST', block=True)
def login_view(request):
    if authenticate(request.POST['user'], request.POST['pass']):
        login(request, user)`,
				Explanation: "django-ratelimit decorator blocks IPs exceeding 5 POST requests per 15 minutes.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A04_2021-Insecure_Design/",
			"https://cwe.mitre.org/data/definitions/770.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		},
	},

	// ─── A05:2021 – Security Misconfiguration ───────────────────────────

	"security_misconfiguration": {
		VulnType:    "security_misconfiguration",
		Title:       "Security Misconfiguration",
		Description: "Disable debug mode, verbose errors, and default credentials in production. Remove unnecessary features, frameworks, and endpoints. Automate hardening with configuration management tools.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# settings.py — production
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'change-me-later'`,
				FixedCode: `import os
# settings.py — production
DEBUG = False
ALLOWED_HOSTS = ['app.example.com']
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True`,
				Explanation: "Disable debug, restrict hosts, use env vars for secrets, and enforce HTTPS for cookies.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `const app = express();
// Default error handler leaks stack traces
// No security headers`,
				FixedCode: `const helmet = require('helmet');
const app = express();

app.use(helmet());
app.disable('x-powered-by');

// Custom error handler hides internals
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});`,
				Explanation: "Helmet sets secure headers; custom error handler hides stack traces from users.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://cwe.mitre.org/data/definitions/16.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html",
		},
	},

	"file_upload": {
		VulnType:    "file_upload",
		Title:       "Unrestricted File Upload",
		Description: "Validate file type by content (magic bytes), not just extension or MIME from the client. Store uploads outside the web root. Rename files with random names. Set size limits and scan for malware.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join('static/uploads', f.filename))
    return 'OK'`,
				FixedCode: `import uuid, magic

UPLOAD_DIR = '/data/uploads'  # Outside web root
ALLOWED_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}
MAX_SIZE = 5 * 1024 * 1024  # 5MB

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f.content_length > MAX_SIZE:
        abort(413)
    content = f.read(2048)
    mime = magic.from_buffer(content, mime=True)
    if mime not in ALLOWED_TYPES:
        abort(415)
    f.seek(0)
    safe_name = f"{uuid.uuid4()}.{mime.split('/')[-1]}"
    f.save(os.path.join(UPLOAD_DIR, safe_name))
    return jsonify({'filename': safe_name})`,
				Explanation: "Check content type via magic bytes, generate random filenames, store outside web root.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `const multer = require('multer');
const upload = multer({ dest: 'public/uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ path: req.file.path });
});`,
				FixedCode: `const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');
const { v4: uuid } = require('uuid');

const upload = multer({
  dest: '/data/uploads/', // Outside public dir
  limits: { fileSize: 5 * 1024 * 1024 },
});

const ALLOWED = new Set(['image/jpeg', 'image/png', 'application/pdf']);

app.post('/upload', upload.single('file'), async (req, res) => {
  const buf = await fs.promises.readFile(req.file.path);
  const type = await fileTypeFromBuffer(buf);
  if (!type || !ALLOWED.has(type.mime)) {
    await fs.promises.unlink(req.file.path);
    return res.status(415).json({ error: 'File type not allowed' });
  }
  const safeName = uuid() + '.' + type.ext;
  await fs.promises.rename(req.file.path, '/data/uploads/' + safeName);
  res.json({ filename: safeName });
});`,
				Explanation: "Validate MIME from file content (not headers), enforce size limit, use random filenames.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://cwe.mitre.org/data/definitions/434.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
		},
	},

	// ─── A06:2021 – Vulnerable and Outdated Components ──────────────────

	"vulnerable_component": {
		VulnType:    "vulnerable_component",
		Title:       "Vulnerable and Outdated Components",
		Description: "Maintain an inventory of all dependencies and their versions. Use automated tools (npm audit, pip-audit, govulncheck, Snyk, Dependabot) to detect known vulnerabilities. Update promptly.",
		CodeExamples: []CodeExample{
			{
				Language:  "node",
				Framework: "npm",
				BadCode: `// package.json with pinned old versions and no auditing
{
  "dependencies": {
    "lodash": "4.17.15",
    "express": "4.16.0"
  }
}`,
				FixedCode: `// Run regularly:
// npm audit
// npm audit fix
// npx npm-check-updates -u

// CI pipeline (.github/workflows/audit.yml):
// - run: npm audit --audit-level=high
// - run: npx snyk test

// Enable Dependabot in .github/dependabot.yml:
// version: 2
// updates:
//   - package-ecosystem: "npm"
//     directory: "/"
//     schedule:
//       interval: "weekly"`,
				Explanation: "Automate dependency auditing in CI and enable Dependabot for automatic PRs.",
			},
			{
				Language:  "python",
				Framework: "pip",
				BadCode: `# requirements.txt — never updated
Django==2.2.0
requests==2.20.0`,
				FixedCode: `# Run regularly:
# pip-audit
# pip install --upgrade -r requirements.txt
# safety check -r requirements.txt

# In CI:
# pip-audit --strict --desc
# Pre-commit hook: pip-audit`,
				Explanation: "Use pip-audit and safety to scan for known CVEs in Python dependencies.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
			"https://cwe.mitre.org/data/definitions/1104.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		},
	},

	// ─── A07:2021 – Identification and Authentication Failures ──────────

	"broken_auth": {
		VulnType:    "broken_auth",
		Title:       "Broken Authentication",
		Description: "Enforce strong passwords, implement MFA, use secure session management, and protect against credential stuffing. Never expose session tokens in URLs.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# settings.py
AUTH_PASSWORD_VALIDATORS = []  # No password policy
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False`,
				FixedCode: `# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_ENGINE = 'django.contrib.sessions.backends.db'`,
				Explanation: "Enforce password complexity, secure session cookies with HttpOnly, Secure, and SameSite flags.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.use(session({
  secret: 'secret',
  cookie: {}
}));`,
				FixedCode: `app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000, // 30 minutes
  },
  store: new RedisStore({ client: redisClient }),
}));`,
				Explanation: "Use strong secret from env, secure cookie flags, server-side session store, and session timeout.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
			"https://cwe.mitre.org/data/definitions/287.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		},
	},

	"session_hijacking": {
		VulnType:    "session_hijacking",
		Title:       "Session Hijacking / Fixation",
		Description: "Regenerate session IDs after authentication. Set HttpOnly, Secure, and SameSite flags on session cookies. Bind sessions to client fingerprint (IP range, user-agent).",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `def login_view(request):
    user = authenticate(request, **request.POST.dict())
    if user:
        # Session ID not regenerated after login!
        request.session['user_id'] = user.id`,
				FixedCode: `from django.contrib.auth import login

def login_view(request):
    user = authenticate(request, **request.POST.dict())
    if user:
        login(request, user)  # Automatically rotates session ID`,
				Explanation: "Django's login() regenerates the session ID, preventing session fixation attacks.",
			},
			{
				Language:  "php",
				Framework: "vanilla",
				BadCode: `<?php
session_start();
if (check_password($user, $pass)) {
    $_SESSION['user'] = $user;
    // Session ID stays the same!
}`,
				FixedCode: `<?php
session_start();
if (check_password($user, $pass)) {
    session_regenerate_id(true); // Destroy old session
    $_SESSION['user'] = $user;
}`,
				Explanation: "session_regenerate_id(true) creates a new session ID and deletes the old one after login.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
			"https://cwe.mitre.org/data/definitions/384.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
		},
	},

	// ─── A08:2021 – Software and Data Integrity Failures ────────────────

	"deserialization": {
		VulnType:    "deserialization",
		Title:       "Insecure Deserialization",
		Description: "Never deserialize untrusted data with native serialization (pickle, Java ObjectInputStream, PHP unserialize). Use safe formats like JSON. If native serialization is needed, use allowlists and integrity checks.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "stdlib",
				BadCode: `import pickle
def load_session(data):
    return pickle.loads(base64.b64decode(data))`,
				FixedCode: `import json, hmac, hashlib

SECRET = os.environ['SESSION_SECRET'].encode()

def load_session(data, signature):
    expected = hmac.new(SECRET, data.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Tampered session")
    return json.loads(data)`,
				Explanation: "Use JSON instead of pickle; verify HMAC signature to detect tampering before parsing.",
			},
			{
				Language:  "java",
				Framework: "stdlib",
				BadCode: `ObjectInputStream ois = new ObjectInputStream(
    new ByteArrayInputStream(userInput));
Object obj = ois.readObject();`,
				FixedCode: `// Use JSON instead of Java serialization
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    mapper.getPolymorphicTypeValidator(),
    ObjectMapper.DefaultTyping.NON_FINAL
);
MyDTO dto = mapper.readValue(userInput, MyDTO.class);`,
				Explanation: "Replace ObjectInputStream with Jackson JSON deserialization into typed DTOs.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
		},
	},

	// ─── A09:2021 – Security Logging and Monitoring Failures ────────────

	"insufficient_logging": {
		VulnType:    "insufficient_logging",
		Title:       "Insufficient Logging and Monitoring",
		Description: "Log all authentication events, access control failures, input validation failures, and administrative actions. Use structured logging. Forward logs to a SIEM. Set up alerts for anomalies.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `def login_view(request):
    user = authenticate(request, **creds)
    if user:
        login(request, user)
    else:
        return HttpResponse('Bad creds', status=401)
    # No logging at all!`,
				FixedCode: `import logging
import structlog

logger = structlog.get_logger()

def login_view(request):
    user = authenticate(request, **creds)
    if user:
        login(request, user)
        logger.info("auth.login.success",
            user_id=user.id, ip=get_client_ip(request))
    else:
        logger.warning("auth.login.failure",
            username=creds.get('username'),
            ip=get_client_ip(request))
        return HttpResponse('Bad creds', status=401)`,
				Explanation: "Log both successful and failed auth events with structured data for SIEM ingestion.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `// No security event logging
app.post('/login', handler);`,
				FixedCode: `const winston = require('winston');
const logger = winston.createLogger({
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'security.log' }),
  ],
});

app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  if (user) {
    logger.info({ event: 'auth.success', userId: user.id, ip: req.ip });
    res.json({ token: signJWT(user) });
  } else {
    logger.warn({ event: 'auth.failure', username: req.body.username, ip: req.ip });
    res.status(401).json({ error: 'Invalid credentials' });
  }
});`,
				Explanation: "Winston writes structured JSON logs for security events, enabling SIEM parsing and alerting.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
			"https://cwe.mitre.org/data/definitions/778.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		},
	},

	// ─── A10:2021 – Server-Side Request Forgery ─────────────────────────

	"ssrf": {
		VulnType:    "ssrf",
		Title:       "Server-Side Request Forgery (SSRF)",
		Description: "Validate and allowlist URLs before making server-side requests. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x). Disable HTTP redirects or re-validate after each redirect.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `import requests

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text`,
				FixedCode: `import requests, ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    import socket
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return not any(ip in net for net in BLOCKED_NETS)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    if not is_safe_url(url):
        abort(403)
    resp = requests.get(url, allow_redirects=False, timeout=5)
    return resp.text`,
				Explanation: "Validate scheme, resolve hostname to IP, check against blocked private ranges, disable redirects.",
			},
			{
				Language:  "go",
				Framework: "net/http",
				BadCode: `func fetch(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, _ := http.Get(url)
    io.Copy(w, resp.Body)
}`,
				FixedCode: `var blockedNets = []net.IPNet{
    {IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
    {IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
    {IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
    {IP: net.ParseIP("127.0.0.0"), Mask: net.CIDRMask(8, 32)},
}

func isSafe(rawURL string) bool {
    u, err := url.Parse(rawURL)
    if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
        return false
    }
    ips, err := net.LookupIP(u.Hostname())
    if err != nil || len(ips) == 0 { return false }
    for _, n := range blockedNets {
        if n.Contains(ips[0]) { return false }
    }
    return true
}

func fetch(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    if !isSafe(target) {
        http.Error(w, "Forbidden", 403)
        return
    }
    client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    }}
    resp, _ := client.Get(target)
    io.Copy(w, resp.Body)
}`,
				Explanation: "Resolve the hostname, check the IP against blocked private ranges, and disable following redirects.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
			"https://cwe.mitre.org/data/definitions/918.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		},
	},

	// ─── Cross-category / additional types ──────────────────────────────

	"csrf": {
		VulnType:    "csrf",
		Title:       "Cross-Site Request Forgery (CSRF)",
		Description: "Use anti-CSRF tokens on all state-changing requests. Set SameSite cookie attribute to Lax or Strict. Verify Origin/Referer headers as defense-in-depth.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# views.py — CSRF protection disabled
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def transfer(request):
    send_money(request.POST['to'], request.POST['amount'])`,
				FixedCode: `# Django has CSRF middleware enabled by default
# Just use the template tag:
# <form method="post">
#   {% csrf_token %}
#   ...
# </form>

def transfer(request):
    send_money(request.POST['to'], request.POST['amount'])`,
				Explanation: "Keep Django CSRF middleware enabled and include {% csrf_token %} in every POST form.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.post('/transfer', (req, res) => {
  transferMoney(req.body.to, req.body.amount);
  res.json({ success: true });
});`,
				FixedCode: `const csrf = require('csurf');
const csrfProtection = csrf({ cookie: { sameSite: 'strict', httpOnly: true } });

app.get('/transfer', csrfProtection, (req, res) => {
  res.render('transfer', { csrfToken: req.csrfToken() });
});

app.post('/transfer', csrfProtection, (req, res) => {
  transferMoney(req.body.to, req.body.amount);
  res.json({ success: true });
});`,
				Explanation: "csurf generates and validates anti-CSRF tokens; SameSite cookie prevents cross-origin submission.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/352.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		},
	},

	"open_redirect": {
		VulnType:    "open_redirect",
		Title:       "Open Redirect",
		Description: "Never redirect to user-supplied URLs without validation. Use an allowlist of permitted redirect destinations. For relative URLs, ensure they start with / and don't contain // or protocol handlers.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `from django.shortcuts import redirect

def login_redirect(request):
    next_url = request.GET.get('next', '/')
    return redirect(next_url)`,
				FixedCode: `from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect

ALLOWED_HOSTS = {'app.example.com'}

def login_redirect(request):
    next_url = request.GET.get('next', '/')
    if not url_has_allowed_host_and_scheme(
        next_url, allowed_hosts=ALLOWED_HOSTS
    ):
        next_url = '/'
    return redirect(next_url)`,
				Explanation: "Validate the redirect URL against allowed hosts before using it.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});`,
				FixedCode: `const ALLOWED_HOSTS = new Set(['app.example.com']);

app.get('/redirect', (req, res) => {
  try {
    const target = new URL(req.query.url, 'https://app.example.com');
    if (!ALLOWED_HOSTS.has(target.hostname)) {
      return res.redirect('/');
    }
    res.redirect(target.href);
  } catch {
    res.redirect('/');
  }
});`,
				Explanation: "Parse the URL and validate the hostname against an allowlist.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/601.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
		},
	},

	"information_disclosure": {
		VulnType:    "information_disclosure",
		Title:       "Information Disclosure",
		Description: "Suppress verbose error messages, stack traces, and server version headers in production. Remove debug endpoints, directory listings, and default pages. Use generic error pages.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "flask",
				BadCode: `app = Flask(__name__)
app.config['DEBUG'] = True
# Default error handlers expose stack traces`,
				FixedCode: `app = Flask(__name__)
app.config['DEBUG'] = False

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"Internal error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404`,
				Explanation: "Disable debug mode and use custom error handlers that log details server-side but return generic messages to users.",
			},
			{
				Language:  "go",
				Framework: "gin",
				BadCode: `r := gin.Default()
// gin.Default() uses Logger and Recovery which may leak info

r.GET("/debug/vars", expvar.Handler()) // Debug endpoint exposed`,
				FixedCode: `gin.SetMode(gin.ReleaseMode)
r := gin.New()
r.Use(gin.Recovery()) // Recovery without detailed output

// Remove debug/pprof endpoints in production
// Custom error response:
r.NoRoute(func(c *gin.Context) {
    c.JSON(404, gin.H{"error": "Not found"})
})`,
				Explanation: "Use ReleaseMode, remove debug endpoints, and customize error responses.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://cwe.mitre.org/data/definitions/200.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
		},
	},

	"api_abuse": {
		VulnType:    "api_abuse",
		Title:       "API Access Control Abuse (BOLA/BFLA)",
		Description: "Implement function-level and object-level authorization checks on every API endpoint. Use consistent authZ middleware. Avoid exposing internal IDs — use UUIDs or opaque tokens.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "django",
				BadCode: `# No permission check — any authenticated user can delete any user
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):
    User.objects.filter(id=user_id).delete()
    return Response(status=204)`,
				FixedCode: `from rest_framework.permissions import IsAdminUser

@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user(request, user_id):
    User.objects.filter(id=user_id).delete()
    return Response(status=204)`,
				Explanation: "Use function-level permission (IsAdminUser) to restrict destructive operations to administrators.",
			},
			{
				Language:  "node",
				Framework: "express",
				BadCode: `// Any logged-in user can access any account's data
app.get('/api/accounts/:id/transactions', authenticate, async (req, res) => {
  const txns = await Transaction.find({ accountId: req.params.id });
  res.json(txns);
});`,
				FixedCode: `app.get('/api/accounts/:id/transactions', authenticate, async (req, res) => {
  const account = await Account.findOne({
    _id: req.params.id,
    ownerId: req.user.id,
  });
  if (!account) return res.status(404).json({ error: 'Not found' });
  const txns = await Transaction.find({ accountId: account._id });
  res.json(txns);
});`,
				Explanation: "Verify object ownership (BOLA check) by filtering on the authenticated user's ID.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/285.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		},
	},

	"xxe": {
		VulnType:    "xxe",
		Title:       "XML External Entity (XXE) Injection",
		Description: "Disable external entity resolution and DTD processing in all XML parsers. Use JSON instead of XML when possible. Configure parsers with secure defaults.",
		CodeExamples: []CodeExample{
			{
				Language:  "python",
				Framework: "lxml",
				BadCode: `from lxml import etree
def parse_xml(data):
    return etree.fromstring(data)`,
				FixedCode: `from defusedxml import ElementTree

def parse_xml(data):
    return ElementTree.fromstring(data)

# Or with lxml:
# parser = etree.XMLParser(resolve_entities=False, no_network=True)
# etree.fromstring(data, parser=parser)`,
				Explanation: "defusedxml disables external entities, DTD processing, and network access by default.",
			},
			{
				Language:  "java",
				Framework: "javax.xml",
				BadCode: `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);`,
				FixedCode: `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);`,
				Explanation: "Disable DOCTYPE declarations and external entity features to prevent XXE attacks.",
			},
		},
		References: []string{
			"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
			"https://cwe.mitre.org/data/definitions/611.html",
			"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
		},
	},
}

// GetRemediation returns remediation guidance for the given vulnerability type.
// It uses the same alias resolution as the compliance module.
// Returns nil if no remediation is found.
func GetRemediation(vulnType string) *Remediation {
	key := normalizeKey(vulnType)
	if r, ok := RemediationDB[key]; ok {
		return &r
	}
	return nil
}

// GetAllRemediations returns remediation entries for all known vulnerability types.
func GetAllRemediations() []Remediation {
	results := make([]Remediation, 0, len(RemediationDB))
	for _, r := range RemediationDB {
		results = append(results, r)
	}
	return results
}

// FormatRemediation returns a human-readable remediation summary string for a finding.
// It includes the title, general description, code examples, and references.
func FormatRemediation(vulnType string) string {
	r := GetRemediation(vulnType)
	if r == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("## Remediation: " + r.Title + "\n\n")
	b.WriteString(r.Description + "\n\n")

	for _, ex := range r.CodeExamples {
		lang := ex.Language
		if ex.Framework != "" {
			lang += " (" + ex.Framework + ")"
		}
		b.WriteString("### " + lang + "\n\n")
		b.WriteString("**Vulnerable:**\n```" + ex.Language + "\n" + ex.BadCode + "\n```\n\n")
		b.WriteString("**Fixed:**\n```" + ex.Language + "\n" + ex.FixedCode + "\n```\n\n")
		b.WriteString("*" + ex.Explanation + "*\n\n")
	}

	if len(r.References) > 0 {
		b.WriteString("### References\n")
		for _, ref := range r.References {
			b.WriteString("- " + ref + "\n")
		}
	}

	return b.String()
}
