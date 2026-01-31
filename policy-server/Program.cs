using Nxmx.PolicyServer;

var builder = WebApplication.CreateBuilder(args);

// ENV VARS
var cs = builder.Configuration["SQLITE_CS"] ?? "Data Source=/var/data/nxmx_policy.db";
var adminKey = builder.Configuration["NXMX_ADMIN_KEY"] ?? "dev-admin-key-change";
var hmacSecret = builder.Configuration["NXMX_POLICY_HMAC_SECRET"] ?? "dev-secret-change";
var ttlSeconds = int.TryParse(builder.Configuration["NXMX_POLICY_TTL_SECONDS"], out var t) ? t : 60;

// DB init
var db = new Db(cs);
db.Init();

var app = builder.Build();

// serve dashboard from wwwroot/index.html
app.UseDefaultFiles();
app.UseStaticFiles();

bool IsAdmin(HttpContext ctx) =>
    ctx.Request.Headers.TryGetValue("X-Admin-Key", out var v) && v.ToString() == adminKey;

// Health check
app.MapGet("/health", () => Results.Ok(new { ok = true }));

// Policy fetch for agents
app.MapGet("/api/policies/{tenantId}", (string tenantId) =>
{
    var policyJson = PolicyBuilder.BuildPolicyJson(db, tenantId);
    var env = PolicyBuilder.Sign(tenantId, policyJson, hmacSecret, TimeSpan.FromSeconds(ttlSeconds));
    return Results.Json(env);
});

// Minimal admin endpoints (enough to prove entrypoint + API works)
app.MapGet("/api/admin/tenants", (HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();
    using var c = db.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "SELECT tenant_id, kill_all, default_rate_limit, enable_audit, enable_pii FROM tenants ORDER BY tenant_id";
    using var r = cmd.ExecuteReader();

    var list = new List<object>();
    while (r.Read())
    {
        list.Add(new
        {
            tenantId = r.GetString(0),
            killAll = r.GetInt32(1) == 1,
            defaultRateLimitPerMinute = r.GetInt32(2),
            enableAudit = r.GetInt32(3) == 1,
            enablePii = r.GetInt32(4) == 1
        });
    }
    return Results.Json(list);
});

app.Run();