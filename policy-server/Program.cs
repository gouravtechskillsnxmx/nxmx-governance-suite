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

// List tenants (admin)
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

// Create/Update Tenant
app.MapPost("/api/admin/tenant/upsert", async (HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var body = await ctx.Request.ReadFromJsonAsync<TenantUpsert>();
    if (body is null || string.IsNullOrWhiteSpace(body.tenantId))
        return Results.BadRequest("tenantId required");

    AdminStore.UpsertTenant(
        db,
        body.tenantId.Trim(),
        body.killAll,
        body.defaultRateLimitPerMinute,
        body.enableAudit,
        body.enablePii
    );

    return Results.Ok(new { ok = true });
});

// List endpoint rules for a tenant
app.MapGet("/api/admin/endpoints/{tenantId}", (HttpContext ctx, string tenantId) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();
    if (string.IsNullOrWhiteSpace(tenantId)) return Results.BadRequest("tenantId required");
    var list = AdminStore.ListEndpointRules(db, tenantId.Trim());
    return Results.Json(list);
});

// Create/Update endpoint rule
app.MapPost("/api/admin/endpoint/upsert", async (HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var body = await ctx.Request.ReadFromJsonAsync<EndpointUpsert>();
    if (body is null || string.IsNullOrWhiteSpace(body.tenantId) || string.IsNullOrWhiteSpace(body.endpointId))
        return Results.BadRequest("tenantId and endpointId required");

    AdminStore.UpsertEndpointRule(
        db,
        body.tenantId.Trim(),
        body.endpointId.Trim(),
        body.disabled,
        body.rateLimitPerMinute,
        body.requiresFeature
    );

    return Results.Ok(new { ok = true });
});

// Delete endpoint rule
app.MapPost("/api/admin/endpoint/delete", async (HttpContext ctx) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var body = await ctx.Request.ReadFromJsonAsync<EndpointDelete>();
    if (body is null || string.IsNullOrWhiteSpace(body.tenantId) || string.IsNullOrWhiteSpace(body.endpointId))
        return Results.BadRequest("tenantId and endpointId required");

    AdminStore.DeleteEndpointRule(db, body.tenantId.Trim(), body.endpointId.Trim());
    return Results.Ok(new { ok = true });
});

app.Run();

//
// IMPORTANT: In a top-level Program.cs, any namespace/type declarations must come AFTER top-level statements.
// Keep these records at the bottom to avoid CS8803.
//
public sealed record TenantUpsert(string tenantId, bool killAll, int defaultRateLimitPerMinute, bool enableAudit, bool enablePii);
public sealed record EndpointUpsert(string tenantId, string endpointId, bool disabled, int rateLimitPerMinute, string? requiresFeature);
public sealed record EndpointDelete(string tenantId, string endpointId);
