using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Nxmx.PolicyServer;

// Simple SQLite helper
public sealed class Db
{
    private readonly string _cs;
    public Db(string cs) => _cs = cs;

    public SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        return c;
    }

    public void Init()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS tenants(
  tenant_id TEXT PRIMARY KEY,
  kill_all INTEGER NOT NULL DEFAULT 0,
  default_rate_limit INTEGER NOT NULL DEFAULT 0,
  enable_audit INTEGER NOT NULL DEFAULT 1,
  enable_pii INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS endpoint_rules(
  tenant_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  rate_limit INTEGER NOT NULL DEFAULT 0,
  requires_feature TEXT NULL,
  PRIMARY KEY(tenant_id, endpoint_id)
);
";
        cmd.ExecuteNonQuery();

        // Ensure default tenant exists
        using var ins = c.CreateCommand();
        ins.CommandText = "INSERT OR IGNORE INTO tenants(tenant_id) VALUES ('default')";
        ins.ExecuteNonQuery();
    }
}

public static class PolicyBuilder
{
    // Minimal policy model (kept inside PolicyServer so it builds even without Nxmx.Agent)
    // NOTE: This must match what your Agent expects.
    private sealed class TenantPolicy
    {
        public string TenantId { get; set; } = "";
        public GlobalPolicy Global { get; set; } = new();
        public Dictionary<string, EndpointRule> Endpoints { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class GlobalPolicy
    {
        public bool KillAll { get; set; }
        public int DefaultRateLimitPerMinute { get; set; }
        public bool EnableAuditLogs { get; set; }
        public bool EnablePiiRedaction { get; set; }
    }

    private sealed class EndpointRule
    {
        public bool Disabled { get; set; }
        public int RateLimitPerMinute { get; set; }
        public string? RequiresFeature { get; set; }
    }

    public sealed class SignedPolicyEnvelope
    {
        public string TenantId { get; set; } = "";
        public DateTime IssuedAtUtc { get; set; }
        public DateTime ExpiresAtUtc { get; set; }
        public string PolicyJson { get; set; } = "";
        public string Signature { get; set; } = ""; // base64(hmacsha256(policyJson))
    }

    public static string BuildPolicyJson(Db db, string tenantId)
    {
        using var c = db.Open();

        // Tenant global policy
        int killAll = 0, defaultRate = 0, enableAudit = 1, enablePii = 1;

        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT kill_all, default_rate_limit, enable_audit, enable_pii FROM tenants WHERE tenant_id=@t";
            cmd.Parameters.AddWithValue("@t", tenantId);
            using var r = cmd.ExecuteReader();
            if (r.Read())
            {
                killAll = r.GetInt32(0);
                defaultRate = r.GetInt32(1);
                enableAudit = r.GetInt32(2);
                enablePii = r.GetInt32(3);
            }
            else
            {
                // Auto-create tenant row if missing
                using var ins = c.CreateCommand();
                ins.CommandText = "INSERT OR IGNORE INTO tenants(tenant_id) VALUES(@t)";
                ins.Parameters.AddWithValue("@t", tenantId);
                ins.ExecuteNonQuery();
            }
        }

        var endpoints = new Dictionary<string, EndpointRule>(StringComparer.OrdinalIgnoreCase);

        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT endpoint_id, disabled, rate_limit, requires_feature FROM endpoint_rules WHERE tenant_id=@t";
            cmd.Parameters.AddWithValue("@t", tenantId);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var endpointId = r.GetString(0);
                endpoints[endpointId] = new EndpointRule
                {
                    Disabled = r.GetInt32(1) == 1,
                    RateLimitPerMinute = r.GetInt32(2),
                    RequiresFeature = r.IsDBNull(3) ? null : r.GetString(3),
                };
            }
        }

        var policy = new TenantPolicy
        {
            TenantId = tenantId,
            Global = new GlobalPolicy
            {
                KillAll = killAll == 1,
                DefaultRateLimitPerMinute = defaultRate,
                EnableAuditLogs = enableAudit == 1,
                EnablePiiRedaction = enablePii == 1
            },
            Endpoints = endpoints
        };

        return JsonSerializer.Serialize(policy);
    }

    public static SignedPolicyEnvelope Sign(string tenantId, string policyJson, string hmacSecret, TimeSpan ttl)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(hmacSecret));
        var sig = h.ComputeHash(Encoding.UTF8.GetBytes(policyJson));

        return new SignedPolicyEnvelope
        {
            TenantId = tenantId,
            IssuedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.Add(ttl),
            PolicyJson = policyJson,
            Signature = Convert.ToBase64String(sig)
        };
    }
}
