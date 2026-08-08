use crate::error::{CliError, Result};
use async_trait::async_trait;
use redis::AsyncCommands;
use rmcp::transport::streamable_http_server::session::{
    SessionState, SessionStore, SessionStoreError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct StoredSubject {
    pub principal_id: String,
    pub tenant_id: String,
    pub client_id: String,
}

pub(super) enum RedisRateLimitDecision {
    Allowed,
    Limited(std::time::Duration),
    Capacity,
}

#[derive(Clone)]
pub(super) struct RedisRemoteState {
    connection: redis::aio::ConnectionManager,
    prefix: String,
    ttl_seconds: u64,
}

impl std::fmt::Debug for RedisRemoteState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisRemoteState")
            .field("prefix", &self.prefix)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

impl RedisRemoteState {
    pub async fn connect(url: &str, prefix: &str, ttl_seconds: u64) -> Result<Self> {
        validate_redis_config(url, prefix, ttl_seconds)?;
        let client = redis::Client::open(url)
            .map_err(|error| CliError::Internal(format!("invalid Redis configuration: {error}")))?;
        let mut connection = client
            .get_connection_manager()
            .await
            .map_err(|error| CliError::Internal(format!("Redis is unavailable: {error}")))?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(|error| CliError::Internal(format!("Redis health check failed: {error}")))?;
        Ok(Self {
            connection,
            prefix: prefix.into(),
            ttl_seconds,
        })
    }

    fn key(&self, kind: &str, id: &str) -> String {
        format!("{}:{kind}:{id}", self.prefix)
    }

    pub async fn verify_and_touch_binding(
        &self,
        session_id: &str,
        subject: &StoredSubject,
    ) -> Result<bool> {
        let binding_key = self.key("binding", session_id);
        let session_key = self.key("session", session_id);
        let sessions_key = self.key("sessions", "active");
        let encoded = serde_json::to_string(subject)
            .map_err(|error| CliError::Internal(format!("session binding encoding: {error}")))?;
        let expiry = unix_time_seconds()?.saturating_add(self.ttl_seconds);
        let mut connection = self.connection.clone();
        let verified: i64 = redis::Script::new(
            r#"
local binding = redis.call('GET', KEYS[1])
if not binding or binding ~= ARGV[1] or redis.call('EXISTS', KEYS[2]) == 0 then
  return 0
end
redis.call('EXPIRE', KEYS[1], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[2])
redis.call('ZADD', KEYS[3], ARGV[3], ARGV[4])
return 1
"#,
        )
        .key(binding_key)
        .key(session_key)
        .key(sessions_key)
        .arg(encoded)
        .arg(self.ttl_seconds)
        .arg(expiry)
        .arg(session_id)
        .invoke_async(&mut connection)
        .await
        .map_err(redis_error)?;
        Ok(verified == 1)
    }

    pub async fn can_create_session(&self, max_sessions: usize) -> Result<bool> {
        let mut connection = self.connection.clone();
        let sessions_key = self.key("sessions", "active");
        let count: i64 = redis::Script::new(
            "redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1]); return redis.call('ZCARD', KEYS[1])",
        )
        .key(sessions_key)
        .arg(unix_time_seconds()?)
        .invoke_async(&mut connection)
        .await
        .map_err(redis_error)?;
        Ok(count < max_sessions as i64)
    }

    pub async fn try_bind_session(
        &self,
        session_id: &str,
        subject: &StoredSubject,
        max_sessions: usize,
    ) -> Result<bool> {
        let binding_key = self.key("binding", session_id);
        let session_key = self.key("session", session_id);
        let sessions_key = self.key("sessions", "active");
        let encoded = serde_json::to_string(subject)
            .map_err(|error| CliError::Internal(format!("session binding encoding: {error}")))?;
        let now = unix_time_seconds()?;
        let expiry = now.saturating_add(self.ttl_seconds);
        let mut connection = self.connection.clone();
        let bound: i64 = redis::Script::new(
            r#"
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
if redis.call('EXISTS', KEYS[3]) == 0 then
  return -1
end
local previous = redis.call('GET', KEYS[1])
if previous and previous ~= ARGV[2] then
  return -2
end
local exists = redis.call('ZSCORE', KEYS[2], ARGV[5])
if not exists and redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[6], ARGV[5])
return 1
"#,
        )
        .key(binding_key)
        .key(sessions_key)
        .key(session_key)
        .arg(now)
        .arg(encoded)
        .arg(self.ttl_seconds)
        .arg(max_sessions)
        .arg(session_id)
        .arg(expiry)
        .invoke_async(&mut connection)
        .await
        .map_err(redis_error)?;
        match bound {
            1 => Ok(true),
            0 => Ok(false),
            -1 => Err(CliError::Internal(
                "Redis MCP session state was not persisted".into(),
            )),
            _ => Err(CliError::Internal(
                "Redis MCP session identifier is already bound to another subject".into(),
            )),
        }
    }

    pub async fn remove_session(&self, session_id: &str) -> Result<()> {
        let mut connection = self.connection.clone();
        redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(self.key("binding", session_id))
            .ignore()
            .cmd("ZREM")
            .arg(self.key("sessions", "active"))
            .arg(session_id)
            .ignore()
            .query_async::<()>(&mut connection)
            .await
            .map_err(redis_error)
    }

    pub async fn consume_rate_limit(
        &self,
        subject: &StoredSubject,
        requests_per_minute: u32,
        burst: u32,
        max_subjects: usize,
    ) -> Result<RedisRateLimitDecision> {
        let subject_json = serde_json::to_vec(subject)
            .map_err(|error| CliError::Internal(format!("rate-limit subject encoding: {error}")))?;
        let digest = Sha256::digest(subject_json);
        let member = hex::encode(&digest[..16]);
        let key = self.key("rate", &member);
        let subjects_key = self.key("rate-subjects", "active");
        let mut connection = self.connection.clone();
        let retry_ms: i64 = redis::Script::new(
            r#"
local now = redis.call('TIME')
local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
local exists = redis.call('ZSCORE', KEYS[2], ARGV[4])
if not exists and redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then
  return -1
end
redis.call('ZADD', KEYS[2], now_ms + tonumber(ARGV[3]), ARGV[4])
local values = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local tokens = tonumber(values[1]) or tonumber(ARGV[2])
local updated = tonumber(values[2]) or now_ms
local rate_per_ms = tonumber(ARGV[1]) / 60000
tokens = math.min(tonumber(ARGV[2]), tokens + math.max(0, now_ms - updated) * rate_per_ms)
local retry_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
else
  retry_ms = math.ceil((1 - tokens) / rate_per_ms)
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated', now_ms)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return retry_ms
"#,
        )
        .key(key)
        .key(subjects_key)
        .arg(requests_per_minute)
        .arg(burst)
        .arg(self.ttl_seconds.saturating_mul(1000))
        .arg(member)
        .arg(max_subjects)
        .invoke_async(&mut connection)
        .await
        .map_err(redis_error)?;
        match retry_ms {
            -1 => Ok(RedisRateLimitDecision::Capacity),
            0 => Ok(RedisRateLimitDecision::Allowed),
            retry_ms => Ok(RedisRateLimitDecision::Limited(
                std::time::Duration::from_millis(retry_ms as u64),
            )),
        }
    }
}

#[async_trait]
impl SessionStore for RedisRemoteState {
    async fn load(
        &self,
        session_id: &str,
    ) -> std::result::Result<Option<SessionState>, SessionStoreError> {
        let mut connection = self.connection.clone();
        let encoded: Option<String> = connection.get(self.key("session", session_id)).await?;
        encoded
            .map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    async fn store(
        &self,
        session_id: &str,
        state: &SessionState,
    ) -> std::result::Result<(), SessionStoreError> {
        let encoded = serde_json::to_string(state)?;
        let mut connection = self.connection.clone();
        connection
            .set_ex::<_, _, ()>(self.key("session", session_id), encoded, self.ttl_seconds)
            .await?;
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> std::result::Result<(), SessionStoreError> {
        let mut connection = self.connection.clone();
        redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(self.key("session", session_id))
            .arg(self.key("binding", session_id))
            .ignore()
            .cmd("ZREM")
            .arg(self.key("sessions", "active"))
            .arg(session_id)
            .ignore()
            .query_async::<()>(&mut connection)
            .await?;
        Ok(())
    }
}

fn validate_redis_config(url: &str, prefix: &str, ttl_seconds: u64) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|error| CliError::BlockedUrl(format!("invalid Redis URL: {error}")))?;
    if !matches!(parsed.scheme(), "redis" | "rediss")
        || parsed.host_str().is_none()
        || parsed.fragment().is_some()
    {
        return Err(CliError::BlockedUrl(
            "Redis URL must use redis:// or rediss:// and cannot contain a fragment".into(),
        ));
    }
    let loopback = parsed.host_str().is_some_and(|host| {
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    });
    if parsed.scheme() != "rediss" && !loopback {
        return Err(CliError::BlockedUrl(
            "non-loopback Redis requires TLS via rediss://".into(),
        ));
    }
    if prefix.is_empty()
        || prefix.len() > 128
        || prefix
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "-_:".contains(character)))
        || !(60..=86_400).contains(&ttl_seconds)
    {
        return Err(CliError::Internal(
            "Redis key prefix or session TTL is invalid (TTL must be 60..=86400 seconds)".into(),
        ));
    }
    Ok(())
}

fn unix_time_seconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::Internal(format!("system clock before Unix epoch: {error}")))
}

fn redis_error(error: redis::RedisError) -> CliError {
    CliError::Internal(format!("Redis state operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_requires_tls_away_from_loopback() {
        assert!(validate_redis_config("redis://127.0.0.1/", "api-cli:mcp", 600).is_ok());
        assert!(validate_redis_config("rediss://cache.example.com/", "api-cli:mcp", 600).is_ok());
        assert!(validate_redis_config("redis://localhost/", "api-cli:mcp", 600).is_err());
        assert!(matches!(
            validate_redis_config("redis://cache.example.com/", "api-cli:mcp", 600),
            Err(CliError::BlockedUrl(_))
        ));
    }

    #[test]
    fn redis_prefix_and_ttl_are_bounded() {
        assert!(validate_redis_config("redis://127.0.0.1/", "bad prefix", 600).is_err());
        assert!(validate_redis_config("redis://127.0.0.1/", "api-cli:mcp", 10).is_err());
    }
}
