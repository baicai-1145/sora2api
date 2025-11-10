"""Database storage layer"""
import aiosqlite
import json
from datetime import datetime
from typing import Optional, List
from pathlib import Path
from .models import Token, TokenStats, Task, RequestLog, AdminConfig, ProxyConfig, WatermarkFreeConfig

class Database:
    """SQLite database manager"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            # Store database in data directory
            data_dir = Path(__file__).parent.parent.parent / "data"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "hancat.db")
        self.db_path = db_path

    def db_exists(self) -> bool:
        """Check if database file exists"""
        return Path(self.db_path).exists()
    
    async def init_db(self):
        """Initialize database tables"""
        async with aiosqlite.connect(self.db_path) as db:
            # Tokens table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    email TEXT NOT NULL,
                    username TEXT NOT NULL,
                    name TEXT NOT NULL,
                    st TEXT,
                    rt TEXT,
                    remark TEXT,
                    expiry_time TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    cooled_until TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    use_count INTEGER DEFAULT 0,
                    plan_type TEXT,
                    plan_title TEXT,
                    subscription_end TIMESTAMP,
                    sora2_supported BOOLEAN,
                    sora2_invite_code TEXT,
                    sora2_redeemed_count INTEGER DEFAULT 0,
                    sora2_total_count INTEGER DEFAULT 0,
                    sora2_remaining_count INTEGER DEFAULT 0,
                    sora2_cooldown_until TIMESTAMP
                )
            """)

            # Add sora2 columns if they don't exist (migration)
            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN sora2_supported BOOLEAN")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN sora2_invite_code TEXT")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN sora2_redeemed_count INTEGER DEFAULT 0")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN sora2_total_count INTEGER DEFAULT 0")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN sora2_remaining_count INTEGER DEFAULT 0")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN sora2_cooldown_until TIMESTAMP")
            except:
                pass  # Column already exists

            # Migrate watermark_free_config table - add new columns
            try:
                await db.execute("ALTER TABLE watermark_free_config ADD COLUMN parse_method TEXT DEFAULT 'third_party'")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE watermark_free_config ADD COLUMN custom_parse_url TEXT")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE watermark_free_config ADD COLUMN custom_parse_token TEXT")
            except:
                pass  # Column already exists

            # Add image_enabled and video_enabled columns if they don't exist (migration)
            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN image_enabled BOOLEAN DEFAULT 1")
            except:
                pass  # Column already exists

            try:
                await db.execute("ALTER TABLE tokens ADD COLUMN video_enabled BOOLEAN DEFAULT 1")
            except:
                pass  # Column already exists

            # Token stats table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS token_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id INTEGER NOT NULL,
                    image_count INTEGER DEFAULT 0,
                    video_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    last_error_at TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)
            
            # Tasks table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT UNIQUE NOT NULL,
                    token_id INTEGER NOT NULL,
                    model TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'processing',
                    progress FLOAT DEFAULT 0,
                    result_urls TEXT,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)
            
            # Request logs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS request_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id INTEGER,
                    operation TEXT NOT NULL,
                    request_body TEXT,
                    response_body TEXT,
                    status_code INTEGER NOT NULL,
                    duration FLOAT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)
            
            # Admin config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS admin_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    error_ban_threshold INTEGER DEFAULT 3,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Proxy config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS proxy_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    proxy_enabled BOOLEAN DEFAULT 0,
                    proxy_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Watermark-free config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS watermark_free_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    watermark_free_enabled BOOLEAN DEFAULT 0,
                    parse_method TEXT DEFAULT 'third_party',
                    custom_parse_url TEXT,
                    custom_parse_token TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Video length config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS video_length_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    default_length TEXT DEFAULT '10s',
                    lengths_json TEXT DEFAULT '{"10s": 300, "15s": 450}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_task_id ON tasks(task_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_task_status ON tasks(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_token_active ON tokens(is_active)")
            
            # Insert default admin config
            await db.execute("""
                INSERT OR IGNORE INTO admin_config (id, error_ban_threshold)
                VALUES (1, 3)
            """)
            
            # Insert default proxy config
            await db.execute("""
                INSERT OR IGNORE INTO proxy_config (id, proxy_enabled, proxy_url)
                VALUES (1, 0, NULL)
            """)

            # Insert default watermark-free config
            await db.execute("""
                INSERT OR IGNORE INTO watermark_free_config (id, watermark_free_enabled, parse_method, custom_parse_url, custom_parse_token)
                VALUES (1, 0, 'third_party', NULL, NULL)
            """)

            # Insert default video length config
            await db.execute("""
                INSERT OR IGNORE INTO video_length_config (id, default_length, lengths_json)
                VALUES (1, '10s', '{"10s": 300, "15s": 450}')
            """)

            await db.commit()

    async def init_config_from_toml(self, config_dict: dict):
        """Initialize database configuration from setting.toml on first startup"""
        async with aiosqlite.connect(self.db_path) as db:
            # Initialize admin config
            admin_config = config_dict.get("admin", {})
            error_ban_threshold = admin_config.get("error_ban_threshold", 3)

            await db.execute("""
                UPDATE admin_config
                SET error_ban_threshold = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (error_ban_threshold,))

            # Initialize proxy config
            proxy_config = config_dict.get("proxy", {})
            proxy_enabled = proxy_config.get("proxy_enabled", False)
            proxy_url = proxy_config.get("proxy_url", "")
            # Convert empty string to None
            proxy_url = proxy_url if proxy_url else None

            await db.execute("""
                UPDATE proxy_config
                SET proxy_enabled = ?, proxy_url = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (proxy_enabled, proxy_url))

            # Initialize watermark-free config
            watermark_config = config_dict.get("watermark_free", {})
            watermark_free_enabled = watermark_config.get("watermark_free_enabled", False)
            parse_method = watermark_config.get("parse_method", "third_party")
            custom_parse_url = watermark_config.get("custom_parse_url", "")
            custom_parse_token = watermark_config.get("custom_parse_token", "")

            # Convert empty strings to None
            custom_parse_url = custom_parse_url if custom_parse_url else None
            custom_parse_token = custom_parse_token if custom_parse_token else None

            await db.execute("""
                UPDATE watermark_free_config
                SET watermark_free_enabled = ?, parse_method = ?, custom_parse_url = ?,
                    custom_parse_token = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (watermark_free_enabled, parse_method, custom_parse_url, custom_parse_token))

            # Initialize video length config
            video_length_config = config_dict.get("video_length", {})
            default_length = video_length_config.get("default_length", "10s")
            lengths = video_length_config.get("lengths", {"10s": 300, "15s": 450})
            lengths_json = json.dumps(lengths)

            await db.execute("""
                UPDATE video_length_config
                SET default_length = ?, lengths_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (default_length, lengths_json))

            await db.commit()

    # Token operations
    async def add_token(self, token: Token) -> int:
        """Add a new token"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO tokens (token, email, username, name, st, rt, remark, expiry_time, is_active,
                                   plan_type, plan_title, subscription_end, sora2_supported, sora2_invite_code,
                                   sora2_redeemed_count, sora2_total_count, sora2_remaining_count, sora2_cooldown_until,
                                   image_enabled, video_enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (token.token, token.email, "", token.name, token.st, token.rt,
                  token.remark, token.expiry_time, token.is_active,
                  token.plan_type, token.plan_title, token.subscription_end,
                  token.sora2_supported, token.sora2_invite_code,
                  token.sora2_redeemed_count, token.sora2_total_count,
                  token.sora2_remaining_count, token.sora2_cooldown_until,
                  token.image_enabled, token.video_enabled))
            await db.commit()
            token_id = cursor.lastrowid

            # Create stats entry
            await db.execute("""
                INSERT INTO token_stats (token_id) VALUES (?)
            """, (token_id,))
            await db.commit()

            return token_id
    
    async def get_token(self, token_id: int) -> Optional[Token]:
        """Get token by ID"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens WHERE id = ?", (token_id,))
            row = await cursor.fetchone()
            if row:
                return Token(**dict(row))
            return None
    
    async def get_token_by_value(self, token: str) -> Optional[Token]:
        """Get token by value"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens WHERE token = ?", (token,))
            row = await cursor.fetchone()
            if row:
                return Token(**dict(row))
            return None
    
    async def get_active_tokens(self) -> List[Token]:
        """Get all active tokens (enabled, not cooled down, not expired)"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM tokens
                WHERE is_active = 1
                AND (cooled_until IS NULL OR cooled_until < CURRENT_TIMESTAMP)
                AND expiry_time > CURRENT_TIMESTAMP
                ORDER BY last_used_at ASC NULLS FIRST
            """)
            rows = await cursor.fetchall()
            return [Token(**dict(row)) for row in rows]
    
    async def get_all_tokens(self) -> List[Token]:
        """Get all tokens"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens ORDER BY created_at DESC")
            rows = await cursor.fetchall()
            return [Token(**dict(row)) for row in rows]

    async def get_tokens_with_available_invites(self, limit: int = 10) -> List[Token]:
        """
        Get tokens that have available Sora2 invite codes.
        Conditions:
          - is_active = 1
          - sora2_supported = 1
          - sora2_invite_code not null/empty
          - sora2_remaining_count > 0
          - (optional) sora2_cooldown_until is null or passed
        Ordered by remaining_count desc and last_used_at (oldest first).
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM tokens
                 WHERE is_active = 1
                   AND sora2_supported = 1
                   AND sora2_invite_code IS NOT NULL
                   AND sora2_invite_code != ''
                   AND sora2_remaining_count > 0
                   AND (sora2_cooldown_until IS NULL OR sora2_cooldown_until <= CURRENT_TIMESTAMP)
                 ORDER BY sora2_remaining_count DESC, last_used_at ASC NULLS FIRST
                 LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [Token(**dict(row)) for row in rows]

    async def update_token_usage(self, token_id: int):
        """Update token usage"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE tokens 
                SET last_used_at = CURRENT_TIMESTAMP, use_count = use_count + 1
                WHERE id = ?
            """, (token_id,))
            await db.commit()
    
    async def update_token_status(self, token_id: int, is_active: bool):
        """Update token status"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE tokens SET is_active = ? WHERE id = ?
            """, (is_active, token_id))
            await db.commit()
    
    async def update_token_sora2(self, token_id: int, supported: bool, invite_code: Optional[str] = None,
                                redeemed_count: int = 0, total_count: int = 0, remaining_count: int = 0):
        """Update token Sora2 support info"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE tokens
                SET sora2_supported = ?, sora2_invite_code = ?, sora2_redeemed_count = ?, sora2_total_count = ?, sora2_remaining_count = ?
                WHERE id = ?
            """, (supported, invite_code, redeemed_count, total_count, remaining_count, token_id))
            await db.commit()

    async def update_token_sora2_remaining(self, token_id: int, remaining_count: int):
        """Update token Sora2 remaining count"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE tokens SET sora2_remaining_count = ? WHERE id = ?
            """, (remaining_count, token_id))
            await db.commit()

    async def update_token_sora2_cooldown(self, token_id: int, cooldown_until: Optional[datetime]):
        """Update token Sora2 cooldown time"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE tokens SET sora2_cooldown_until = ? WHERE id = ?
            """, (cooldown_until, token_id))
            await db.commit()

    async def update_token_cooldown(self, token_id: int, cooled_until: datetime):
        """Update token cooldown"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE tokens SET cooled_until = ? WHERE id = ?
            """, (cooled_until, token_id))
            await db.commit()
    
    async def delete_token(self, token_id: int):
        """Delete token"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM token_stats WHERE token_id = ?", (token_id,))
            await db.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
            await db.commit()

    async def update_token(self, token_id: int,
                          token: Optional[str] = None,
                          st: Optional[str] = None,
                          rt: Optional[str] = None,
                          remark: Optional[str] = None,
                          expiry_time: Optional[datetime] = None,
                          plan_type: Optional[str] = None,
                          plan_title: Optional[str] = None,
                          subscription_end: Optional[datetime] = None,
                          image_enabled: Optional[bool] = None,
                          video_enabled: Optional[bool] = None):
        """Update token (AT, ST, RT, remark, expiry_time, subscription info, image_enabled, video_enabled)"""
        async with aiosqlite.connect(self.db_path) as db:
            # Build dynamic update query
            updates = []
            params = []

            if token is not None:
                updates.append("token = ?")
                params.append(token)

            if st is not None:
                updates.append("st = ?")
                params.append(st)

            if rt is not None:
                updates.append("rt = ?")
                params.append(rt)

            if remark is not None:
                updates.append("remark = ?")
                params.append(remark)

            if expiry_time is not None:
                updates.append("expiry_time = ?")
                params.append(expiry_time)

            if plan_type is not None:
                updates.append("plan_type = ?")
                params.append(plan_type)

            if plan_title is not None:
                updates.append("plan_title = ?")
                params.append(plan_title)

            if subscription_end is not None:
                updates.append("subscription_end = ?")
                params.append(subscription_end)

            if image_enabled is not None:
                updates.append("image_enabled = ?")
                params.append(image_enabled)

            if video_enabled is not None:
                updates.append("video_enabled = ?")
                params.append(video_enabled)

            if updates:
                params.append(token_id)
                query = f"UPDATE tokens SET {', '.join(updates)} WHERE id = ?"
                await db.execute(query, params)
                await db.commit()

    # Token stats operations
    async def get_token_stats(self, token_id: int) -> Optional[TokenStats]:
        """Get token statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM token_stats WHERE token_id = ?", (token_id,))
            row = await cursor.fetchone()
            if row:
                return TokenStats(**dict(row))
            return None
    
    async def increment_image_count(self, token_id: int):
        """Increment image generation count"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE token_stats SET image_count = image_count + 1 WHERE token_id = ?
            """, (token_id,))
            await db.commit()
    
    async def increment_video_count(self, token_id: int):
        """Increment video generation count"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE token_stats SET video_count = video_count + 1 WHERE token_id = ?
            """, (token_id,))
            await db.commit()
    
    async def increment_error_count(self, token_id: int):
        """Increment error count"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE token_stats 
                SET error_count = error_count + 1, last_error_at = CURRENT_TIMESTAMP
                WHERE token_id = ?
            """, (token_id,))
            await db.commit()
    
    async def reset_error_count(self, token_id: int):
        """Reset error count"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE token_stats SET error_count = 0 WHERE token_id = ?
            """, (token_id,))
            await db.commit()
    
    # Task operations
    async def create_task(self, task: Task) -> int:
        """Create a new task"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO tasks (task_id, token_id, model, prompt, status, progress)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (task.task_id, task.token_id, task.model, task.prompt, task.status, task.progress))
            await db.commit()
            return cursor.lastrowid
    
    async def update_task(self, task_id: str, status: str, progress: float, 
                         result_urls: Optional[str] = None, error_message: Optional[str] = None):
        """Update task status"""
        async with aiosqlite.connect(self.db_path) as db:
            completed_at = datetime.now() if status in ["completed", "failed"] else None
            await db.execute("""
                UPDATE tasks 
                SET status = ?, progress = ?, result_urls = ?, error_message = ?, completed_at = ?
                WHERE task_id = ?
            """, (status, progress, result_urls, error_message, completed_at, task_id))
            await db.commit()
    
    async def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = await cursor.fetchone()
            if row:
                return Task(**dict(row))
            return None
    
    # Request log operations
    async def log_request(self, log: RequestLog):
        """Log a request"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO request_logs (token_id, operation, request_body, response_body, status_code, duration)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (log.token_id, log.operation, log.request_body, log.response_body, 
                  log.status_code, log.duration))
            await db.commit()
    
    async def get_recent_logs(self, limit: int = 100) -> List[dict]:
        """Get recent logs with token email"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT
                    rl.id,
                    rl.token_id,
                    rl.operation,
                    rl.request_body,
                    rl.response_body,
                    rl.status_code,
                    rl.duration,
                    rl.created_at,
                    t.email as token_email
                FROM request_logs rl
                LEFT JOIN tokens t ON rl.token_id = t.id
                ORDER BY rl.created_at DESC
                LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    # Admin config operations
    async def get_admin_config(self) -> AdminConfig:
        """Get admin configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM admin_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return AdminConfig(**dict(row))
            return AdminConfig()
    
    async def update_admin_config(self, config: AdminConfig):
        """Update admin configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE admin_config
                SET error_ban_threshold = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (config.error_ban_threshold,))
            await db.commit()
    
    # Proxy config operations
    async def get_proxy_config(self) -> ProxyConfig:
        """Get proxy configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM proxy_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return ProxyConfig(**dict(row))
            return ProxyConfig()
    
    async def update_proxy_config(self, enabled: bool, proxy_url: Optional[str]):
        """Update proxy configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE proxy_config
                SET proxy_enabled = ?, proxy_url = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (enabled, proxy_url))
            await db.commit()

    # Watermark-free config operations
    async def get_watermark_free_config(self) -> WatermarkFreeConfig:
        """Get watermark-free configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM watermark_free_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return WatermarkFreeConfig(**dict(row))
            return WatermarkFreeConfig()

    async def update_watermark_free_config(self, enabled: bool, parse_method: str = None,
                                          custom_parse_url: str = None, custom_parse_token: str = None):
        """Update watermark-free configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            if parse_method is None and custom_parse_url is None and custom_parse_token is None:
                # Only update enabled status
                await db.execute("""
                    UPDATE watermark_free_config
                    SET watermark_free_enabled = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """, (enabled,))
            else:
                # Update all fields
                await db.execute("""
                    UPDATE watermark_free_config
                    SET watermark_free_enabled = ?, parse_method = ?, custom_parse_url = ?,
                        custom_parse_token = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """, (enabled, parse_method or "third_party", custom_parse_url, custom_parse_token))
            await db.commit()

    # Video length config operations
    async def get_video_length_config(self):
        """Get video length configuration"""
        from .models import VideoLengthConfig
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM video_length_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return VideoLengthConfig(**dict(row))
            return VideoLengthConfig()

    async def update_video_length_config(self, default_length: str, lengths_json: str):
        """Update video length configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE video_length_config
                SET default_length = ?, lengths_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (default_length, lengths_json))
            await db.commit()

    async def get_n_frames_for_length(self, length: str) -> int:
        """Get n_frames value for a given video length"""
        config = await self.get_video_length_config()
        try:
            lengths = json.loads(config.lengths_json)
            return lengths.get(length, 300)  # Default to 300 if not found
        except:
            return 300  # Default to 300 if JSON parsing fails
