"""
AI BEE CC - Enterprise Multi-Tenant Call Center Platform
Comprehensive Database Models
"""

from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()


def init_db(app):
    """Veritabanını başlat"""
    db.init_app(app)
    with app.app_context():
        db.create_all()


# ============================================
# 1. MULTI-TENANT / PLATFORM MODELS
# ============================================

class Tenant(db.Model):
    """Çağrı Merkezi (CC) - Ana tenant modeli"""
    __tablename__ = 'tenants'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)  # Benzersiz CC kodu
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200))  # Subdomain/domain
    logo_url = db.Column(db.String(500))
    
    # Lokalizasyon
    timezone = db.Column(db.String(50), default='Europe/Istanbul')
    language = db.Column(db.String(10), default='tr')
    currency = db.Column(db.String(10), default='TRY')
    
    # Limitler
    max_agents = db.Column(db.Integer, default=10)
    max_concurrent_calls = db.Column(db.Integer, default=20)
    recording_retention_days = db.Column(db.Integer, default=180)
    storage_quota_gb = db.Column(db.Integer, default=50)
    
    # Durum
    status = db.Column(db.String(20), default='active')  # active, suspended, trial, cancelled
    trial_ends_at = db.Column(db.DateTime)
    
    # API
    api_key = db.Column(db.String(100))
    webhook_url = db.Column(db.String(500))
    webhook_secret = db.Column(db.String(100))
    
    # Zaman damgaları
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # İlişkiler
    users = db.relationship('User', backref='tenant', lazy='dynamic')
    projects = db.relationship('Project', backref='tenant', lazy='dynamic')
    modules = db.relationship('TenantModule', backref='tenant', lazy='dynamic')
    sip_trunks = db.relationship('SIPTrunk', backref='tenant', lazy='dynamic')
    dids = db.relationship('DID', backref='tenant', lazy='dynamic')


class TenantModule(db.Model):
    """Tenant modül yönetimi - Hangi modüller aktif"""
    __tablename__ = 'tenant_modules'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)  # crm, dialer, ai, omnichannel, wfm, qa
    is_enabled = db.Column(db.Boolean, default=True)
    settings = db.Column(db.JSON)  # Modül özel ayarları
    enabled_at = db.Column(db.DateTime, default=datetime.utcnow)


class TenantSettings(db.Model):
    """Tenant genel ayarları"""
    __tablename__ = 'tenant_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    # Çalışma saatleri
    working_hours_start = db.Column(db.String(5), default='09:00')
    working_hours_end = db.Column(db.String(5), default='18:00')
    working_days = db.Column(db.JSON, default=[1,2,3,4,5])  # 1=Pazartesi
    holidays = db.Column(db.JSON, default=[])
    
    # Güvenlik
    password_min_length = db.Column(db.Integer, default=8)
    password_require_special = db.Column(db.Boolean, default=True)
    session_timeout_minutes = db.Column(db.Integer, default=480)
    max_login_attempts = db.Column(db.Integer, default=5)
    two_factor_required = db.Column(db.Boolean, default=False)
    ip_whitelist = db.Column(db.JSON)
    
    # KVKK/GDPR
    data_retention_days = db.Column(db.Integer, default=730)
    auto_mask_personal_data = db.Column(db.Boolean, default=True)
    consent_required = db.Column(db.Boolean, default=True)
    recording_announcement = db.Column(db.Text)


# ============================================
# 2. PROJECT / PROJE MODELS
# ============================================

class Project(db.Model):
    """Proje / Müşteri Markası"""
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    code = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    sector = db.Column(db.String(100))
    
    # Kampanya türü
    campaign_type = db.Column(db.String(20), default='blended')  # inbound, outbound, blended
    
    # Çalışma ayarları
    working_hours_start = db.Column(db.String(5), default='09:00')
    working_hours_end = db.Column(db.String(5), default='18:00')
    working_days = db.Column(db.JSON, default=[1,2,3,4,5])
    
    # Limitler
    max_daily_attempts = db.Column(db.Integer, default=5)
    retry_interval_hours = db.Column(db.Integer, default=24)
    max_concurrent_calls = db.Column(db.Integer, default=10)
    
    # SLA hedefleri
    target_aht = db.Column(db.Integer, default=300)  # saniye
    target_sla_percent = db.Column(db.Integer, default=80)
    target_sla_seconds = db.Column(db.Integer, default=20)
    target_abandon_rate = db.Column(db.Float, default=5.0)
    target_conversion_rate = db.Column(db.Float, default=15.0)
    
    # KVKK
    consent_text = db.Column(db.Text)
    recording_announcement = db.Column(db.Text)
    
    # Durum
    status = db.Column(db.String(20), default='active')  # active, paused, completed, archived
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # İlişkiler
    users = db.relationship('ProjectUser', backref='project', lazy='dynamic')
    campaigns = db.relationship('Campaign', backref='project', lazy='dynamic')
    customers = db.relationship('Customer', backref='project', lazy='dynamic')
    calls = db.relationship('Call', backref='project', lazy='dynamic')
    queues = db.relationship('Queue', backref='project', lazy='dynamic')


class ProjectUser(db.Model):
    """Proje-Kullanıcı eşleştirmesi"""
    __tablename__ = 'project_users'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(20), default='agent')  # admin, supervisor, agent, qa
    
    # İzinler
    can_view_recordings = db.Column(db.Boolean, default=True)
    can_export_data = db.Column(db.Boolean, default=False)
    can_edit_customers = db.Column(db.Boolean, default=True)
    
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 3. USER & RBAC MODELS
# ============================================

class User(UserMixin, db.Model):
    """Kullanıcı modeli - Geliştirilmiş"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    
    # Kimlik bilgileri
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Profil
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    full_name = db.Column(db.String(160))
    phone = db.Column(db.String(20))
    avatar_url = db.Column(db.String(500))
    
    # Dahili numara
    extension = db.Column(db.String(20))
    sip_password = db.Column(db.String(100))
    
    # Rol ve Yetki
    role = db.Column(db.String(20), default='agent')  # super_admin, admin, supervisor, agent, qa, analyst, client
    is_super_admin = db.Column(db.Boolean, default=False)  # Platform süper admin
    
    # Organizasyon
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    
    # Durum
    status = db.Column(db.String(20), default='offline')  # available, busy, break, training, after_call_work, offline
    is_active = db.Column(db.Boolean, default=True)
    is_locked = db.Column(db.Boolean, default=False)
    lock_reason = db.Column(db.String(200))
    
    # Güvenlik
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(100))
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime)
    must_change_password = db.Column(db.Boolean, default=False)
    
    # Session
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime)
    current_ip = db.Column(db.String(50))
    
    # Agent - Kampanya ve Mola
    current_campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    pause_started_at = db.Column(db.DateTime)
    pause_type = db.Column(db.String(50))  # pause, system_error, meeting, meal, tea, wc
    total_pause_time = db.Column(db.Integer, default=0)  # Saniye cinsinden toplam mola
    
    # Zaman damgaları
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # İlişkiler
    roles = db.relationship('UserRole', backref='user', lazy='dynamic')
    skills = db.relationship('UserSkill', backref='user', lazy='dynamic')
    projects = db.relationship('ProjectUser', backref='user', lazy='dynamic')
    calls = db.relationship('Call', backref='agent', lazy='dynamic', foreign_keys='Call.agent_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission_code):
        """Kullanıcının belirli bir yetkisi var mı kontrol et"""
        for user_role in self.roles:
            for role_perm in user_role.role.permissions:
                if role_perm.permission.code == permission_code:
                    return True
        return False
    
    def get_initials(self):
        if self.full_name:
            parts = self.full_name.split()
            if len(parts) >= 2:
                return (parts[0][0] + parts[-1][0]).upper()
            return self.full_name[:2].upper()
        return self.username[:2].upper()


class Role(db.Model):
    """Rol tanımları"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))  # NULL = sistem rolü
    
    code = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_system = db.Column(db.Boolean, default=False)  # Sistem rolü silinemez
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    permissions = db.relationship('RolePermission', backref='role', lazy='dynamic')
    users = db.relationship('UserRole', backref='role', lazy='dynamic')


class Permission(db.Model):
    """Yetki tanımları"""
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    
    module = db.Column(db.String(50), nullable=False)  # crm, voip, reports, admin, ai
    code = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Örnekler:
    # crm.customers.view, crm.customers.create, crm.customers.edit, crm.customers.delete
    # voip.calls.listen, voip.calls.download, voip.queues.manage
    # reports.view, reports.export
    # admin.users.manage, admin.settings.manage


class RolePermission(db.Model):
    """Rol-Yetki eşleştirmesi"""
    __tablename__ = 'role_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), nullable=False)


class UserRole(db.Model):
    """Kullanıcı-Rol eşleştirmesi"""
    __tablename__ = 'user_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 4. ORGANIZATION MODELS
# ============================================

class Department(db.Model):
    """Departmanlar"""
    __tablename__ = 'departments'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50))
    description = db.Column(db.Text)
    manager_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    teams = db.relationship('Team', backref='department', lazy='dynamic')
    users = db.relationship('User', backref='department', lazy='dynamic', foreign_keys='User.department_id')
    manager = db.relationship('User', foreign_keys=[manager_id])


class Team(db.Model):
    """Takımlar"""
    __tablename__ = 'teams'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50))
    description = db.Column(db.Text)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    members = db.relationship('User', backref='team', lazy='dynamic', foreign_keys='User.team_id')
    supervisor = db.relationship('User', foreign_keys=[supervisor_id])


class Skill(db.Model):
    """Beceri tanımları"""
    __tablename__ = 'skills'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50))
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # language, product, technical
    
    is_active = db.Column(db.Boolean, default=True)


class UserSkill(db.Model):
    """Kullanıcı-Beceri eşleştirmesi"""
    __tablename__ = 'user_skills'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    skill_id = db.Column(db.Integer, db.ForeignKey('skills.id'), nullable=False)
    level = db.Column(db.Integer, default=1)  # 1-5 skill level
    
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 5. TELEPHONY / VOIP MODELS
# ============================================

class SIPTrunk(db.Model):
    """SIP Trunk tanımları"""
    __tablename__ = 'sip_trunks'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    provider = db.Column(db.String(100))
    
    # Bağlantı bilgileri
    host = db.Column(db.String(200), nullable=False)
    port = db.Column(db.Integer, default=5060)
    transport = db.Column(db.String(10), default='UDP')  # UDP, TCP, TLS
    username = db.Column(db.String(100))
    password = db.Column(db.String(200))
    
    # Codec ayarları
    codecs = db.Column(db.JSON, default=['G.711', 'G.729'])
    
    # Kapasite
    max_channels = db.Column(db.Integer, default=30)
    current_channels = db.Column(db.Integer, default=0)
    
    # Yedekleme
    is_primary = db.Column(db.Boolean, default=True)
    failover_trunk_id = db.Column(db.Integer, db.ForeignKey('sip_trunks.id'))
    
    # Gelişmiş ayarlar
    outbound_proxy = db.Column(db.String(200))
    auth_user = db.Column(db.String(100))
    ip_whitelist = db.Column(db.Text)
    nat_enabled = db.Column(db.Boolean, default=True)
    keep_alive_interval = db.Column(db.Integer, default=30)
    
    # Durum
    status = db.Column(db.String(20), default='active')  # active, inactive, error
    last_health_check = db.Column(db.DateTime)
    last_check = db.Column(db.DateTime)  # Alias for last_health_check
    health_status = db.Column(db.String(20))
    latency_ms = db.Column(db.Integer)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DID(db.Model):
    """DID / Telefon Numarası"""
    __tablename__ = 'dids'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    number = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(200))
    did_type = db.Column(db.String(20), default='inbound')  # inbound, outbound, both
    
    # Yönlendirme
    destination_type = db.Column(db.String(20))  # ivr, queue, user, external
    destination_id = db.Column(db.Integer)
    destination_name = db.Column(db.String(100))
    
    # CLI için kullanım
    use_for_outbound = db.Column(db.Boolean, default=False)
    cli_priority = db.Column(db.Integer, default=1)
    
    # Trunk
    trunk_id = db.Column(db.Integer, db.ForeignKey('sip_trunks.id'))
    trunk = db.relationship('SIPTrunk', backref='dids')
    
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class IVR(db.Model):
    """IVR Menü"""
    __tablename__ = 'ivrs'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Karşılama
    welcome_audio_url = db.Column(db.String(500))
    welcome_tts_text = db.Column(db.Text)
    
    # Menü timeout
    timeout_seconds = db.Column(db.Integer, default=10)
    max_retries = db.Column(db.Integer, default=3)
    
    # Timeout/Invalid yönlendirme
    timeout_destination_type = db.Column(db.String(20))
    timeout_destination_id = db.Column(db.Integer)
    
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    options = db.relationship('IVROption', backref='ivr', lazy='dynamic')


class IVROption(db.Model):
    """IVR Menü seçenekleri"""
    __tablename__ = 'ivr_options'
    
    id = db.Column(db.Integer, primary_key=True)
    ivr_id = db.Column(db.Integer, db.ForeignKey('ivrs.id'), nullable=False)
    
    digit = db.Column(db.String(5), nullable=False)  # 0-9, *, #
    label = db.Column(db.String(100))
    
    # Yönlendirme
    destination_type = db.Column(db.String(20), nullable=False)  # queue, ivr, user, external, voicemail
    destination_id = db.Column(db.Integer)
    destination_number = db.Column(db.String(50))  # external için
    
    audio_url = db.Column(db.String(500))
    tts_text = db.Column(db.Text)


class Queue(db.Model):
    """Çağrı Kuyruğu / ACD"""
    __tablename__ = 'queues'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50))
    description = db.Column(db.Text)
    
    # Strateji
    strategy = db.Column(db.String(30), default='ring_all')
    # ring_all, round_robin, least_recent, fewest_calls, random, skill_based
    
    # Zaman ayarları
    ring_timeout = db.Column(db.Integer, default=30)  # Her agent için çalma süresi
    max_wait_time = db.Column(db.Integer, default=600)  # Max bekleme süresi
    wrap_up_time = db.Column(db.Integer, default=30)  # After call work süresi
    
    # Anons ayarları
    announce_position = db.Column(db.Boolean, default=True)
    announce_hold_time = db.Column(db.Boolean, default=True)
    hold_music_url = db.Column(db.String(500))
    
    # Overflow
    overflow_enabled = db.Column(db.Boolean, default=True)
    overflow_threshold = db.Column(db.Integer, default=10)  # Bekleyen çağrı sayısı
    overflow_destination_type = db.Column(db.String(20))
    overflow_destination_id = db.Column(db.Integer)
    
    # VIP
    vip_enabled = db.Column(db.Boolean, default=False)
    vip_priority_boost = db.Column(db.Integer, default=10)
    
    # SLA
    sla_target_seconds = db.Column(db.Integer, default=20)
    sla_target_percent = db.Column(db.Integer, default=80)
    
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    members = db.relationship('QueueMember', backref='queue', lazy='dynamic')


class QueueMember(db.Model):
    """Kuyruk üyesi (Agent)"""
    __tablename__ = 'queue_members'
    
    id = db.Column(db.Integer, primary_key=True)
    queue_id = db.Column(db.Integer, db.ForeignKey('queues.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    priority = db.Column(db.Integer, default=1)
    penalty = db.Column(db.Integer, default=0)
    
    is_paused = db.Column(db.Boolean, default=False)
    pause_reason = db.Column(db.String(100))
    
    added_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 6. CAMPAIGN / DIALER MODELS
# ============================================

class Campaign(db.Model):
    """Kampanya"""
    __tablename__ = 'campaigns'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Dialer tipi
    dialer_type = db.Column(db.String(20), default='preview')  # preview, progressive, predictive
    
    # Pacing
    pacing_ratio = db.Column(db.Float, default=1.0)  # Agent başına çağrı oranı
    max_abandonment_rate = db.Column(db.Float, default=3.0)  # % max terk oranı
    
    # Zaman penceresi
    start_time = db.Column(db.String(5), default='09:00')
    end_time = db.Column(db.String(5), default='18:00')
    allowed_days = db.Column(db.JSON, default=[1,2,3,4,5])
    
    # Deneme kuralları
    max_attempts = db.Column(db.Integer, default=5)
    retry_interval_minutes = db.Column(db.Integer, default=60)
    
    # CLI
    cli_rotation = db.Column(db.Boolean, default=True)
    cli_numbers = db.Column(db.JSON)  # DID ID listesi
    
    # Kuyruk ve script
    queue_id = db.Column(db.Integer, db.ForeignKey('queues.id'))
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'))
    disposition_set_id = db.Column(db.Integer, db.ForeignKey('disposition_sets.id'))
    
    # Durum
    status = db.Column(db.String(20), default='draft')  # draft, active, paused, completed
    
    # İstatistikler
    total_leads = db.Column(db.Integer, default=0)
    contacted_leads = db.Column(db.Integer, default=0)
    converted_leads = db.Column(db.Integer, default=0)
    
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    leads = db.relationship('Lead', backref='campaign', lazy='dynamic')


class DialList(db.Model):
    """Arama Listesi"""
    __tablename__ = 'dial_lists'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    source = db.Column(db.String(100))  # import, api, manual
    
    # İstatistikler
    total_records = db.Column(db.Integer, default=0)
    valid_records = db.Column(db.Integer, default=0)
    duplicate_records = db.Column(db.Integer, default=0)
    
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    leads = db.relationship('Lead', backref='dial_list', lazy='dynamic')


class Lead(db.Model):
    """Lead / Arama Kaydı"""
    __tablename__ = 'leads'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    dial_list_id = db.Column(db.Integer, db.ForeignKey('dial_lists.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    
    # Müşteri bilgileri (denormalize)
    phone = db.Column(db.String(20), nullable=False)
    alt_phone = db.Column(db.String(20))
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    email = db.Column(db.String(120))
    company = db.Column(db.String(200))
    
    # Ek veriler
    custom_data = db.Column(db.JSON)
    
    # Öncelik ve skor
    priority = db.Column(db.Integer, default=5)  # 1-10
    score = db.Column(db.Float)
    
    # Arama durumu
    status = db.Column(db.String(20), default='new')  # new, in_progress, contacted, converted, dnc, failed
    
    # Deneme bilgileri
    attempts = db.Column(db.Integer, default=0)
    last_attempt_at = db.Column(db.DateTime)
    next_attempt_at = db.Column(db.DateTime)
    
    # Atama
    assigned_agent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Son disposition
    last_disposition_id = db.Column(db.Integer, db.ForeignKey('dispositions.id'))
    
    # Callback (geri arama) bilgileri
    callback_at = db.Column(db.DateTime)
    callback_note = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LeadAttempt(db.Model):
    """Lead arama denemeleri"""
    __tablename__ = 'lead_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'), nullable=False)
    call_id = db.Column(db.Integer, db.ForeignKey('calls.id'))
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    attempt_number = db.Column(db.Integer, nullable=False)
    phone_used = db.Column(db.String(20))
    
    result = db.Column(db.String(30))  # answered, no_answer, busy, voicemail, failed
    disposition_id = db.Column(db.Integer, db.ForeignKey('dispositions.id'))
    
    duration_seconds = db.Column(db.Integer)
    notes = db.Column(db.Text)
    
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 7. CRM MODELS
# ============================================

class Customer(db.Model):
    """Müşteri"""
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    # Temel bilgiler
    customer_no = db.Column(db.String(50))  # Müşteri numarası
    type = db.Column(db.String(20), default='individual')  # individual, company
    
    # Kişi bilgileri
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    full_name = db.Column(db.String(160))
    tc_no = db.Column(db.String(11))  # Maskelenmiş saklanabilir
    birth_date = db.Column(db.Date)
    gender = db.Column(db.String(10))
    
    # Şirket bilgileri
    company_name = db.Column(db.String(200))
    tax_no = db.Column(db.String(20))
    tax_office = db.Column(db.String(100))
    
    # İletişim
    phone = db.Column(db.String(20))
    alt_phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    
    # Adres
    address = db.Column(db.Text)
    city = db.Column(db.String(100))
    district = db.Column(db.String(100))
    postal_code = db.Column(db.String(10))
    country = db.Column(db.String(100), default='Türkiye')
    
    # Segmentasyon
    segment = db.Column(db.String(50))  # vip, premium, standard
    category = db.Column(db.String(100))
    tags = db.Column(db.JSON)
    
    # Pipeline
    pipeline_id = db.Column(db.Integer, db.ForeignKey('pipelines.id'))
    pipeline_stage_id = db.Column(db.Integer, db.ForeignKey('pipeline_stages.id'))
    
    # Durum
    status = db.Column(db.String(20), default='lead')  # lead, prospect, customer, churned
    
    # KVKK
    consent_given = db.Column(db.Boolean, default=False)
    consent_date = db.Column(db.DateTime)
    data_deletion_requested = db.Column(db.Boolean, default=False)
    
    # Atama
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Custom fields
    custom_fields = db.Column(db.JSON)
    
    # Skor
    lead_score = db.Column(db.Float)
    sentiment_score = db.Column(db.Float)
    
    # İstatistikler
    total_calls = db.Column(db.Integer, default=0)
    total_tickets = db.Column(db.Integer, default=0)
    total_revenue = db.Column(db.Float, default=0)
    
    last_contact_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # İlişkiler
    calls = db.relationship('Call', backref='customer', lazy='dynamic')
    tickets = db.relationship('Ticket', backref='customer', lazy='dynamic')
    notes = db.relationship('CustomerNote', backref='customer', lazy='dynamic')


class CustomerNote(db.Model):
    """Müşteri notları"""
    __tablename__ = 'customer_notes'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    call_id = db.Column(db.Integer, db.ForeignKey('calls.id'))
    
    content = db.Column(db.Text, nullable=False)
    is_pinned = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CustomField(db.Model):
    """Özel alan tanımları"""
    __tablename__ = 'custom_fields'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    entity_type = db.Column(db.String(50), nullable=False)  # customer, lead, ticket
    field_name = db.Column(db.String(100), nullable=False)
    field_label = db.Column(db.String(200), nullable=False)
    field_type = db.Column(db.String(30), nullable=False)  # text, number, date, select, multiselect, checkbox
    
    options = db.Column(db.JSON)  # select için seçenekler
    default_value = db.Column(db.String(500))
    
    is_required = db.Column(db.Boolean, default=False)
    is_visible = db.Column(db.Boolean, default=True)
    is_searchable = db.Column(db.Boolean, default=False)
    
    # Rol bazlı görünürlük
    visible_to_roles = db.Column(db.JSON)  # boş = herkes
    
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Pipeline(db.Model):
    """Satış Pipeline"""
    __tablename__ = 'pipelines'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    is_default = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    stages = db.relationship('PipelineStage', backref='pipeline', lazy='dynamic', order_by='PipelineStage.sort_order')


class PipelineStage(db.Model):
    """Pipeline aşamaları"""
    __tablename__ = 'pipeline_stages'
    
    id = db.Column(db.Integer, primary_key=True)
    pipeline_id = db.Column(db.Integer, db.ForeignKey('pipelines.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), default='#F5A623')
    
    probability = db.Column(db.Integer, default=0)  # Kazanma olasılığı %
    
    sort_order = db.Column(db.Integer, default=0)
    is_won = db.Column(db.Boolean, default=False)
    is_lost = db.Column(db.Boolean, default=False)
    
    # Otomatik aksiyonlar
    auto_task_template = db.Column(db.Text)  # JSON task şablonu


class Ticket(db.Model):
    """Destek Talebi"""
    __tablename__ = 'tickets'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    
    ticket_no = db.Column(db.String(50), unique=True)
    subject = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    
    # Kategorizasyon
    category_id = db.Column(db.Integer, db.ForeignKey('ticket_categories.id'))
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    
    # Durum
    status = db.Column(db.String(20), default='open')  # open, pending, in_progress, resolved, closed
    
    # Atama
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    
    # SLA
    sla_due_at = db.Column(db.DateTime)
    sla_breached = db.Column(db.Boolean, default=False)
    first_response_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    
    # İlişkili çağrı
    call_id = db.Column(db.Integer, db.ForeignKey('calls.id'))
    
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TicketCategory(db.Model):
    """Ticket kategorileri"""
    __tablename__ = 'ticket_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    parent_id = db.Column(db.Integer, db.ForeignKey('ticket_categories.id'))
    
    # SLA varsayılanları
    default_priority = db.Column(db.String(20), default='normal')
    sla_hours = db.Column(db.Integer, default=24)
    
    # Otomatik atama
    auto_assign_team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    
    is_active = db.Column(db.Boolean, default=True)


# ============================================
# 8. CALL MODELS
# ============================================

class Call(db.Model):
    """Çağrı kaydı"""
    __tablename__ = 'calls'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    # Çağrı tanımlayıcı
    call_uuid = db.Column(db.String(100), unique=True)
    
    # Yön
    direction = db.Column(db.String(10), nullable=False)  # inbound, outbound
    
    # Numaralar
    caller_number = db.Column(db.String(20))
    called_number = db.Column(db.String(20))
    did_id = db.Column(db.Integer, db.ForeignKey('dids.id'))
    
    # Taraflar
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    
    # Kuyruk/Kampanya
    queue_id = db.Column(db.Integer, db.ForeignKey('queues.id'))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    lead_id = db.Column(db.Integer, db.ForeignKey('leads.id'))
    
    # Zaman bilgileri
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    answered_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    
    # Süreler (saniye)
    ring_duration = db.Column(db.Integer, default=0)
    talk_duration = db.Column(db.Integer, default=0)
    hold_duration = db.Column(db.Integer, default=0)
    total_duration = db.Column(db.Integer, default=0)
    wrap_up_duration = db.Column(db.Integer, default=0)
    
    # Kuyruk bilgileri
    queue_wait_time = db.Column(db.Integer, default=0)
    queue_position = db.Column(db.Integer)
    
    # Durum
    status = db.Column(db.String(20), default='ringing')
    # ringing, answered, on_hold, transferred, ended, missed, voicemail
    
    hangup_cause = db.Column(db.String(50))
    # normal, busy, no_answer, rejected, failed, transferred
    
    # Disposition
    disposition_id = db.Column(db.Integer, db.ForeignKey('dispositions.id'))
    disposition = db.Column(db.String(50))  # Basit disposition kodu
    disposed_at = db.Column(db.DateTime)
    agent_note = db.Column(db.Text)  # Agent'ın çağrı sonucu notu
    
    # QA Durumu
    qa_status = db.Column(db.String(20))  # pending, passed, failed
    
    # Transfer bilgileri
    transferred_from_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    transferred_to_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    transfer_type = db.Column(db.String(20))  # blind, attended
    
    # Agent notları
    notes = db.Column(db.Text)
    
    # Kalite
    qa_score = db.Column(db.Float)
    ai_qa_score = db.Column(db.Float)
    sentiment_score = db.Column(db.Float)
    
    # Teknik bilgiler
    trunk_id = db.Column(db.Integer, db.ForeignKey('sip_trunks.id'))
    codec = db.Column(db.String(20))
    mos_score = db.Column(db.Float)  # Mean Opinion Score
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # İlişkiler
    recording = db.relationship('CallRecording', backref='call', uselist=False)
    transcript = db.relationship('CallTranscript', backref='call', uselist=False)
    qa_evaluations = db.relationship('QAEvaluation', backref='call', lazy='dynamic')


class CallRecording(db.Model):
    """Çağrı kaydı"""
    __tablename__ = 'call_recordings'
    
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.Integer, db.ForeignKey('calls.id'), nullable=False)
    
    file_path = db.Column(db.String(500), nullable=False)
    file_url = db.Column(db.String(500))
    file_size = db.Column(db.Integer)  # bytes
    duration = db.Column(db.Integer)  # saniye
    format = db.Column(db.String(10), default='wav')
    
    # Stereo kayıtta kanal bilgisi
    channels = db.Column(db.Integer, default=1)
    sample_rate = db.Column(db.Integer, default=8000)
    
    # Maskeleme
    is_masked = db.Column(db.Boolean, default=False)
    masked_file_path = db.Column(db.String(500))
    
    # Saklama
    retention_until = db.Column(db.DateTime)
    is_archived = db.Column(db.Boolean, default=False)
    archived_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CallTranscript(db.Model):
    """Çağrı transkripti"""
    __tablename__ = 'call_transcripts'
    
    id = db.Column(db.Integer, primary_key=True)
    call_id = db.Column(db.Integer, db.ForeignKey('calls.id'), nullable=False)
    
    # Tam metin
    full_text = db.Column(db.Text)
    
    # Segment bazlı (JSON array)
    segments = db.Column(db.JSON)
    # [{"speaker": "agent", "start": 0.5, "end": 3.2, "text": "..."}]
    
    # AI özet
    summary = db.Column(db.Text)
    
    # Etiketler
    topics = db.Column(db.JSON)  # ["fiyat", "iade", "şikayet"]
    keywords = db.Column(db.JSON)
    
    # Duygu analizi
    overall_sentiment = db.Column(db.String(20))  # positive, neutral, negative
    sentiment_timeline = db.Column(db.JSON)
    
    # Tespit edilen sorunlar
    detected_issues = db.Column(db.JSON)  # yasaklı kelime, KVKK ihlali vb.
    
    # İşleme bilgileri
    stt_provider = db.Column(db.String(50))  # whisper, google, azure
    language = db.Column(db.String(10), default='tr')
    confidence_score = db.Column(db.Float)
    
    processed_at = db.Column(db.DateTime, default=datetime.utcnow)


class DispositionSet(db.Model):
    """Disposition seti"""
    __tablename__ = 'disposition_sets'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    is_default = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    dispositions = db.relationship('Disposition', backref='disposition_set', lazy='dynamic')


class Disposition(db.Model):
    """Arama sonucu (Disposition)"""
    __tablename__ = 'dispositions'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    disposition_set_id = db.Column(db.Integer, db.ForeignKey('disposition_sets.id'))
    
    code = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    category = db.Column(db.String(30))  # success, callback, dnc, failed, other
    color = db.Column(db.String(20), default='#666')
    
    # Aksiyonlar
    schedule_callback = db.Column(db.Boolean, default=False)
    add_to_dnc = db.Column(db.Boolean, default=False)
    create_ticket = db.Column(db.Boolean, default=False)
    send_sms = db.Column(db.Boolean, default=False)
    send_email = db.Column(db.Boolean, default=False)
    
    # Sıralama
    sort_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)


class Script(db.Model):
    """Agent scripti"""
    __tablename__ = 'scripts'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Script içeriği (JSON formatında akış)
    content = db.Column(db.JSON)
    # {"sections": [{"title": "Giriş", "text": "...", "fields": [...]}]}
    
    # Tip
    script_type = db.Column(db.String(20), default='sales')  # sales, support, survey
    
    is_global = db.Column(db.Boolean, default=False)  # Tüm tenant'lar için geçerli mi
    is_active = db.Column(db.Boolean, default=True)
    version = db.Column(db.Integer, default=1)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================
# 9. QA MODELS
# ============================================

class QAForm(db.Model):
    """QA değerlendirme formu"""
    __tablename__ = 'qa_forms'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Toplam puan
    max_score = db.Column(db.Integer, default=100)
    passing_score = db.Column(db.Integer, default=70)
    
    is_active = db.Column(db.Boolean, default=True)
    version = db.Column(db.Integer, default=1)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    criteria = db.relationship('QACriteria', backref='form', lazy='dynamic', order_by='QACriteria.sort_order')


class QACriteria(db.Model):
    """QA değerlendirme kriterleri"""
    __tablename__ = 'qa_criteria'
    
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('qa_forms.id'), nullable=False)
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))  # Açılış, Dinleme, Ürün Bilgisi, Kapanış
    
    # Puanlama
    weight = db.Column(db.Float, default=1.0)  # Ağırlık
    max_points = db.Column(db.Integer, default=10)
    
    # Kritik mi?
    is_critical = db.Column(db.Boolean, default=False)  # Kritik = fail edilirse geçersiz
    is_auto_scored = db.Column(db.Boolean, default=False)  # AI tarafından puanlanabilir
    
    sort_order = db.Column(db.Integer, default=0)


class QAEvaluation(db.Model):
    """QA değerlendirmesi"""
    __tablename__ = 'qa_evaluations'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    call_id = db.Column(db.Integer, db.ForeignKey('calls.id'), nullable=False)
    form_id = db.Column(db.Integer, db.ForeignKey('qa_forms.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # NULL = AI
    
    # Puanlar
    total_score = db.Column(db.Float)
    max_possible_score = db.Column(db.Float)
    percentage = db.Column(db.Float)
    
    # Kriter puanları (JSON)
    scores = db.Column(db.JSON)
    # [{"criteria_id": 1, "score": 8, "comment": "..."}]
    
    # Sonuç
    passed = db.Column(db.Boolean)
    
    # Notlar
    feedback = db.Column(db.Text)
    coaching_notes = db.Column(db.Text)
    
    # İtiraz
    appeal_status = db.Column(db.String(20))  # pending, approved, rejected
    appeal_notes = db.Column(db.Text)
    
    # AI değerlendirmesi mi?
    is_ai_evaluation = db.Column(db.Boolean, default=False)
    ai_confidence = db.Column(db.Float)
    
    evaluated_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================
# 10. AI MODELS
# ============================================

class AISettings(db.Model):
    """AI ayarları"""
    __tablename__ = 'ai_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    # STT ayarları
    stt_provider = db.Column(db.String(50), default='whisper')  # whisper, google, azure
    stt_model = db.Column(db.String(50), default='base')
    stt_language = db.Column(db.String(10), default='tr')
    
    # LLM ayarları
    llm_provider = db.Column(db.String(50), default='openai')
    llm_model = db.Column(db.String(50), default='gpt-4')
    llm_temperature = db.Column(db.Float, default=0.3)
    
    # Özellikler
    auto_summary_enabled = db.Column(db.Boolean, default=True)
    sentiment_analysis_enabled = db.Column(db.Boolean, default=True)
    topic_detection_enabled = db.Column(db.Boolean, default=True)
    agent_assist_enabled = db.Column(db.Boolean, default=True)
    auto_qa_enabled = db.Column(db.Boolean, default=True)
    forbidden_words_enabled = db.Column(db.Boolean, default=True)
    
    # Eşikler
    sentiment_alert_threshold = db.Column(db.Float, default=-0.5)
    qa_auto_fail_threshold = db.Column(db.Float, default=50.0)
    
    # Yasaklı kelimeler
    forbidden_words = db.Column(db.JSON)
    
    # Özet şablonları
    summary_template = db.Column(db.Text)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class KnowledgeBase(db.Model):
    """Bilgi tabanı (RAG için)"""
    __tablename__ = 'knowledge_bases'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Embedding ayarları
    embedding_model = db.Column(db.String(100), default='text-embedding-ada-002')
    chunk_size = db.Column(db.Integer, default=500)
    chunk_overlap = db.Column(db.Integer, default=50)
    
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    documents = db.relationship('KBDocument', backref='knowledge_base', lazy='dynamic')


class KBDocument(db.Model):
    """Bilgi tabanı dokümanı"""
    __tablename__ = 'kb_documents'
    
    id = db.Column(db.Integer, primary_key=True)
    knowledge_base_id = db.Column(db.Integer, db.ForeignKey('knowledge_bases.id'), nullable=False)
    
    title = db.Column(db.String(500), nullable=False)
    content = db.Column(db.Text)
    
    # Dosya bilgileri
    file_name = db.Column(db.String(500))
    file_path = db.Column(db.String(500))
    file_type = db.Column(db.String(50))  # pdf, docx, txt, html
    file_size = db.Column(db.Integer)
    
    # Kategori ve etiketler
    category = db.Column(db.String(100))
    tags = db.Column(db.JSON)
    
    # Embedding durumu
    is_indexed = db.Column(db.Boolean, default=False)
    indexed_at = db.Column(db.DateTime)
    chunk_count = db.Column(db.Integer, default=0)
    
    # Versiyon
    version = db.Column(db.Integer, default=1)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================
# 11. INTEGRATION MODELS
# ============================================

class Integration(db.Model):
    """Entegrasyonlar"""
    __tablename__ = 'integrations'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # crm, sms, email, payment, webhook
    provider = db.Column(db.String(50))  # hubspot, salesforce, twilio
    
    # Kimlik bilgileri (şifreli saklanmalı)
    credentials = db.Column(db.JSON)
    
    # Ayarlar
    settings = db.Column(db.JSON)
    
    # Durum
    is_active = db.Column(db.Boolean, default=True)
    last_sync_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Webhook(db.Model):
    """Webhook tanımları"""
    __tablename__ = 'webhooks'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    secret = db.Column(db.String(100))
    
    # Olaylar
    events = db.Column(db.JSON)
    # ["call.started", "call.ended", "ticket.created", "lead.converted"]
    
    # Ayarlar
    is_active = db.Column(db.Boolean, default=True)
    retry_count = db.Column(db.Integer, default=3)
    timeout_seconds = db.Column(db.Integer, default=30)
    
    # İstatistikler
    total_sent = db.Column(db.Integer, default=0)
    total_failed = db.Column(db.Integer, default=0)
    last_triggered_at = db.Column(db.DateTime)
    last_status = db.Column(db.Integer)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class APIKey(db.Model):
    """API anahtarları"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(100), unique=True, nullable=False)
    key_prefix = db.Column(db.String(20))  # Gösterim için ilk karakterler
    
    # Yetkiler
    permissions = db.Column(db.JSON)  # ["read", "write", "delete"]
    
    # Kısıtlamalar
    ip_whitelist = db.Column(db.JSON)
    rate_limit = db.Column(db.Integer, default=1000)  # requests per hour
    
    # Durum
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime)
    last_used_at = db.Column(db.DateTime)
    total_requests = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 12. AUDIT & LOG MODELS
# ============================================

class AuditLog(db.Model):
    """Denetim kaydı"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Olay bilgileri
    action = db.Column(db.String(50), nullable=False)
    # create, read, update, delete, login, logout, export, etc.
    
    resource_type = db.Column(db.String(50))  # user, customer, call, ticket
    resource_id = db.Column(db.Integer)
    
    # Detaylar
    description = db.Column(db.Text)
    old_values = db.Column(db.JSON)
    new_values = db.Column(db.JSON)
    
    # İstek bilgileri
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    request_method = db.Column(db.String(10))
    request_path = db.Column(db.String(500))
    
    # Sonuç
    status = db.Column(db.String(20), default='success')  # success, failed
    error_message = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SecurityEvent(db.Model):
    """Güvenlik olayları"""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    event_type = db.Column(db.String(50), nullable=False)
    # failed_login, suspicious_ip, brute_force, unauthorized_access, password_change
    
    severity = db.Column(db.String(20), default='info')  # info, warning, critical
    
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    
    # İşlem durumu
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolved_at = db.Column(db.DateTime)
    resolution_notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemEvent(db.Model):
    """Sistem olayları"""
    __tablename__ = 'system_events'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    
    event_type = db.Column(db.String(50), nullable=False)
    # trunk_down, recording_error, api_error, queue_overflow, high_wait_time
    
    severity = db.Column(db.String(20), default='info')
    
    source = db.Column(db.String(100))  # service/component adı
    description = db.Column(db.Text)
    details = db.Column(db.JSON)
    
    # İşlem durumu
    is_acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    acknowledged_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 13. REPORT & DASHBOARD MODELS
# ============================================

class Report(db.Model):
    """Rapor tanımları"""
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    report_type = db.Column(db.String(50))  # agent, campaign, queue, quality, executive
    
    # Sorgu/filtre
    query_config = db.Column(db.JSON)
    
    # Görünüm
    chart_type = db.Column(db.String(30))  # table, bar, line, pie, funnel
    columns = db.Column(db.JSON)
    
    # Planlama
    is_scheduled = db.Column(db.Boolean, default=False)
    schedule_cron = db.Column(db.String(50))  # "0 9 * * 1" (Her pazartesi 09:00)
    recipients = db.Column(db.JSON)  # email listesi
    
    # Yetki
    is_public = db.Column(db.Boolean, default=False)
    visible_to_roles = db.Column(db.JSON)
    
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Dashboard(db.Model):
    """Dashboard tanımları"""
    __tablename__ = 'dashboards'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Layout (JSON - widget pozisyonları)
    layout = db.Column(db.JSON)
    
    # Varsayılan mı
    is_default = db.Column(db.Boolean, default=False)
    
    # Yetki
    visible_to_roles = db.Column(db.JSON)
    
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    widgets = db.relationship('DashboardWidget', backref='dashboard', lazy='dynamic')


class DashboardWidget(db.Model):
    """Dashboard widget'ları"""
    __tablename__ = 'dashboard_widgets'
    
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboards.id'), nullable=False)
    
    widget_type = db.Column(db.String(50), nullable=False)
    # stat_card, chart, table, gauge, list
    
    title = db.Column(db.String(200))
    
    # Veri kaynağı
    data_source = db.Column(db.String(100))
    # calls_today, active_agents, queue_waiting, sla_percent, etc.
    
    # Ayarlar
    config = db.Column(db.JSON)
    
    # Pozisyon
    position_x = db.Column(db.Integer, default=0)
    position_y = db.Column(db.Integer, default=0)
    width = db.Column(db.Integer, default=1)
    height = db.Column(db.Integer, default=1)


# ============================================
# 14. NOTIFICATION MODEL
# ============================================

class Notification(db.Model):
    """Bildirimler"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    type = db.Column(db.String(50), nullable=False)
    # call_assigned, ticket_assigned, qa_evaluation, system_alert, etc.
    
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    
    # Bağlantı
    link_type = db.Column(db.String(50))
    link_id = db.Column(db.Integer)
    
    # Durum
    is_read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 15. BILLING & SUBSCRIPTION MODELS
# ============================================

class BillingPlan(db.Model):
    """Platform fiyatlandırma planları"""
    __tablename__ = 'billing_plans'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)  # starter, professional, enterprise
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Fiyatlandırma
    price_monthly = db.Column(db.Numeric(10, 2), default=0)
    price_yearly = db.Column(db.Numeric(10, 2), default=0)
    currency = db.Column(db.String(10), default='TRY')
    
    # Agent bazlı ek ücret
    price_per_agent = db.Column(db.Numeric(10, 2), default=0)
    included_agents = db.Column(db.Integer, default=5)
    
    # Limitler
    max_agents = db.Column(db.Integer, default=10)
    max_concurrent_calls = db.Column(db.Integer, default=20)
    max_projects = db.Column(db.Integer, default=5)
    storage_gb = db.Column(db.Integer, default=50)
    recording_retention_days = db.Column(db.Integer, default=90)
    
    # VoIP dahil dakika
    included_minutes_inbound = db.Column(db.Integer, default=0)
    included_minutes_outbound = db.Column(db.Integer, default=0)
    
    # AI dakika
    included_ai_minutes = db.Column(db.Integer, default=0)
    
    # Modüller
    modules_included = db.Column(db.JSON, default=[])
    
    # Durum
    is_active = db.Column(db.Boolean, default=True)
    is_public = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TenantSubscription(db.Model):
    """Tenant abonelik bilgileri"""
    __tablename__ = 'tenant_subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('billing_plans.id'), nullable=False)
    
    billing_cycle = db.Column(db.String(20), default='monthly')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    status = db.Column(db.String(20), default='active')
    payment_type = db.Column(db.String(20), default='prepaid')
    
    balance = db.Column(db.Numeric(12, 2), default=0)
    credit_limit = db.Column(db.Numeric(12, 2), default=0)
    
    low_balance_threshold = db.Column(db.Numeric(10, 2), default=100)
    low_balance_notified = db.Column(db.Boolean, default=False)
    auto_renew = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    plan = db.relationship('BillingPlan', backref='subscriptions')


class TenantBillingInfo(db.Model):
    """Tenant fatura bilgileri"""
    __tablename__ = 'tenant_billing_info'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, unique=True)
    
    company_name = db.Column(db.String(200))
    tax_office = db.Column(db.String(100))
    tax_number = db.Column(db.String(20))
    
    address_line1 = db.Column(db.String(200))
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    postal_code = db.Column(db.String(20))
    country = db.Column(db.String(100), default='Türkiye')
    
    billing_email = db.Column(db.String(200))
    billing_phone = db.Column(db.String(20))
    
    e_invoice_enabled = db.Column(db.Boolean, default=False)
    e_invoice_address = db.Column(db.String(200))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================
# 16. VOIP BILLING / TARIFF MODELS
# ============================================

class VoIPTariff(db.Model):
    """VoIP ücretlendirme tarifeleri"""
    __tablename__ = 'voip_tariffs'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    default_rate_inbound = db.Column(db.Numeric(8, 4), default=0)
    default_rate_outbound = db.Column(db.Numeric(8, 4), default=0)
    connection_fee = db.Column(db.Numeric(8, 4), default=0)
    
    billing_increment = db.Column(db.Integer, default=60)
    minimum_duration = db.Column(db.Integer, default=0)
    
    is_active = db.Column(db.Boolean, default=True)
    is_default = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rates = db.relationship('VoIPRate', backref='tariff', lazy='dynamic')


class VoIPRate(db.Model):
    """Ülke/operatör bazlı VoIP fiyatları"""
    __tablename__ = 'voip_rates'
    
    id = db.Column(db.Integer, primary_key=True)
    tariff_id = db.Column(db.Integer, db.ForeignKey('voip_tariffs.id'), nullable=False)
    
    destination_type = db.Column(db.String(20), nullable=False)
    destination_code = db.Column(db.String(20), nullable=False)
    destination_name = db.Column(db.String(100))
    prefix_pattern = db.Column(db.String(50))
    
    rate_inbound = db.Column(db.Numeric(8, 4))
    rate_outbound = db.Column(db.Numeric(8, 4))
    connection_fee = db.Column(db.Numeric(8, 4))
    
    peak_rate_outbound = db.Column(db.Numeric(8, 4))
    off_peak_rate_outbound = db.Column(db.Numeric(8, 4))
    peak_hours_start = db.Column(db.String(5))
    peak_hours_end = db.Column(db.String(5))
    
    is_active = db.Column(db.Boolean, default=True)
    is_blocked = db.Column(db.Boolean, default=False)
    
    effective_from = db.Column(db.DateTime, default=datetime.utcnow)
    effective_until = db.Column(db.DateTime)


class TenantVoIPConfig(db.Model):
    """Tenant VoIP yapılandırması"""
    __tablename__ = 'tenant_voip_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, unique=True)
    
    voip_model = db.Column(db.String(20), default='reseller')
    tariff_id = db.Column(db.Integer, db.ForeignKey('voip_tariffs.id'))
    
    max_concurrent_inbound = db.Column(db.Integer, default=10)
    max_concurrent_outbound = db.Column(db.Integer, default=10)
    max_cps = db.Column(db.Integer, default=5)
    max_daily_minutes = db.Column(db.Integer, default=0)
    max_daily_calls = db.Column(db.Integer, default=0)
    
    allowed_call_hours_start = db.Column(db.String(5), default='09:00')
    allowed_call_hours_end = db.Column(db.String(5), default='21:00')
    
    allowed_countries = db.Column(db.JSON)
    blocked_countries = db.Column(db.JSON)
    blocked_prefixes = db.Column(db.JSON)
    
    fraud_protection_enabled = db.Column(db.Boolean, default=True)
    fraud_daily_spend_limit = db.Column(db.Numeric(10, 2), default=1000)
    fraud_hourly_call_limit = db.Column(db.Integer, default=100)
    fraud_concurrent_spike_threshold = db.Column(db.Integer, default=20)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================
# 17. VOIP PROVISIONING MODELS
# ============================================

class DIDPool(db.Model):
    """Platform DID havuzu"""
    __tablename__ = 'did_pools'
    
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(20), unique=True, nullable=False)
    country_code = db.Column(db.String(5), default='TR')
    area_code = db.Column(db.String(10))
    number_type = db.Column(db.String(20), default='geographic')
    
    provider = db.Column(db.String(100))
    provider_cost = db.Column(db.Numeric(8, 2))
    monthly_rental = db.Column(db.Numeric(8, 2), default=0)
    
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    assigned_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='available')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CLIPool(db.Model):
    """Platform CLI havuzu"""
    __tablename__ = 'cli_pools'
    
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(200))
    
    owner_type = db.Column(db.String(20), default='platform')
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    is_shared = db.Column(db.Boolean, default=False)
    
    allowed_destinations = db.Column(db.JSON)
    rotation_priority = db.Column(db.Integer, default=1)
    daily_usage_limit = db.Column(db.Integer, default=0)
    current_daily_usage = db.Column(db.Integer, default=0)
    
    status = db.Column(db.String(20), default='active')
    spam_score = db.Column(db.Integer, default=0)
    last_spam_check = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TenantCLIAssignment(db.Model):
    """Tenant CLI atamaları"""
    __tablename__ = 'tenant_cli_assignments'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    cli_id = db.Column(db.Integer, db.ForeignKey('cli_pools.id'), nullable=False)
    
    usage_type = db.Column(db.String(20), default='all')
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    
    rotation_enabled = db.Column(db.Boolean, default=True)
    rotation_priority = db.Column(db.Integer, default=1)
    
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class TrunkAllocation(db.Model):
    """Tenant trunk tahsisleri"""
    __tablename__ = 'trunk_allocations'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    trunk_id = db.Column(db.Integer, db.ForeignKey('sip_trunks.id'), nullable=False)
    
    allocated_channels = db.Column(db.Integer, default=10)
    priority = db.Column(db.Integer, default=1)
    direction = db.Column(db.String(20), default='both')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 18. USAGE METERING & BILLING RECORDS
# ============================================

class UsageRecord(db.Model):
    """Kullanım kayıtları"""
    __tablename__ = 'usage_records'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    usage_type = db.Column(db.String(30), nullable=False)
    quantity = db.Column(db.Numeric(12, 4), nullable=False)
    unit = db.Column(db.String(20), default='minute')
    
    unit_price = db.Column(db.Numeric(10, 4))
    total_amount = db.Column(db.Numeric(12, 4))
    currency = db.Column(db.String(10), default='TRY')
    
    reference_type = db.Column(db.String(30))
    reference_id = db.Column(db.Integer)
    
    call_direction = db.Column(db.String(10))
    destination_code = db.Column(db.String(20))
    destination_name = db.Column(db.String(100))
    
    usage_date = db.Column(db.Date, nullable=False)
    usage_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    is_billed = db.Column(db.Boolean, default=False)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'))


class UsageSummary(db.Model):
    """Kullanım özetleri"""
    __tablename__ = 'usage_summaries'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    period_type = db.Column(db.String(10), nullable=False)
    period_date = db.Column(db.Date, nullable=False)
    
    voip_inbound_minutes = db.Column(db.Numeric(12, 2), default=0)
    voip_inbound_amount = db.Column(db.Numeric(12, 2), default=0)
    voip_outbound_minutes = db.Column(db.Numeric(12, 2), default=0)
    voip_outbound_amount = db.Column(db.Numeric(12, 2), default=0)
    voip_total_calls = db.Column(db.Integer, default=0)
    
    ai_transcription_minutes = db.Column(db.Numeric(12, 2), default=0)
    ai_transcription_amount = db.Column(db.Numeric(12, 2), default=0)
    ai_summary_count = db.Column(db.Integer, default=0)
    ai_summary_amount = db.Column(db.Numeric(12, 2), default=0)
    
    storage_gb = db.Column(db.Numeric(10, 2), default=0)
    storage_amount = db.Column(db.Numeric(12, 2), default=0)
    
    total_amount = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(10), default='TRY')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Invoice(db.Model):
    """Faturalar"""
    __tablename__ = 'invoices'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    period_start = db.Column(db.Date, nullable=False)
    period_end = db.Column(db.Date, nullable=False)
    
    subtotal = db.Column(db.Numeric(12, 2), nullable=False)
    tax_rate = db.Column(db.Numeric(5, 2), default=20)
    tax_amount = db.Column(db.Numeric(12, 2), nullable=False)
    total_amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency = db.Column(db.String(10), default='TRY')
    
    status = db.Column(db.String(20), default='draft')
    
    issue_date = db.Column(db.Date, default=date.today)
    due_date = db.Column(db.Date)
    paid_date = db.Column(db.Date)
    
    payment_method = db.Column(db.String(50))
    payment_reference = db.Column(db.String(200))
    pdf_url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('InvoiceItem', backref='invoice', lazy='dynamic')


class InvoiceItem(db.Model):
    """Fatura kalemleri"""
    __tablename__ = 'invoice_items'
    
    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'), nullable=False)
    
    description = db.Column(db.String(500), nullable=False)
    item_type = db.Column(db.String(50))
    
    quantity = db.Column(db.Numeric(12, 4), default=1)
    unit = db.Column(db.String(20))
    unit_price = db.Column(db.Numeric(10, 4))
    amount = db.Column(db.Numeric(12, 2), nullable=False)


class Payment(db.Model):
    """Ödemeler"""
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    payment_type = db.Column(db.String(30), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency = db.Column(db.String(10), default='TRY')
    
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'))
    
    payment_method = db.Column(db.String(50))
    payment_gateway = db.Column(db.String(50))
    gateway_transaction_id = db.Column(db.String(200))
    
    status = db.Column(db.String(20), default='pending')
    paid_at = db.Column(db.DateTime)
    
    card_last_four = db.Column(db.String(4))
    card_brand = db.Column(db.String(20))
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 19. WHITE-LABEL & BRANDING
# ============================================

class TenantBranding(db.Model):
    """Tenant marka ayarları"""
    __tablename__ = 'tenant_brandings'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, unique=True)
    
    logo_light_url = db.Column(db.String(500))
    logo_dark_url = db.Column(db.String(500))
    favicon_url = db.Column(db.String(500))
    
    primary_color = db.Column(db.String(10), default='#F5A623')
    secondary_color = db.Column(db.String(10), default='#4A4A4A')
    accent_color = db.Column(db.String(10), default='#50E3C2')
    
    default_theme = db.Column(db.String(10), default='light')
    
    app_title = db.Column(db.String(100))
    login_title = db.Column(db.String(200))
    login_subtitle = db.Column(db.String(500))
    
    email_header_html = db.Column(db.Text)
    email_footer_html = db.Column(db.Text)
    email_from_name = db.Column(db.String(100))
    
    support_url = db.Column(db.String(500))
    support_email = db.Column(db.String(200))
    support_phone = db.Column(db.String(50))
    
    custom_css = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TenantDomain(db.Model):
    """Tenant domain yönetimi"""
    __tablename__ = 'tenant_domains'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    domain = db.Column(db.String(200), unique=True, nullable=False)
    domain_type = db.Column(db.String(20), default='subdomain')
    
    ssl_enabled = db.Column(db.Boolean, default=True)
    ssl_certificate_path = db.Column(db.String(500))
    ssl_expires_at = db.Column(db.DateTime)
    
    dns_verified = db.Column(db.Boolean, default=False)
    dns_verification_token = db.Column(db.String(100))
    dns_verified_at = db.Column(db.DateTime)
    
    is_primary = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 20. SUPPORT / TICKET SYSTEM
# ============================================

class SupportTicket(db.Model):
    """Destek talepleri"""
    __tablename__ = 'support_tickets'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)
    subject = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    category = db.Column(db.String(50))
    priority = db.Column(db.String(20), default='normal')
    status = db.Column(db.String(20), default='open')
    
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    sla_level = db.Column(db.String(20))
    sla_due_at = db.Column(db.DateTime)
    sla_breached = db.Column(db.Boolean, default=False)
    
    tags = db.Column(db.JSON)
    
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    first_response_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    
    messages = db.relationship('SupportTicketMessage', backref='ticket', lazy='dynamic')


class SupportTicketMessage(db.Model):
    """Ticket mesajları"""
    __tablename__ = 'support_ticket_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('support_tickets.id'), nullable=False)
    
    message = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_type = db.Column(db.String(20))
    
    attachments = db.Column(db.JSON)
    is_internal = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemAnnouncement(db.Model):
    """Platform duyuruları"""
    __tablename__ = 'system_announcements'
    
    id = db.Column(db.Integer, primary_key=True)
    
    title = db.Column(db.String(300), nullable=False)
    content = db.Column(db.Text, nullable=False)
    announcement_type = db.Column(db.String(30), nullable=False)
    
    target_tenants = db.Column(db.JSON)
    is_public = db.Column(db.Boolean, default=True)
    is_pinned = db.Column(db.Boolean, default=False)
    
    publish_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    maintenance_start = db.Column(db.DateTime)
    maintenance_end = db.Column(db.DateTime)
    
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================
# 21. QUOTA & POLICY ENGINE
# ============================================

class TenantQuota(db.Model):
    """Tenant kota tanımları"""
    __tablename__ = 'tenant_quotas'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, unique=True)
    
    max_agents = db.Column(db.Integer, default=10)
    max_supervisors = db.Column(db.Integer, default=3)
    max_admins = db.Column(db.Integer, default=2)
    
    max_projects = db.Column(db.Integer, default=5)
    max_campaigns = db.Column(db.Integer, default=10)
    max_queues = db.Column(db.Integer, default=10)
    max_ivrs = db.Column(db.Integer, default=5)
    
    max_concurrent_inbound = db.Column(db.Integer, default=10)
    max_concurrent_outbound = db.Column(db.Integer, default=10)
    max_cps = db.Column(db.Integer, default=5)
    max_daily_outbound_minutes = db.Column(db.Integer, default=0)
    max_daily_outbound_calls = db.Column(db.Integer, default=0)
    
    storage_quota_gb = db.Column(db.Integer, default=50)
    recording_retention_days = db.Column(db.Integer, default=90)
    
    ai_monthly_minutes = db.Column(db.Integer, default=0)
    ai_monthly_summaries = db.Column(db.Integer, default=0)
    
    current_agents = db.Column(db.Integer, default=0)
    current_supervisors = db.Column(db.Integer, default=0)
    current_projects = db.Column(db.Integer, default=0)
    current_storage_gb = db.Column(db.Numeric(10, 2), default=0)
    
    allow_overage = db.Column(db.Boolean, default=False)
    overage_rate_multiplier = db.Column(db.Numeric(5, 2), default=1.5)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class QuotaAlert(db.Model):
    """Kota uyarıları"""
    __tablename__ = 'quota_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    
    alert_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500))
    
    current_value = db.Column(db.Numeric(12, 2))
    limit_value = db.Column(db.Numeric(12, 2))
    percentage = db.Column(db.Integer)
    
    is_acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    acknowledged_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
