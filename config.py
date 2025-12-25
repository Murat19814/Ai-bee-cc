"""
Yapay Zekâ Destekli Profesyonel Çağrı Merkezi
Konfigürasyon Dosyası
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Ana konfigürasyon sınıfı"""
    
    # Uygulama Ayarları
    SECRET_KEY = os.getenv('SECRET_KEY', 'cagri-merkezi-secret-key-2024')
    APP_NAME = "AI BEE CC"
    VERSION = "2.0"
    
    # Veritabanı
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'sqlite:///callcenter.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 300,
        'pool_pre_ping': True
    }
    
    # Redis (Real-time veriler için)
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Session Ayarları
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_TYPE = 'redis'
    
    # Upload Ayarları
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv', 'wav', 'mp3', 'ogg'}
    
    # Çağrı Kayıt Ayarları
    RECORDINGS_FOLDER = os.path.join(os.path.dirname(__file__), 'recordings')
    RECORDING_FORMAT = 'wav'
    RECORDING_RETENTION_DAYS = 180  # KVKK uyumlu
    
    # VoIP / SIP Ayarları
    SIP_SERVER = os.getenv('SIP_SERVER', 'sip.example.com')
    SIP_PORT = int(os.getenv('SIP_PORT', 5060))
    SIP_TRANSPORT = os.getenv('SIP_TRANSPORT', 'TLS')  # TLS for security
    SIP_USERNAME = os.getenv('SIP_USERNAME', '')
    SIP_PASSWORD = os.getenv('SIP_PASSWORD', '')
    
    # WebRTC / SRTP
    SRTP_ENABLED = True
    STUN_SERVERS = ['stun:stun.l.google.com:19302']
    TURN_SERVERS = os.getenv('TURN_SERVERS', '').split(',')
    
    # OpenAI / AI Ayarları
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4-turbo-preview')
    WHISPER_MODEL = os.getenv('WHISPER_MODEL', 'base')  # tiny, base, small, medium, large
    
    # AI Özellikleri
    AI_FEATURES = {
        'speech_to_text': True,
        'auto_summary': True,
        'sentiment_analysis': True,
        'agent_assist': True,
        'quality_scoring': True,
        'forbidden_words_detection': True,
        'knowledge_base_rag': True
    }
    
    # Dialer Ayarları
    DIALER_SETTINGS = {
        'preview_timeout': 30,  # saniye
        'progressive_ratio': 1.2,
        'predictive_ratio': 2.0,
        'max_attempts': 5,
        'cooldown_hours': 24,
        'amd_enabled': True,  # Answering Machine Detection
        'cli_rotation': True
    }
    
    # Queue / ACD Ayarları
    QUEUE_SETTINGS = {
        'default_timeout': 300,  # 5 dakika
        'max_wait_time': 600,  # 10 dakika
        'announce_position': True,
        'announce_wait_time': True,
        'overflow_threshold': 10,
        'skill_based_routing': True,
        'priority_routing': True
    }
    
    # KPI Hedefleri
    KPI_TARGETS = {
        'AHT': 300,  # Average Handle Time (saniye)
        'SLA': 80,  # % çağrıların X saniyede cevaplanması
        'SLA_THRESHOLD': 20,  # saniye
        'ABANDON_RATE': 5,  # % max terk oranı
        'CONVERSION_RATE': 15,  # % satış dönüşüm
        'QA_SCORE': 85,  # min kalite puanı
        'FIRST_CALL_RESOLUTION': 70  # % ilk çağrıda çözüm
    }
    
    # KVKK Ayarları
    KVKK_SETTINGS = {
        'consent_required': True,
        'data_retention_days': 730,  # 2 yıl
        'auto_mask_personal_data': True,
        'audit_logging': True,
        'data_encryption': True,
        'access_log_retention': 365
    }
    
    # Yasaklı Kelimeler (KVKK/Kalite)
    FORBIDDEN_WORDS = [
        'garanti', 'kesin', 'mutlaka', 'yüzde yüz',
        'hakaret', 'küfür', 'tehdit'
    ]
    
    # Çalışma Saatleri
    WORKING_HOURS = {
        'start': '09:00',
        'end': '18:00',
        'timezone': 'Europe/Istanbul',
        'holidays': []  # Tatil günleri
    }
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class DevelopmentConfig(Config):
    """Geliştirme ortamı"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Canlı ortam"""
    DEBUG = False
    TESTING = False
    
    # Canlıda daha güçlü güvenlik
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class TestingConfig(Config):
    """Test ortamı"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_callcenter.db'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

