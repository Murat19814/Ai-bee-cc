"""
AI BEE CC - Kapsamlı Yetki Sistemi
================================
Modül bazlı, detaylı yetki tanımları ve rol şablonları
"""

from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user

# ==================== YETKİ TANIMLARI ====================
# Format: module.resource.action

PERMISSIONS = {
    # ========== DASHBOARD ==========
    'dashboard': {
        'name': 'Dashboard',
        'name_de': 'Dashboard',
        'permissions': {
            'dashboard.view': {'name': 'Dashboard Görüntüle', 'name_de': 'Dashboard anzeigen'},
            'dashboard.widgets.manage': {'name': 'Widget Yönetimi', 'name_de': 'Widget verwalten'},
            'dashboard.realtime': {'name': 'Gerçek Zamanlı İzleme', 'name_de': 'Echtzeit-Überwachung'},
        }
    },
    
    # ========== CRM ==========
    'crm': {
        'name': 'CRM / Müşteriler',
        'name_de': 'CRM / Kunden',
        'permissions': {
            'crm.customers.view': {'name': 'Müşterileri Görüntüle', 'name_de': 'Kunden anzeigen'},
            'crm.customers.create': {'name': 'Müşteri Oluştur', 'name_de': 'Kunden erstellen'},
            'crm.customers.edit': {'name': 'Müşteri Düzenle', 'name_de': 'Kunden bearbeiten'},
            'crm.customers.delete': {'name': 'Müşteri Sil', 'name_de': 'Kunden löschen'},
            'crm.customers.export': {'name': 'Müşteri Dışa Aktar', 'name_de': 'Kunden exportieren'},
            'crm.customers.import': {'name': 'Müşteri İçe Aktar', 'name_de': 'Kunden importieren'},
            'crm.customers.merge': {'name': 'Müşteri Birleştir', 'name_de': 'Kunden zusammenführen'},
            'crm.leads.view': {'name': 'Leadleri Görüntüle', 'name_de': 'Leads anzeigen'},
            'crm.leads.create': {'name': 'Lead Oluştur', 'name_de': 'Lead erstellen'},
            'crm.leads.edit': {'name': 'Lead Düzenle', 'name_de': 'Lead bearbeiten'},
            'crm.leads.delete': {'name': 'Lead Sil', 'name_de': 'Lead löschen'},
            'crm.leads.assign': {'name': 'Lead Ata', 'name_de': 'Lead zuweisen'},
            'crm.notes.view': {'name': 'Notları Görüntüle', 'name_de': 'Notizen anzeigen'},
            'crm.notes.create': {'name': 'Not Ekle', 'name_de': 'Notiz hinzufügen'},
            'crm.history.view': {'name': 'Geçmişi Görüntüle', 'name_de': 'Verlauf anzeigen'},
            'crm.tags.manage': {'name': 'Etiket Yönetimi', 'name_de': 'Tags verwalten'},
            'crm.segments.manage': {'name': 'Segment Yönetimi', 'name_de': 'Segmente verwalten'},
        }
    },
    
    # ========== ÇAĞRILAR ==========
    'calls': {
        'name': 'Çağrılar',
        'name_de': 'Anrufe',
        'permissions': {
            'calls.view': {'name': 'Çağrıları Görüntüle', 'name_de': 'Anrufe anzeigen'},
            'calls.make': {'name': 'Çağrı Yap', 'name_de': 'Anrufe tätigen'},
            'calls.receive': {'name': 'Çağrı Al', 'name_de': 'Anrufe empfangen'},
            'calls.transfer': {'name': 'Çağrı Transfer', 'name_de': 'Anrufe weiterleiten'},
            'calls.conference': {'name': 'Konferans Çağrı', 'name_de': 'Konferenzanrufe'},
            'calls.hold': {'name': 'Bekletme', 'name_de': 'Halten'},
            'calls.mute': {'name': 'Sessiz', 'name_de': 'Stummschalten'},
            'calls.history.view': {'name': 'Çağrı Geçmişi', 'name_de': 'Anrufverlauf'},
            'calls.history.export': {'name': 'Geçmiş Dışa Aktar', 'name_de': 'Verlauf exportieren'},
        }
    },
    
    # ========== SES KAYITLARI ==========
    'recordings': {
        'name': 'Ses Kayıtları',
        'name_de': 'Aufnahmen',
        'permissions': {
            'recordings.view': {'name': 'Kayıtları Görüntüle', 'name_de': 'Aufnahmen anzeigen'},
            'recordings.listen': {'name': 'Kayıt Dinle', 'name_de': 'Aufnahmen anhören'},
            'recordings.download': {'name': 'Kayıt İndir', 'name_de': 'Aufnahmen herunterladen'},
            'recordings.delete': {'name': 'Kayıt Sil', 'name_de': 'Aufnahmen löschen'},
            'recordings.share': {'name': 'Kayıt Paylaş', 'name_de': 'Aufnahmen teilen'},
            'recordings.transcribe': {'name': 'Transkript Oluştur', 'name_de': 'Transkribieren'},
        }
    },
    
    # ========== KALİTE KONTROL (QC) ==========
    'qc': {
        'name': 'Kalite Kontrol',
        'name_de': 'Qualitätskontrolle',
        'permissions': {
            'qc.panel.access': {'name': 'QC Paneline Erişim', 'name_de': 'QC-Panel Zugriff'},
            'qc.evaluate': {'name': 'Çağrı Değerlendir', 'name_de': 'Anrufe bewerten'},
            'qc.approve': {'name': 'QC Onayla (OK)', 'name_de': 'QC genehmigen'},
            'qc.reject': {'name': 'QC Reddet (Termin/Storno)', 'name_de': 'QC ablehnen'},
            'qc.notes.add': {'name': 'QC Notu Ekle', 'name_de': 'QC-Notiz hinzufügen'},
            'qc.history.view': {'name': 'QC Geçmişi', 'name_de': 'QC-Verlauf'},
            'qc.reports.view': {'name': 'QC Raporları', 'name_de': 'QC-Berichte'},
            'qc.criteria.manage': {'name': 'QC Kriterleri Yönet', 'name_de': 'QC-Kriterien verwalten'},
            'qc.forms.manage': {'name': 'QC Formları Yönet', 'name_de': 'QC-Formulare verwalten'},
        }
    },
    
    # ========== KAMPANYALAR ==========
    'campaigns': {
        'name': 'Kampanyalar',
        'name_de': 'Kampagnen',
        'permissions': {
            'campaigns.view': {'name': 'Kampanyaları Görüntüle', 'name_de': 'Kampagnen anzeigen'},
            'campaigns.create': {'name': 'Kampanya Oluştur', 'name_de': 'Kampagne erstellen'},
            'campaigns.edit': {'name': 'Kampanya Düzenle', 'name_de': 'Kampagne bearbeiten'},
            'campaigns.delete': {'name': 'Kampanya Sil', 'name_de': 'Kampagne löschen'},
            'campaigns.start': {'name': 'Kampanya Başlat', 'name_de': 'Kampagne starten'},
            'campaigns.stop': {'name': 'Kampanya Durdur', 'name_de': 'Kampagne stoppen'},
            'campaigns.assign_agents': {'name': 'Agent Ata', 'name_de': 'Agenten zuweisen'},
            'campaigns.leads.manage': {'name': 'Lead Listesi Yönet', 'name_de': 'Lead-Liste verwalten'},
            'campaigns.scripts.manage': {'name': 'Script Yönet', 'name_de': 'Skripte verwalten'},
            'campaigns.stats.view': {'name': 'İstatistikleri Görüntüle', 'name_de': 'Statistiken anzeigen'},
        }
    },
    
    # ========== PROJELER ==========
    'projects': {
        'name': 'Projeler',
        'name_de': 'Projekte',
        'permissions': {
            'projects.view': {'name': 'Projeleri Görüntüle', 'name_de': 'Projekte anzeigen'},
            'projects.create': {'name': 'Proje Oluştur', 'name_de': 'Projekt erstellen'},
            'projects.edit': {'name': 'Proje Düzenle', 'name_de': 'Projekt bearbeiten'},
            'projects.delete': {'name': 'Proje Sil', 'name_de': 'Projekt löschen'},
            'projects.assign_users': {'name': 'Kullanıcı Ata', 'name_de': 'Benutzer zuweisen'},
        }
    },
    
    # ========== RAPORLAR ==========
    'reports': {
        'name': 'Raporlar',
        'name_de': 'Berichte',
        'permissions': {
            'reports.view': {'name': 'Raporları Görüntüle', 'name_de': 'Berichte anzeigen'},
            'reports.agent_performance': {'name': 'Agent Performans Raporu', 'name_de': 'Agent-Leistungsbericht'},
            'reports.campaign': {'name': 'Kampanya Raporu', 'name_de': 'Kampagnenbericht'},
            'reports.quality': {'name': 'Kalite Raporu', 'name_de': 'Qualitätsbericht'},
            'reports.financial': {'name': 'Finansal Rapor', 'name_de': 'Finanzbericht'},
            'reports.custom': {'name': 'Özel Rapor Oluştur', 'name_de': 'Benutzerdefinierter Bericht'},
            'reports.export': {'name': 'Rapor Dışa Aktar', 'name_de': 'Bericht exportieren'},
            'reports.schedule': {'name': 'Rapor Zamanla', 'name_de': 'Bericht planen'},
        }
    },
    
    # ========== KULLANICI YÖNETİMİ ==========
    'users': {
        'name': 'Kullanıcı Yönetimi',
        'name_de': 'Benutzerverwaltung',
        'permissions': {
            'users.view': {'name': 'Kullanıcıları Görüntüle', 'name_de': 'Benutzer anzeigen'},
            'users.create': {'name': 'Kullanıcı Oluştur', 'name_de': 'Benutzer erstellen'},
            'users.edit': {'name': 'Kullanıcı Düzenle', 'name_de': 'Benutzer bearbeiten'},
            'users.delete': {'name': 'Kullanıcı Sil', 'name_de': 'Benutzer löschen'},
            'users.activate': {'name': 'Kullanıcı Aktif/Pasif', 'name_de': 'Benutzer aktivieren/deaktivieren'},
            'users.reset_password': {'name': 'Şifre Sıfırla', 'name_de': 'Passwort zurücksetzen'},
            'users.assign_roles': {'name': 'Rol Ata', 'name_de': 'Rollen zuweisen'},
            'users.view_activity': {'name': 'Aktivite Görüntüle', 'name_de': 'Aktivität anzeigen'},
            'users.impersonate': {'name': 'Kullanıcı Olarak Giriş', 'name_de': 'Als Benutzer anmelden'},
        }
    },
    
    # ========== ROL YÖNETİMİ ==========
    'roles': {
        'name': 'Rol Yönetimi',
        'name_de': 'Rollenverwaltung',
        'permissions': {
            'roles.view': {'name': 'Rolleri Görüntüle', 'name_de': 'Rollen anzeigen'},
            'roles.create': {'name': 'Rol Oluştur', 'name_de': 'Rolle erstellen'},
            'roles.edit': {'name': 'Rol Düzenle', 'name_de': 'Rolle bearbeiten'},
            'roles.delete': {'name': 'Rol Sil', 'name_de': 'Rolle löschen'},
            'roles.assign_permissions': {'name': 'Yetki Ata', 'name_de': 'Berechtigungen zuweisen'},
        }
    },
    
    # ========== VoIP ==========
    'voip': {
        'name': 'VoIP / Telefon',
        'name_de': 'VoIP / Telefonie',
        'permissions': {
            'voip.extensions.view': {'name': 'Dahilileri Görüntüle', 'name_de': 'Nebenstellen anzeigen'},
            'voip.extensions.manage': {'name': 'Dahili Yönet', 'name_de': 'Nebenstellen verwalten'},
            'voip.trunks.view': {'name': 'Trunk Görüntüle', 'name_de': 'Trunks anzeigen'},
            'voip.trunks.manage': {'name': 'Trunk Yönet', 'name_de': 'Trunks verwalten'},
            'voip.dids.view': {'name': 'DID Görüntüle', 'name_de': 'DIDs anzeigen'},
            'voip.dids.manage': {'name': 'DID Yönet', 'name_de': 'DIDs verwalten'},
            'voip.queues.view': {'name': 'Kuyrukları Görüntüle', 'name_de': 'Warteschlangen anzeigen'},
            'voip.queues.manage': {'name': 'Kuyruk Yönet', 'name_de': 'Warteschlangen verwalten'},
            'voip.ivr.manage': {'name': 'IVR Yönet', 'name_de': 'IVR verwalten'},
            'voip.live_monitor': {'name': 'Canlı İzleme', 'name_de': 'Live-Überwachung'},
            'voip.whisper': {'name': 'Fısıltı (Whisper)', 'name_de': 'Flüstern'},
            'voip.barge': {'name': 'Araya Gir (Barge)', 'name_de': 'Einschalten'},
        }
    },
    
    # ========== BLACKLIST ==========
    'blacklist': {
        'name': 'Blacklist',
        'name_de': 'Sperrliste',
        'permissions': {
            'blacklist.view': {'name': 'Blacklist Görüntüle', 'name_de': 'Sperrliste anzeigen'},
            'blacklist.add': {'name': 'Blacklist Ekle', 'name_de': 'Zur Sperrliste hinzufügen'},
            'blacklist.remove': {'name': 'Blacklist Kaldır', 'name_de': 'Von Sperrliste entfernen'},
            'blacklist.import': {'name': 'Blacklist İçe Aktar', 'name_de': 'Sperrliste importieren'},
            'blacklist.export': {'name': 'Blacklist Dışa Aktar', 'name_de': 'Sperrliste exportieren'},
        }
    },
    
    # ========== AI ÖZELLİKLERİ ==========
    'ai': {
        'name': 'AI / Yapay Zeka',
        'name_de': 'AI / Künstliche Intelligenz',
        'permissions': {
            'ai.transcription.use': {'name': 'Transkripsiyon Kullan', 'name_de': 'Transkription verwenden'},
            'ai.sentiment.view': {'name': 'Duygu Analizi Görüntüle', 'name_de': 'Stimmungsanalyse anzeigen'},
            'ai.suggestions.view': {'name': 'AI Önerileri Görüntüle', 'name_de': 'AI-Vorschläge anzeigen'},
            'ai.bot.manage': {'name': 'AI Bot Yönet', 'name_de': 'AI-Bot verwalten'},
            'ai.training.manage': {'name': 'AI Eğitimi Yönet', 'name_de': 'AI-Training verwalten'},
        }
    },
    
    # ========== AYARLAR ==========
    'settings': {
        'name': 'Ayarlar',
        'name_de': 'Einstellungen',
        'permissions': {
            'settings.general.view': {'name': 'Genel Ayarları Görüntüle', 'name_de': 'Allgemeine Einstellungen anzeigen'},
            'settings.general.edit': {'name': 'Genel Ayarları Düzenle', 'name_de': 'Allgemeine Einstellungen bearbeiten'},
            'settings.security.view': {'name': 'Güvenlik Ayarlarını Görüntüle', 'name_de': 'Sicherheitseinstellungen anzeigen'},
            'settings.security.edit': {'name': 'Güvenlik Ayarlarını Düzenle', 'name_de': 'Sicherheitseinstellungen bearbeiten'},
            'settings.integrations.view': {'name': 'Entegrasyon Ayarlarını Görüntüle', 'name_de': 'Integrationseinstellungen anzeigen'},
            'settings.integrations.edit': {'name': 'Entegrasyon Ayarlarını Düzenle', 'name_de': 'Integrationseinstellungen bearbeiten'},
            'settings.backup.manage': {'name': 'Yedekleme Yönet', 'name_de': 'Backup verwalten'},
            'settings.audit_logs.view': {'name': 'Denetim Loglarını Görüntüle', 'name_de': 'Audit-Logs anzeigen'},
        }
    },
    
    # ========== BİLDİRİMLER ==========
    'notifications': {
        'name': 'Bildirimler',
        'name_de': 'Benachrichtigungen',
        'permissions': {
            'notifications.view': {'name': 'Bildirimleri Görüntüle', 'name_de': 'Benachrichtigungen anzeigen'},
            'notifications.send': {'name': 'Bildirim Gönder', 'name_de': 'Benachrichtigung senden'},
            'notifications.broadcast': {'name': 'Toplu Bildirim', 'name_de': 'Massenbenachrichtigung'},
            'notifications.templates.manage': {'name': 'Bildirim Şablonları', 'name_de': 'Benachrichtigungsvorlagen'},
        }
    },
    
    # ========== PLATFORM (SUPER ADMIN) ==========
    'platform': {
        'name': 'Platform Yönetimi',
        'name_de': 'Plattformverwaltung',
        'permissions': {
            'platform.tenants.view': {'name': 'Tenant\'ları Görüntüle', 'name_de': 'Mandanten anzeigen'},
            'platform.tenants.create': {'name': 'Tenant Oluştur', 'name_de': 'Mandant erstellen'},
            'platform.tenants.edit': {'name': 'Tenant Düzenle', 'name_de': 'Mandant bearbeiten'},
            'platform.tenants.delete': {'name': 'Tenant Sil', 'name_de': 'Mandant löschen'},
            'platform.tenants.suspend': {'name': 'Tenant Askıya Al', 'name_de': 'Mandant sperren'},
            'platform.billing.view': {'name': 'Faturalandırma Görüntüle', 'name_de': 'Abrechnung anzeigen'},
            'platform.billing.manage': {'name': 'Faturalandırma Yönet', 'name_de': 'Abrechnung verwalten'},
            'platform.system.monitor': {'name': 'Sistem İzleme', 'name_de': 'Systemüberwachung'},
            'platform.system.config': {'name': 'Sistem Konfigürasyon', 'name_de': 'Systemkonfiguration'},
        }
    },
}


# ==================== ROL ŞABLONLARI ====================
ROLE_TEMPLATES = {
    'super_admin': {
        'name': 'Super Admin',
        'name_de': 'Super Admin',
        'description': 'Tüm platform yetkilerine sahip',
        'description_de': 'Vollzugriff auf die gesamte Plattform',
        'color': '#dc2626',
        'icon': 'ti-crown',
        'permissions': '*'  # Tüm yetkiler
    },
    
    'admin': {
        'name': 'Admin',
        'name_de': 'Administrator',
        'description': 'Callcenter yönetimi tam yetki',
        'description_de': 'Vollständige Callcenter-Verwaltung',
        'color': '#7c3aed',
        'icon': 'ti-shield-check',
        'permissions': [
            # Dashboard
            'dashboard.view', 'dashboard.widgets.manage', 'dashboard.realtime',
            # CRM - Tümü
            'crm.customers.view', 'crm.customers.create', 'crm.customers.edit', 'crm.customers.delete',
            'crm.customers.export', 'crm.customers.import', 'crm.customers.merge',
            'crm.leads.view', 'crm.leads.create', 'crm.leads.edit', 'crm.leads.delete', 'crm.leads.assign',
            'crm.notes.view', 'crm.notes.create', 'crm.history.view', 'crm.tags.manage', 'crm.segments.manage',
            # Çağrılar - Tümü
            'calls.view', 'calls.make', 'calls.receive', 'calls.transfer', 'calls.conference',
            'calls.hold', 'calls.mute', 'calls.history.view', 'calls.history.export',
            # Kayıtlar - Tümü
            'recordings.view', 'recordings.listen', 'recordings.download', 'recordings.delete',
            'recordings.share', 'recordings.transcribe',
            # QC - Tümü
            'qc.panel.access', 'qc.evaluate', 'qc.approve', 'qc.reject', 'qc.notes.add',
            'qc.history.view', 'qc.reports.view', 'qc.criteria.manage', 'qc.forms.manage',
            # Kampanyalar - Tümü
            'campaigns.view', 'campaigns.create', 'campaigns.edit', 'campaigns.delete',
            'campaigns.start', 'campaigns.stop', 'campaigns.assign_agents',
            'campaigns.leads.manage', 'campaigns.scripts.manage', 'campaigns.stats.view',
            # Projeler - Tümü
            'projects.view', 'projects.create', 'projects.edit', 'projects.delete', 'projects.assign_users',
            # Raporlar - Tümü
            'reports.view', 'reports.agent_performance', 'reports.campaign', 'reports.quality',
            'reports.financial', 'reports.custom', 'reports.export', 'reports.schedule',
            # Kullanıcılar - Tümü
            'users.view', 'users.create', 'users.edit', 'users.delete', 'users.activate',
            'users.reset_password', 'users.assign_roles', 'users.view_activity',
            # Roller
            'roles.view', 'roles.create', 'roles.edit', 'roles.delete', 'roles.assign_permissions',
            # VoIP - Tümü
            'voip.extensions.view', 'voip.extensions.manage', 'voip.trunks.view', 'voip.trunks.manage',
            'voip.dids.view', 'voip.dids.manage', 'voip.queues.view', 'voip.queues.manage',
            'voip.ivr.manage', 'voip.live_monitor', 'voip.whisper', 'voip.barge',
            # Blacklist
            'blacklist.view', 'blacklist.add', 'blacklist.remove', 'blacklist.import', 'blacklist.export',
            # AI
            'ai.transcription.use', 'ai.sentiment.view', 'ai.suggestions.view', 'ai.bot.manage', 'ai.training.manage',
            # Ayarlar - Tümü
            'settings.general.view', 'settings.general.edit', 'settings.security.view', 'settings.security.edit',
            'settings.integrations.view', 'settings.integrations.edit', 'settings.backup.manage', 'settings.audit_logs.view',
            # Bildirimler
            'notifications.view', 'notifications.send', 'notifications.broadcast', 'notifications.templates.manage',
        ]
    },
    
    'supervisor': {
        'name': 'Supervisor',
        'name_de': 'Teamleiter',
        'description': 'Takım yönetimi ve izleme',
        'description_de': 'Teamverwaltung und Überwachung',
        'color': '#2563eb',
        'icon': 'ti-users',
        'permissions': [
            # Dashboard
            'dashboard.view', 'dashboard.realtime',
            # CRM
            'crm.customers.view', 'crm.customers.create', 'crm.customers.edit',
            'crm.customers.export',
            'crm.leads.view', 'crm.leads.edit', 'crm.leads.assign',
            'crm.notes.view', 'crm.notes.create', 'crm.history.view',
            # Çağrılar
            'calls.view', 'calls.make', 'calls.receive', 'calls.transfer',
            'calls.history.view', 'calls.history.export',
            # Kayıtlar
            'recordings.view', 'recordings.listen', 'recordings.download',
            # QC
            'qc.panel.access', 'qc.evaluate', 'qc.approve', 'qc.reject', 'qc.notes.add',
            'qc.history.view', 'qc.reports.view',
            # Kampanyalar
            'campaigns.view', 'campaigns.edit', 'campaigns.start', 'campaigns.stop',
            'campaigns.assign_agents', 'campaigns.stats.view',
            # Projeler
            'projects.view',
            # Raporlar
            'reports.view', 'reports.agent_performance', 'reports.campaign', 'reports.quality',
            'reports.export',
            # Kullanıcılar - Sınırlı
            'users.view', 'users.view_activity',
            # VoIP - Sınırlı
            'voip.extensions.view', 'voip.queues.view', 'voip.live_monitor', 'voip.whisper', 'voip.barge',
            # Blacklist
            'blacklist.view', 'blacklist.add',
            # Bildirimler
            'notifications.view', 'notifications.send',
        ]
    },
    
    'qc_listener': {
        'name': 'QC Dinleme',
        'name_de': 'QC-Prüfer',
        'description': 'Kalite kontrol ve çağrı değerlendirme',
        'description_de': 'Qualitätskontrolle und Anrufbewertung',
        'color': '#10b981',
        'icon': 'ti-headphones',
        'permissions': [
            # Dashboard - Sınırlı
            'dashboard.view',
            # CRM - Sadece görüntüleme
            'crm.customers.view',
            'crm.leads.view',
            'crm.notes.view', 'crm.history.view',
            # Çağrılar - Sadece görüntüleme
            'calls.view', 'calls.history.view',
            # Kayıtlar - Tam erişim
            'recordings.view', 'recordings.listen', 'recordings.download', 'recordings.transcribe',
            # QC - Tam erişim
            'qc.panel.access', 'qc.evaluate', 'qc.approve', 'qc.reject', 'qc.notes.add',
            'qc.history.view', 'qc.reports.view',
            # Bildirimler
            'notifications.view',
        ]
    },
    
    'agent': {
        'name': 'Agent',
        'name_de': 'Agent',
        'description': 'Çağrı merkezi agent',
        'description_de': 'Callcenter-Agent',
        'color': '#f59e0b',
        'icon': 'ti-headset',
        'permissions': [
            # Dashboard - Kendi
            'dashboard.view',
            # CRM - Sınırlı
            'crm.customers.view', 'crm.customers.edit',
            'crm.leads.view', 'crm.leads.edit',
            'crm.notes.view', 'crm.notes.create',
            # Çağrılar - Kendi
            'calls.view', 'calls.make', 'calls.receive', 'calls.transfer', 'calls.hold', 'calls.mute',
            # Kayıtlar - Kendi
            'recordings.listen',
            # Kampanyalar - Sadece görüntüleme
            'campaigns.view',
            # Blacklist - Ekleme
            'blacklist.view', 'blacklist.add',
            # Bildirimler
            'notifications.view',
        ]
    },
    
    'analyst': {
        'name': 'Analist',
        'name_de': 'Analyst',
        'description': 'Raporlama ve analiz',
        'description_de': 'Berichterstattung und Analyse',
        'color': '#6366f1',
        'icon': 'ti-chart-bar',
        'permissions': [
            # Dashboard
            'dashboard.view', 'dashboard.realtime',
            # CRM - Görüntüleme
            'crm.customers.view', 'crm.customers.export',
            'crm.leads.view',
            'crm.history.view',
            # Çağrılar - Görüntüleme
            'calls.view', 'calls.history.view', 'calls.history.export',
            # Kayıtlar - Görüntüleme
            'recordings.view', 'recordings.listen',
            # QC - Görüntüleme
            'qc.history.view', 'qc.reports.view',
            # Kampanyalar - Görüntüleme
            'campaigns.view', 'campaigns.stats.view',
            # Projeler
            'projects.view',
            # Raporlar - Tam
            'reports.view', 'reports.agent_performance', 'reports.campaign', 'reports.quality',
            'reports.financial', 'reports.custom', 'reports.export', 'reports.schedule',
            # Bildirimler
            'notifications.view',
        ]
    },
}


# ==================== YETKİ KONTROL FONKSİYONLARI ====================

def get_all_permission_codes():
    """Tüm yetki kodlarını döndür"""
    codes = []
    for module in PERMISSIONS.values():
        codes.extend(module['permissions'].keys())
    return codes


def get_role_permissions(role_code):
    """Bir rolün yetkilerini döndür"""
    template = ROLE_TEMPLATES.get(role_code)
    if not template:
        return []
    
    if template['permissions'] == '*':
        return get_all_permission_codes()
    
    return template['permissions']


def user_has_permission(user, permission_code):
    """
    Kullanıcının belirli bir yetkisi var mı kontrol et.
    Önce role bakıyor, sonra özel yetkilere.
    """
    if not user or not user.is_authenticated:
        return False
    
    # Super admin her şeyi yapabilir
    if user.is_super_admin or user.role == 'super_admin':
        return True
    
    # Rol bazlı kontrol
    role_perms = get_role_permissions(user.role)
    if permission_code in role_perms:
        return True
    
    # Özel yetki kontrolü (user.custom_permissions JSON alanı varsa)
    if hasattr(user, 'custom_permissions') and user.custom_permissions:
        try:
            custom = user.custom_permissions if isinstance(user.custom_permissions, list) else []
            if permission_code in custom:
                return True
        except:
            pass
    
    return False


def user_has_any_permission(user, permission_codes):
    """Kullanıcının verilen yetkilerden en az birine sahip mi"""
    return any(user_has_permission(user, p) for p in permission_codes)


def user_has_all_permissions(user, permission_codes):
    """Kullanıcının verilen tüm yetkilere sahip mi"""
    return all(user_has_permission(user, p) for p in permission_codes)


def get_user_permissions(user):
    """Kullanıcının tüm yetkilerini döndür"""
    if not user or not user.is_authenticated:
        return []
    
    if user.is_super_admin or user.role == 'super_admin':
        return get_all_permission_codes()
    
    perms = set(get_role_permissions(user.role))
    
    # Özel yetkiler
    if hasattr(user, 'custom_permissions') and user.custom_permissions:
        try:
            custom = user.custom_permissions if isinstance(user.custom_permissions, list) else []
            perms.update(custom)
        except:
            pass
    
    return list(perms)


def get_user_modules(user):
    """Kullanıcının erişebildiği modülleri döndür"""
    perms = get_user_permissions(user)
    modules = set()
    
    for perm in perms:
        if '.' in perm:
            module = perm.split('.')[0]
            modules.add(module)
    
    return list(modules)


# ==================== DECORATOR'LAR ====================

def permission_required(permission_code):
    """Yetki gerektiren route'lar için decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Lütfen giriş yapın.', 'warning')
                return redirect(url_for('login'))
            
            if not user_has_permission(current_user, permission_code):
                flash('Bu işlem için yetkiniz yok.', 'danger')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def any_permission_required(*permission_codes):
    """Verilen yetkilerden en az biri gerekli"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Lütfen giriş yapın.', 'warning')
                return redirect(url_for('login'))
            
            if not user_has_any_permission(current_user, permission_codes):
                flash('Bu işlem için yetkiniz yok.', 'danger')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(*roles):
    """Belirli roller için decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Lütfen giriş yapın.', 'warning')
                return redirect(url_for('login'))
            
            # Super admin her yere girebilir
            if current_user.is_super_admin or current_user.role == 'super_admin':
                return f(*args, **kwargs)
            
            if current_user.role not in roles:
                flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==================== TEMPLATE HELPERS ====================

def init_permission_helpers(app):
    """Jinja2 template'lere yetki helper'ları ekle"""
    
    @app.context_processor
    def inject_permission_helpers():
        def can(permission_code):
            return user_has_permission(current_user, permission_code)
        
        def can_any(*perms):
            return user_has_any_permission(current_user, perms)
        
        def can_all(*perms):
            return user_has_all_permissions(current_user, perms)
        
        def user_modules():
            return get_user_modules(current_user)
        
        return {
            'can': can,
            'can_any': can_any,
            'can_all': can_all,
            'user_modules': user_modules,
            'PERMISSIONS': PERMISSIONS,
            'ROLE_TEMPLATES': ROLE_TEMPLATES,
        }
