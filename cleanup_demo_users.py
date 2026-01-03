"""Cleanup Demo-User (Dry-Run by default)

IMPORTANT (Go-Live safe default):
- By default we DO NOT hard-delete users, we only DEACTIVATE them.
  Reason: users are often referenced by AuditLog / SecurityEvent foreign keys.
  Hard-delete can fail (FK violation) and can break referential integrity.

Usage:
  python cleanup_demo_users.py                       # dry-run (shows candidates)
  python cleanup_demo_users.py --apply               # apply default mode=deactivate
  python cleanup_demo_users.py --apply --mode delete --purge-audit

Safe rules:
- NEVER touch user "Murat66"
- NEVER touch BeeLife users (@beelife-cc.com)
- Candidates are ALL OTHER users (demo accounts)
"""

import argparse

from app import app, db
from models import AuditLog, SecurityEvent, User


# BeeLife gerçek kullanıcı isimleri - BUNLARI ASLA SİLME
BEELIFE_USERNAMES = {
    "Murat66",
    "ferhat.acikgoz",
    "ayhan.yildizdogan",
    "ahmet.komur",
    "hatice.yildiz",
    "meral.tasdogan",
    "abdulcelil.arslan",
    "asli.akdogan",
    "eda.hatipoglu",
    "erdogan.cuvoglu",
    "fatma.karipcin",
    "gonul.dag",
    "gulay.dikmen",
    "hilal.coskun",
    "leyla.dogan",
    "nihat.kedi",
    "selma.delioglu",
    "seyda.uludag",
    "tuncay.karaca",
    "turgay.yumrukaya",
    "yucel.gokce",
    "yuksel.taskin",
    "taner.turan",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Apply changes (default: deactivate)")
    parser.add_argument(
        "--mode",
        choices=["deactivate", "delete"],
        default="deactivate",
        help="deactivate (recommended) or delete (dangerous, may require --purge-audit)",
    )
    parser.add_argument(
        "--purge-audit",
        action="store_true",
        help="When mode=delete: also delete audit_logs/security_events rows for the user first",
    )
    args = parser.parse_args()

    with app.app_context():
        candidates = []
        kept_users = []
        
        for u in User.query.all():
            # KORU: Bilinen kullanıcı adları
            if u.username in BEELIFE_USERNAMES:
                kept_users.append(u)
                continue
            
            # KORU: BeeLife email'leri
            if (u.email or "").lower().endswith("@beelife-cc.com"):
                kept_users.append(u)
                continue
            
            # Geri kalan her şey DEMO - temizlenecek
            candidates.append(u)

        print("=" * 80)
        print("🐝 BEE LIFE CC - DEMO KULLANICI TEMİZLİĞİ")
        print("=" * 80)
        
        print(f"\n✅ KORUNAN KULLANICILAR ({len(kept_users)}):")
        print("-" * 60)
        for u in kept_users:
            print(f"   ✓ {u.username:<25} {u.email or '-':<35} {u.role}")
        
        print(f"\n🗑️  SİLİNECEK DEMO KULLANICILAR ({len(candidates)}):")
        print("-" * 60)
        for u in candidates:
            status = "DEACTIVE" if not u.is_active else "active"
            print(f"   ✗ id={u.id:<4} {u.username:<25} {u.email or '-':<35} {u.role:<12} [{status}]")

        if not args.apply:
            print("\n" + "=" * 80)
            print("⚠️  DRY-RUN: Değişiklik yapılmadı!")
            print("    Uygulamak için: python cleanup_demo_users.py --apply")
            print("=" * 80)
            return

        try:
            if args.mode == "deactivate":
                for u in candidates:
                    # Disable account safely (keeps foreign keys valid)
                    u.is_active = False
                    u.is_locked = True
                    u.lock_reason = "disabled_by_cleanup"

                    # Make login impossible even if something toggles is_active later
                    if u.email and not u.email.startswith("disabled+"):
                        u.email = f"disabled+{u.id}@invalid.local"
                    if not u.username.startswith("disabled_"):
                        u.username = f"disabled_{u.id}_{u.username}"

                db.session.commit()
                print(f"\n✅ {len(candidates)} demo kullanıcı deaktif edildi.")
                return

            # mode == delete
            if not args.purge_audit:
                print("\n❌ --purge-audit olmadan hard-delete yapılamaz (FK ihlali riski).")
                print("   Önerilen: --mode deactivate kullanın.")
                return

            for u in candidates:
                # purge dependent rows first
                AuditLog.query.filter_by(user_id=u.id).delete(synchronize_session=False)
                SecurityEvent.query.filter_by(user_id=u.id).delete(synchronize_session=False)
                db.session.delete(u)

            db.session.commit()
            print(f"\n✅ {len(candidates)} demo kullanıcı silindi (audit kayıtları dahil).")
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ HATA: {e}")
            raise


if __name__ == "__main__":
    main()
