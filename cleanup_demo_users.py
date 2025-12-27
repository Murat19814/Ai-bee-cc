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
- Candidates are common demo accounts like username=="admin" and emails ending with "@ai-bee-cc.com"
"""

import argparse

from app import app, db
from models import AuditLog, SecurityEvent, User


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
        keep_usernames = {"Murat66"}

        candidates = []
        for u in User.query.all():
            if u.username in keep_usernames:
                continue

            is_demo = False
            if u.username == "admin":
                is_demo = True
            if (u.email or "").lower().endswith("@ai-bee-cc.com"):
                is_demo = True

            if is_demo:
                candidates.append(u)

        print("=" * 80)
        print(f"Demo candidates: {len(candidates)}")
        for u in candidates:
            print(f"- id={u.id} tenant_id={u.tenant_id} username={u.username} email={u.email} role={u.role}")

        if not args.apply:
            print("\nDry-run only. Run with --apply to apply changes.")
            return

        try:
            if args.mode == "deactivate":
                for u in candidates:
                    # Disable account safely (keeps foreign keys valid)
                    u.is_active = False
                    u.is_locked = True
                    u.lock_reason = "disabled_by_cleanup"

                    # Make login impossible even if something toggles is_active later
                    if u.email:
                        u.email = f"disabled+{u.id}@invalid.local"
                    u.username = f"disabled_{u.id}_{u.username}"

                db.session.commit()
                print(f"\nDeactivated {len(candidates)} demo users.")
                return

            # mode == delete
            if not args.purge_audit:
                print("\nRefusing to hard-delete without --purge-audit (to avoid FK violations).")
                print("Tip: use --mode deactivate (recommended).")
                return

            for u in candidates:
                # purge dependent rows first
                AuditLog.query.filter_by(user_id=u.id).delete(synchronize_session=False)
                SecurityEvent.query.filter_by(user_id=u.id).delete(synchronize_session=False)
                db.session.delete(u)

            db.session.commit()
            print(f"\nDeleted {len(candidates)} demo users (with audit/security purge).")
        except Exception:
            db.session.rollback()
            raise


if __name__ == "__main__":
    main()
