"""Cleanup Demo-User (Dry-Run by default)

Usage:
  python cleanup_demo_users.py            # dry-run
  python cleanup_demo_users.py --apply    # delete

Rules (safe defaults):
- NEVER delete user "Murat66"
- Deletes common demo accounts like username=="admin" and emails ending with "@ai-bee-cc.com" (except Murat66)
"""

import argparse
from app import app, db
from models import User


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Actually delete users")
    args = parser.parse_args()

    with app.app_context():
        q = User.query

        keep_usernames = {"Murat66"}

        candidates = []
        for u in q.all():
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
            print("\nDry-run only. Run with --apply to delete.")
            return

        for u in candidates:
            db.session.delete(u)
        db.session.commit()
        print(f"\nDeleted {len(candidates)} demo users.")


if __name__ == "__main__":
    main()
