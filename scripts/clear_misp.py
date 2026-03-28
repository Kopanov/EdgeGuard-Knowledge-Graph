#!/usr/bin/env python3
"""
EdgeGuard - Clear MISP Events Script

Clears all EdgeGuard-created events from MISP while preserving:
- Taxonomies
- Organizations
- Non-EdgeGuard events
- Users and roles

Usage:
    python3 clear_misp.py [--dry-run] [--force]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import argparse
import logging
from datetime import datetime
from typing import Dict, List

import requests
import urllib3

from config import MISP_API_KEY, MISP_URL, apply_misp_http_host_header

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class MISPClearer:
    """
    Clears EdgeGuard events from MISP.

    Safe deletion:
    - Only deletes events with 'EdgeGuard' in the name
    - Preserves taxonomies, orgs, and other system data
    """

    def __init__(self, url: str = None, api_key: str = None, verify_ssl: bool = False):
        self.url = url or MISP_URL
        self.api_key = api_key or MISP_API_KEY
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}
        )
        apply_misp_http_host_header(self.session)
        self.deleted_count = 0
        self.error_count = 0

    def list_edgeguard_events(self) -> List[Dict]:
        """
        List all EdgeGuard-created events.

        Returns:
            List of event dicts with id, info, date
        """
        events = []

        try:
            # Get all events
            response = self.session.get(
                f"{self.url}/events/index",
                params={"limit": 1000},  # Get up to 1000 events
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code != 200:
                logger.error(f"Failed to list events: {response.status_code}")
                return events

            all_events = response.json()

            # Filter for EdgeGuard events
            for event in all_events:
                info = event.get("info", "")
                if "EdgeGuard" in info:
                    events.append(
                        {
                            "id": event.get("id"),
                            "info": info,
                            "date": event.get("date"),
                            "attribute_count": event.get("attribute_count", 0),
                        }
                    )

            logger.info(f"Found {len(events)} EdgeGuard events")
            return events

        except Exception as e:
            logger.error(f"Error listing events: {e}")
            return events

    def delete_event(self, event_id: str) -> bool:
        """
        Delete a single event by ID.

        Args:
            event_id: MISP event ID

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            response = self.session.delete(
                f"{self.url}/events/{event_id}",
                verify=self.verify_ssl,
                timeout=30,
                allow_redirects=True,  # MISP may return 302 on successful DELETE
            )

            if response.status_code in (200, 302):
                logger.info(f"✅ Deleted event {event_id}")
                return True
            else:
                logger.error(f"❌ Failed to delete event {event_id}: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"❌ Error deleting event {event_id}: {e}")
            return False

    def clear_all(self, dry_run: bool = False) -> Dict:
        """
        Clear all EdgeGuard events from MISP.

        Args:
            dry_run: If True, only show what would be deleted

        Returns:
            Dict with deletion summary
        """
        logger.info("=" * 60)
        logger.info("🧹 MISP Clear Operation")
        logger.info("=" * 60)

        # List EdgeGuard events
        events = self.list_edgeguard_events()

        if not events:
            logger.info("No EdgeGuard events found to delete")
            return {"success": True, "deleted": 0, "errors": 0, "message": "No EdgeGuard events found"}

        # Show events to be deleted
        logger.info(f"\nEvents to {'DELETE' if not dry_run else '(DRY RUN)'}:")
        for event in events:
            logger.info(f"  - [{event['id']}] {event['info']} ({event['attribute_count']} attributes)")

        if dry_run:
            logger.info(f"\n🔍 Dry run complete. Would delete {len(events)} events.")
            return {"success": True, "deleted": 0, "errors": 0, "would_delete": len(events), "dry_run": True}

        # Confirm deletion
        logger.info(f"\n⚠️  About to delete {len(events)} EdgeGuard events")
        logger.info("This will NOT affect taxonomies, organizations, or other system data.")

        # Delete events
        self.deleted_count = 0
        self.error_count = 0

        for event in events:
            if self.delete_event(event["id"]):
                self.deleted_count += 1
            else:
                self.error_count += 1

        logger.info("\n" + "=" * 60)
        logger.info("✅ MISP Clear Complete")
        logger.info("=" * 60)
        logger.info(f"Deleted: {self.deleted_count} events")
        logger.info(f"Errors: {self.error_count}")

        return {
            "success": self.error_count == 0,
            "deleted": self.deleted_count,
            "errors": self.error_count,
            "total": len(events),
        }

    def clear_old_events(self, days: int = 30, dry_run: bool = False) -> Dict:
        """
        Clear EdgeGuard events older than specified days.

        Args:
            days: Delete events older than this many days
            dry_run: If True, only show what would be deleted

        Returns:
            Dict with deletion summary
        """
        from datetime import timedelta, timezone

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        logger.info("=" * 60)
        logger.info(f"🧹 MISP Clear Old Events (>{days} days)")
        logger.info("=" * 60)

        # List EdgeGuard events
        events = self.list_edgeguard_events()

        # Filter by age
        old_events = []
        for event in events:
            try:
                event_date = datetime.strptime(event["date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if event_date < cutoff_date:
                    old_events.append(event)
            except (ValueError, KeyError, TypeError):
                # If date parsing fails, include it to be safe
                old_events.append(event)

        if not old_events:
            logger.info(f"No EdgeGuard events older than {days} days found")
            return {"success": True, "deleted": 0, "errors": 0, "message": f"No events older than {days} days"}

        # Show events to be deleted
        logger.info(f"\nEvents to {'DELETE' if not dry_run else '(DRY RUN)'}:")
        for event in old_events:
            logger.info(f"  - [{event['id']}] {event['info']} ({event['date']})")

        if dry_run:
            logger.info(f"\n🔍 Dry run complete. Would delete {len(old_events)} old events.")
            return {"success": True, "deleted": 0, "errors": 0, "would_delete": len(old_events), "dry_run": True}

        # Delete old events
        deleted = 0
        errors = 0

        for event in old_events:
            if self.delete_event(event["id"]):
                deleted += 1
            else:
                errors += 1

        logger.info("\n" + "=" * 60)
        logger.info("✅ MISP Clear Old Events Complete")
        logger.info("=" * 60)
        logger.info(f"Deleted: {deleted} events")
        logger.info(f"Errors: {errors}")

        return {"success": errors == 0, "deleted": deleted, "errors": errors, "total": len(old_events)}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Clear EdgeGuard events from MISP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 clear_misp.py --dry-run          # Preview what would be deleted
  python3 clear_misp.py --force            # Delete all EdgeGuard events
  python3 clear_misp.py --old 7            # Delete events older than 7 days
        """,
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be deleted without deleting")
    parser.add_argument("--force", "-f", action="store_true", help="Skip confirmation and delete immediately")
    parser.add_argument("--old", "-o", type=int, metavar="DAYS", help="Delete events older than DAYS days")

    args = parser.parse_args()

    # Require explicit action
    if not args.dry_run and not args.force and args.old is None:
        parser.print_help()
        print("\n⚠️  No action specified. Use --dry-run to preview, --force to delete, or --old DAYS for old events.")
        sys.exit(1)

    clearer = MISPClearer()

    if args.old is not None:
        result = clearer.clear_old_events(days=args.old, dry_run=args.dry_run)
    else:
        result = clearer.clear_all(dry_run=args.dry_run)

    # Clear checkpoint file so MITRE ETag and other cursors are reset
    if result.get("success") and not args.dry_run:
        try:
            from baseline_checkpoint import clear_checkpoint

            clear_checkpoint()
            logger.info("Cleared baseline checkpoint (ETag/cursor cache)")
        except Exception as e:
            logger.warning("Could not clear checkpoint: %s", e)

    # Exit with appropriate code
    if result.get("success"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
