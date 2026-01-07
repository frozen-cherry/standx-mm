"""StandX Account Monitor Script.

Monitors multiple accounts and sends alerts via Telegram.

Usage:
    python monitor.py config1.yaml config2.yaml config3.yaml
    python monitor.py -c config1.yaml -c config2.yaml
"""
import asyncio
import argparse
import time
import logging
from dataclasses import dataclass
from typing import List, Dict

import requests
import httpx

from config import load_config, Config
from api.auth import StandXAuth


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# Constants
POLL_INTERVAL_SEC = 60  # 1 minute
STATUS_REPORT_INTERVAL_SEC = 2 * 60 * 60  # 2 hours
EQUITY_DROP_THRESHOLD = 0.10  # 10% drop triggers alert


def send_notify(title: str, message: str, channel: str = "info", priority: str = "normal"):
    """Send notification via Telegram."""
    try:
        requests.post(
            "http://81.92.219.140:8000/notify",
            json={"title": title, "message": message, "channel": channel, "priority": priority},
            headers={"X-API-Key": "bananaisgreat"},
            timeout=10,
        )
        logger.info(f"Notification sent: [{priority}] {title}")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")


@dataclass
class AccountState:
    """Tracks an account's monitoring state."""
    config_path: str
    config: Config
    auth: StandXAuth
    initial_equity: float = 0.0
    current_equity: float = 0.0
    trader_pts: float = 0.0
    maker_pts: float = 0.0
    holder_pts: float = 0.0
    uptime_tier: str = "-"
    uptime_eligible: float = 0.0
    low_equity_alerted: bool = False


async def query_balance(auth: StandXAuth) -> Dict:
    """Query account balance."""
    url = "https://perps.standx.com/api/query_balance"
    headers = auth.get_auth_headers()
    headers["Accept"] = "application/json"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


async def query_all_stats(auth: StandXAuth) -> Dict:
    """Query all points and uptime for an account."""
    stats = {
        "trader_pts": 0.0,
        "maker_pts": 0.0,
        "holder_pts": 0.0,
        "uptime_tier": "N/A",
        "uptime_eligible": 0.0,
    }
    
    headers = {"Authorization": f"Bearer {auth.token}", "Accept": "application/json"}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Trading campaign (Trader Points)
        try:
            r = await client.get("https://api.standx.com/v1/offchain/trading-campaign/points", headers=headers)
            if r.status_code == 200:
                stats["trader_pts"] = float(r.json().get("trading_point", 0) or 0) / 1_000_000
        except:
            pass
        
        # Maker campaign (Maker Points)
        try:
            r = await client.get("https://api.standx.com/v1/offchain/maker-campaign/points", headers=headers)
            if r.status_code == 200:
                stats["maker_pts"] = float(r.json().get("maker_point", 0) or 0) / 1_000_000
        except:
            pass
        
        # Perps campaign (Holder Points)
        try:
            r = await client.get("https://api.standx.com/v1/offchain/perps-campaign/points", headers=headers)
            if r.status_code == 200:
                stats["holder_pts"] = float(r.json().get("total_point", 0) or 0) / 1_000_000
        except:
            pass
        
        # Uptime (most recent hour)
        try:
            uptime_headers = auth.get_auth_headers("")
            uptime_headers["Accept"] = "application/json"
            r = await client.get("https://perps.standx.com/api/maker/uptime", headers=uptime_headers)
            if r.status_code == 200:
                hours = r.json().get("hours", [])
                if hours:
                    latest = hours[-1]  # Most recent hour
                    tier = latest.get("tier", "")
                    tier_map = {"tier_a": "A", "tier_b": "B", "tier_c": "C", "tier_d": "D"}
                    stats["uptime_tier"] = tier_map.get(tier, "-")
                    stats["uptime_eligible"] = latest.get("eligible_hour", 0)
        except:
            pass
    
    return stats


async def init_account(config_path: str) -> AccountState:
    """Initialize an account for monitoring."""
    config = load_config(config_path)
    auth = StandXAuth()
    
    logger.info(f"Authenticating: {config_path}")
    await auth.authenticate(config.wallet.chain, config.wallet.private_key)
    
    # Get initial balance
    balance_data = await query_balance(auth)
    equity = float(balance_data.get("equity", 0) or 0)
    
    logger.info(f"Account {config_path}: Initial equity ${equity:,.2f}")
    
    return AccountState(
        config_path=config_path,
        config=config,
        auth=auth,
        initial_equity=equity,
        current_equity=equity,
    )


async def poll_account(account: AccountState) -> bool:
    """Poll account status. Returns True if successful."""
    try:
        balance_data = await query_balance(account.auth)
        account.current_equity = float(balance_data.get("equity", 0) or 0)
        
        stats = await query_all_stats(account.auth)
        account.trader_pts = stats["trader_pts"]
        account.maker_pts = stats["maker_pts"]
        account.holder_pts = stats["holder_pts"]
        account.uptime_tier = stats["uptime_tier"]
        account.uptime_eligible = stats["uptime_eligible"]
        return True
    except Exception as e:
        logger.error(f"Failed to poll {account.config_path}: {e}")
        return False


def check_equity_alert(account: AccountState):
    """Check if equity dropped below threshold and send alert."""
    if account.initial_equity <= 0:
        return
    
    drop_ratio = (account.initial_equity - account.current_equity) / account.initial_equity
    
    if drop_ratio >= EQUITY_DROP_THRESHOLD and not account.low_equity_alerted:
        account.low_equity_alerted = True
        msg = (
            f"{account.config_path} 余额告警! "
            f"初始${account.initial_equity:,.0f} → 当前${account.current_equity:,.0f} "
            f"(降{drop_ratio*100:.1f}%)"
        )
        send_notify("余额告警", msg, channel="alert", priority="critical")
    
    # Reset alert if equity recovered
    if drop_ratio < EQUITY_DROP_THRESHOLD * 0.8:
        account.low_equity_alerted = False


def send_status_report(accounts: List[AccountState]):
    """Send periodic status report."""
    lines = []
    for acc in accounts:
        name = acc.config_path.replace(".yaml", "").replace("config-", "").replace("config", "main")
        # Format: name: $equity T/M/H pts Uptime
        pts_str = f"T{acc.trader_pts:.0f}/M{acc.maker_pts:.0f}/H{acc.holder_pts:.0f}"
        uptime_str = f"U:{acc.uptime_tier}"
        lines.append(f"{name}: ${acc.current_equity:,.0f} {pts_str} {uptime_str}")
    
    msg = "\n".join(lines)
    send_notify("StandX 状态", msg, channel="info", priority="normal")


async def monitor_loop(accounts: List[AccountState]):
    """Main monitoring loop."""
    last_report_time = 0
    
    # Poll all accounts first to get points
    for account in accounts:
        await poll_account(account)
    
    # Send initial status report
    send_status_report(accounts)
    last_report_time = time.time()
    
    while True:
        # Poll all accounts
        for account in accounts:
            success = await poll_account(account)
            if success:
                check_equity_alert(account)
        
        # Periodic status report (every 2 hours)
        now = time.time()
        if now - last_report_time >= STATUS_REPORT_INTERVAL_SEC:
            send_status_report(accounts)
            last_report_time = now
        
        # Wait before next poll
        await asyncio.sleep(POLL_INTERVAL_SEC)


async def main(config_paths: List[str]):
    """Main entry point."""
    logger.info(f"Starting monitor for {len(config_paths)} accounts")
    
    # Initialize all accounts
    accounts = []
    for path in config_paths:
        try:
            account = await init_account(path)
            accounts.append(account)
        except Exception as e:
            logger.error(f"Failed to init {path}: {e}")
    
    if not accounts:
        logger.error("No accounts initialized, exiting")
        return
    
    logger.info(f"Monitoring {len(accounts)} accounts, poll interval {POLL_INTERVAL_SEC}s")
    
    try:
        await monitor_loop(accounts)
    except KeyboardInterrupt:
        logger.info("Monitor stopped")


def parse_args():
    parser = argparse.ArgumentParser(description="StandX Account Monitor")
    parser.add_argument(
        "configs",
        nargs="*",
        help="Config files to monitor",
    )
    parser.add_argument(
        "-c", "--config",
        action="append",
        dest="extra_configs",
        help="Additional config file (can be used multiple times)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Collect all config paths
    config_paths = args.configs or []
    if args.extra_configs:
        config_paths.extend(args.extra_configs)
    
    if not config_paths:
        print("Usage: python monitor.py config1.yaml config2.yaml ...")
        print("   or: python monitor.py -c config1.yaml -c config2.yaml")
        exit(1)
    
    asyncio.run(main(config_paths))
