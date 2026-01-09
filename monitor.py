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
import os
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
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
POLL_INTERVAL_SEC = 300  # 5 minutes
STATUS_REPORT_INTERVAL_SEC = 2 * 60 * 60  # 2 hours
EQUITY_DROP_THRESHOLD = 0.10  # 10% drop triggers alert
POSITION_ALERT_MULTIPLIER = 5  # Alert if position > order_size * 5
STATUS_LOG_FILE = "status.log"


def send_notify(title: str, message: str, channel: str = "info", priority: str = "normal"):
    """Send notification via Telegram.
    
    Requires environment variables:
        NOTIFY_URL: Notification service URL (e.g., http://localhost:8000/notify)
        NOTIFY_API_KEY: API key for the notification service
    
    See: https://github.com/frozen-cherry/tg-notify
    """
    notify_url = os.environ.get("NOTIFY_URL", "")
    notify_api_key = os.environ.get("NOTIFY_API_KEY", "")
    
    if not notify_url:
        return  # Notification not configured
    
    try:
        headers = {}
        if notify_api_key:
            headers["X-API-Key"] = notify_api_key
        
        requests.post(
            notify_url,
            json={"title": title, "message": message, "channel": channel, "priority": priority},
            headers=headers,
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
    position: float = 0.0  # Position size (negative = short)
    upnl: float = 0.0  # Unrealized PnL
    trader_pts: float = 0.0
    maker_pts: float = 0.0
    holder_pts: float = 0.0
    uptime_12h: str = ""  # 12-hour uptime visualization ████░░░░
    latency_avg: float = 0.0  # Average latency in ms
    latency_max: float = 0.0  # Max latency in ms
    low_equity_alerted: bool = False
    high_position_alerted: bool = False


def read_latency_stats(config_path: str, window_hours: float = 2.0) -> tuple:
    """
    Read latency log file and compute stats for recent window.
    
    Returns:
        (avg_ms, max_ms) or (0, 0) if no data
    """
    import os
    from datetime import datetime, timedelta
    
    config_name = config_path.replace(".yaml", "").replace(".yml", "")
    log_file = f"latency_{config_name}.log"
    
    if not os.path.exists(log_file):
        return (0.0, 0.0)
    
    try:
        cutoff_time = datetime.now() - timedelta(hours=window_hours)
        latencies = []
        
        with open(log_file, "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 3:
                    timestamp_str, endpoint, latency_ms = parts[0], parts[1], parts[2]
                    try:
                        ts = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        if ts >= cutoff_time:
                            latencies.append(float(latency_ms))
                    except:
                        pass
        
        if latencies:
            return (sum(latencies) / len(latencies), max(latencies))
        return (0.0, 0.0)
    except:
        return (0.0, 0.0)


async def query_balance(auth: StandXAuth) -> Dict:
    """Query account balance and position."""
    url = "https://perps.standx.com/api/query_balance"
    headers = auth.get_auth_headers()
    headers["Accept"] = "application/json"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


async def query_position(auth: StandXAuth, symbol: str) -> Dict:
    """Query position for a symbol."""
    url = f"https://perps.standx.com/api/query_positions?symbol={symbol}"
    headers = auth.get_auth_headers()
    headers["Accept"] = "application/json"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Handle both list and dict response formats
        if isinstance(data, list):
            positions = data
        else:
            positions = data.get("positions", [])
        
        if positions:
            return positions[0]
        return {}


def build_uptime_bar(hours_data: List[Dict]) -> str:
    """Build 12-hour uptime visualization bar.
    
    █ = UP (has data for that hour)
    ░ = DOWN (no data for that hour)
    
    Returns a string like: ████░░░░████ (oldest to newest, left to right)
    """
    now = datetime.now(timezone.utc)
    # Round down to current hour
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    
    # Build set of hours that have uptime data
    uptime_hours = set()
    for h in hours_data:
        hour_str = h.get("hour", "")
        try:
            dt = datetime.fromisoformat(hour_str.replace("Z", "+00:00"))
            uptime_hours.add(dt.replace(minute=0, second=0, microsecond=0))
        except:
            pass
    
    # Build bar for last 12 hours (oldest to newest)
    bar = ""
    for i in range(11, -1, -1):  # 11 hours ago to now
        hour = current_hour - timedelta(hours=i)
        if hour in uptime_hours:
            bar += "█"
        else:
            bar += "░"
    
    return bar


async def query_all_stats(auth: StandXAuth) -> Dict:
    """Query all points and uptime for an account."""
    stats = {
        "trader_pts": 0.0,
        "maker_pts": 0.0,
        "holder_pts": 0.0,
        "uptime_12h": "░" * 12,  # Default: all down
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
        
        # Uptime (12 hours visualization)
        try:
            uptime_headers = auth.get_auth_headers("")
            uptime_headers["Accept"] = "application/json"
            r = await client.get("https://perps.standx.com/api/maker/uptime", headers=uptime_headers)
            if r.status_code == 200:
                hours = r.json().get("hours", [])
                stats["uptime_12h"] = build_uptime_bar(hours)
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
        # Query balance
        balance_data = await query_balance(account.auth)
        account.current_equity = float(balance_data.get("equity", 0) or 0)
        account.upnl = float(balance_data.get("upnl", 0) or 0)
        
        # Query position
        pos_data = await query_position(account.auth, account.config.symbol)
        account.position = float(pos_data.get("qty", 0) or 0)
        
        # Query stats
        stats = await query_all_stats(account.auth)
        account.trader_pts = stats["trader_pts"]
        account.maker_pts = stats["maker_pts"]
        account.holder_pts = stats["holder_pts"]
        account.uptime_12h = stats["uptime_12h"]
        
        # Read latency stats from log file
        account.latency_avg, account.latency_max = read_latency_stats(account.config_path)
        
        return True
    except Exception as e:
        logger.error(f"Failed to poll {account.config_path}: {e}")
        return False


def check_equity_alert(account: AccountState):
    """Check if equity dropped below threshold and send alert.
    
    After alerting, resets baseline to current equity so next alert
    only triggers on another 10% drop from the new baseline.
    """
    if account.initial_equity <= 0:
        return
    
    drop_ratio = (account.initial_equity - account.current_equity) / account.initial_equity
    
    if drop_ratio >= EQUITY_DROP_THRESHOLD:
        msg = (
            f"{account.config_path} 余额告警! "
            f"基准${account.initial_equity:,.0f} → 当前${account.current_equity:,.0f} "
            f"(降{drop_ratio*100:.1f}%)"
        )
        send_notify("余额告警", msg, channel="alert", priority="critical")
        
        # Reset baseline to current equity
        # Next alert will only trigger on another 10% drop from here
        account.initial_equity = account.current_equity


def check_position_alert(account: AccountState):
    """Check if position exceeds threshold and send alert."""
    order_size = account.config.order_size_btc
    threshold = order_size * POSITION_ALERT_MULTIPLIER
    
    if abs(account.position) > threshold and not account.high_position_alerted:
        account.high_position_alerted = True
        name = account.config_path.replace(".yaml", "").replace("config-", "").replace("config", "main")
        msg = f"{name} 仓位告警: {account.position:.4f} BTC (阈值: ±{threshold:.4f})"
        send_notify("仓位告警", msg, channel="info", priority="normal")
    
    # Reset alert if position reduced
    if abs(account.position) < threshold * 0.5:
        account.high_position_alerted = False


def send_status_report(accounts: List[AccountState]):
    """Send periodic status report."""
    lines = []
    for acc in accounts:
        name = acc.config_path.replace(".yaml", "").replace("config-", "").replace("config", "main")
        # Format: name: $equity pos uPNL pts uptime latency
        pos_str = f"pos:{acc.position:+.4f}"
        upnl_str = f"uPNL:{acc.upnl:+.2f}"
        pts_str = f"T{acc.trader_pts:.0f}/M{acc.maker_pts:.0f}/H{acc.holder_pts:.0f}"
        uptime_str = f"[{acc.uptime_12h}]"
        
        # Latency with warning indicator
        if acc.latency_avg > 0:
            latency_warning = "⚠️" if acc.latency_avg > 200 or acc.latency_max > 1000 else ""
            latency_str = f"延迟:{acc.latency_avg:.0f}/{acc.latency_max:.0f}ms{latency_warning}"
        else:
            latency_str = "延迟:-"
        
        lines.append(f"{name}: ${acc.current_equity:,.0f} {pos_str} {upnl_str} {pts_str} {uptime_str} {latency_str}")
    
    msg = "\n".join(lines)
    send_notify("StandX 状态", msg, channel="info", priority="normal")


def write_status_log(accounts: List[AccountState]):
    """Write current status to log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [f"=== StandX Monitor Status @ {timestamp} ===", ""]
    
    for acc in accounts:
        name = acc.config_path.replace(".yaml", "").replace("config-", "").replace("config", "main")
        lines.append(f"Account: {name}")
        lines.append(f"  Equity:     ${acc.current_equity:,.2f}")
        lines.append(f"  Position:   {acc.position:+.4f} BTC")
        lines.append(f"  uPNL:       ${acc.upnl:+.2f}")
        lines.append(f"  Points:     T{acc.trader_pts:.0f} / M{acc.maker_pts:.0f} / H{acc.holder_pts:.0f}")
        lines.append(f"  Uptime 12h: [{acc.uptime_12h}]")
        lines.append(f"  Latency:    avg {acc.latency_avg:.0f}ms / max {acc.latency_max:.0f}ms")
        lines.append("")
    
    # Overwrite the file with current status
    with open(STATUS_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


async def monitor_loop(accounts: List[AccountState]):
    """Main monitoring loop."""
    last_report_time = 0
    
    # Poll all accounts first to get points
    for account in accounts:
        await poll_account(account)
    
    # Send initial status report and write log
    send_status_report(accounts)
    write_status_log(accounts)
    last_report_time = time.time()
    
    while True:
        # Poll all accounts
        for account in accounts:
            success = await poll_account(account)
            if success:
                check_equity_alert(account)
                check_position_alert(account)
        
        # Write status log after each poll
        write_status_log(accounts)
        
        # Periodic status report (every 2 hours)
        now = time.time()
        if now - last_report_time >= STATUS_REPORT_INTERVAL_SEC:
            send_status_report(accounts)
            last_report_time = now
        
        # Wait before next poll
        await asyncio.sleep(POLL_INTERVAL_SEC)


async def main(config_paths: List[str]):
    """Main entry point."""
    # Check notification configuration
    notify_url = os.environ.get("NOTIFY_URL", "")
    notify_api_key = os.environ.get("NOTIFY_API_KEY", "")
    
    logger.info("=" * 50)
    logger.info("Notification Configuration:")
    if notify_url:
        logger.info(f"  NOTIFY_URL: {notify_url}")
        logger.info(f"  NOTIFY_API_KEY: {'*' * 8 if notify_api_key else '(not set)'}")
        logger.info("  -> Telegram notifications ENABLED")
    else:
        logger.info("  NOTIFY_URL: (not set)")
        logger.info("  -> Telegram notifications DISABLED")
        logger.info("  -> Alerts will only be logged locally")
    logger.info("=" * 50)
    
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
    
    # Auto-detect config files if none specified
    if not config_paths:
        import glob
        all_yamls = glob.glob("*.yaml") + glob.glob("*.yml")
        # Exclude example config
        config_paths = [f for f in all_yamls if not f.startswith("config.example")]
        
        if config_paths:
            print(f"Auto-detected config files: {config_paths}")
        else:
            print("No config files found.")
            print("Usage: python monitor.py config1.yaml config2.yaml ...")
            print("   or: python monitor.py -c config1.yaml -c config2.yaml")
            exit(1)
    
    asyncio.run(main(config_paths))
