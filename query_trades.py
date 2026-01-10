"""Query trade history from StandX API."""
import asyncio
import json
import httpx
import yaml
import argparse
from datetime import datetime, timedelta

from api.auth import StandXAuth


async def query_trades(auth: StandXAuth, symbol: str = None, limit: int = 100, start: str = None, end: str = None):
    """Query trade history."""
    headers = auth.get_auth_headers()
    headers["Accept"] = "application/json"
    
    params = {"limit": limit}
    if symbol:
        params["symbol"] = symbol
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            "https://perps.standx.com/api/query_trades",
            headers=headers,
            params=params
        )
        return response.json()


async def main():
    parser = argparse.ArgumentParser(description="Query trade history")
    parser.add_argument("-c", "--config", default="config-bot2.yaml", help="Config file")
    parser.add_argument("-s", "--symbol", help="Filter by symbol (e.g., ETH-USD)")
    parser.add_argument("-l", "--limit", type=int, default=50, help="Number of trades to fetch")
    parser.add_argument("-d", "--days", type=int, default=7, help="Days of history")
    args = parser.parse_args()
    
    # Load config
    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    # Create auth
    auth = StandXAuth()
    await auth.authenticate(config["wallet"]["chain"], config["wallet"]["private_key"])
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=args.days)
    
    # Query trades
    print(f"Querying trades from {start_time.isoformat()}Z to {end_time.isoformat()}Z")
    if args.symbol:
        print(f"Symbol filter: {args.symbol}")
    print(f"Limit: {args.limit}")
    print("=" * 80)
    
    trades = await query_trades(
        auth,
        symbol=args.symbol,
        limit=args.limit,
        start=start_time.isoformat() + "Z",
        end=end_time.isoformat() + "Z"
    )
    
    # Print raw response first
    if isinstance(trades, dict) and "error" in trades:
        print(f"Error: {trades}")
        return
    
    # Parse and display
    if isinstance(trades, list):
        trade_list = trades
    else:
        trade_list = trades.get("result", trades.get("trades", []))
    
    if not trade_list:
        print("No trades found")
        return
    
    # Aggregate trades with same time, side, price
    aggregated = []
    current_key = None
    current_trade = None
    
    for trade in trade_list:
        time_str = trade.get("time", trade.get("created_at", "N/A"))[:19]  # Truncate to second
        symbol = trade.get("symbol", "N/A")
        side = trade.get("side", "N/A")
        price = float(trade.get("price", 0))
        qty = float(trade.get("qty", 0))
        pnl = float(trade.get("pnl", trade.get("realized_pnl", 0)))
        
        key = (time_str, symbol, side, price)
        
        if current_key == key:
            # Same trade, aggregate
            current_trade["qty"] += qty
            current_trade["pnl"] += pnl
        else:
            # New trade
            if current_trade:
                aggregated.append(current_trade)
            current_key = key
            current_trade = {
                "time": time_str,
                "symbol": symbol,
                "side": side,
                "price": price,
                "qty": qty,
                "pnl": pnl
            }
    
    if current_trade:
        aggregated.append(current_trade)
    
    print(f"Found {len(trade_list)} trades, aggregated to {len(aggregated)} entries:\n")
    
    # Summary
    total_pnl = 0
    buy_qty = 0
    sell_qty = 0
    
    for trade in aggregated:
        pnl_str = f"${trade['pnl']:+.2f}" if trade['pnl'] != 0 else ""
        print(f"{trade['time']} | {trade['symbol']:8} | {trade['side']:4} | qty: {trade['qty']:8.4f} @ {trade['price']:10.2f} {pnl_str}")
        
        total_pnl += trade['pnl']
        if trade['side'] == "buy":
            buy_qty += trade['qty']
        else:
            sell_qty += trade['qty']
    
    print("\n" + "=" * 80)
    print(f"Summary:")
    print(f"  Total trades:    {len(aggregated)}")
    print(f"  Total buy qty:   {buy_qty:.4f}")
    print(f"  Total sell qty:  {sell_qty:.4f}")
    print(f"  Total PnL:       ${total_pnl:+.2f}")


if __name__ == "__main__":
    asyncio.run(main())
