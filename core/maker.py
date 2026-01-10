"""Market making logic for StandX Maker Bot.

Event-driven design:
- Price updates trigger order checks
- Order placement runs when conditions are met
"""
import uuid
import logging
import asyncio
from typing import Optional

import requests

from config import Config
from api.http_client import StandXHTTPClient
from core.state import State, OpenOrder


logger = logging.getLogger(__name__)


def send_notify(title: str, message: str, priority: str = "normal"):
    """Send notification via Telegram.
    
    Requires environment variables:
        NOTIFY_URL: Notification service URL
        NOTIFY_API_KEY: API key for the notification service
    """
    import os
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
            json={"title": title, "message": message, "channel": "alert", "priority": priority},
            headers=headers,
            timeout=5,
        )
    except:
        pass  # Don't let notification failure affect trading


class Maker:
    """Market making logic."""
    
    def __init__(self, config: Config, client: StandXHTTPClient, state: State):
        self.config = config
        self.client = client
        self.state = state
        self._running = False
        self._pending_check = asyncio.Event()
        self._reduce_log_file = None  # Will be set by main.py
    
    async def initialize(self):
        """Initialize state from exchange."""
        logger.info("Initializing state from exchange...")
        
        # Get current position
        positions = await self.client.query_positions(self.config.symbol)
        if positions:
            self.state.update_position(positions[0].qty)
        else:
            self.state.update_position(0.0)
        
        # Get current open orders
        orders = await self.client.query_open_orders(self.config.symbol)
        
        for order in orders:
            if order.side == "buy":
                self.state.set_order("buy", OpenOrder(
                    cl_ord_id=order.cl_ord_id,
                    side="buy",
                    price=float(order.price),
                    qty=float(order.qty),
                ))
            elif order.side == "sell":
                self.state.set_order("sell", OpenOrder(
                    cl_ord_id=order.cl_ord_id,
                    side="sell",
                    price=float(order.price),
                    qty=float(order.qty),
                ))
        
        logger.info(
            f"Initialized: position={self.state.position}, "
            f"buy_order={self.state.has_order('buy')}, "
            f"sell_order={self.state.has_order('sell')}"
        )
    
    def on_price_update(self, price: float):
        """
        Called when price updates from WebSocket.
        Triggers order check if needed.
        """
        self.state.update_price(price, self.config.volatility_window_sec)
        
        # Signal that we need to check orders
        self._pending_check.set()
    
    async def run(self):
        """Run the event-driven maker loop."""
        self._running = True
        logger.info("Maker started (event-driven mode)")
        
        while self._running:
            try:
                # Wait for price update signal (with timeout for periodic checks)
                try:
                    await asyncio.wait_for(self._pending_check.wait(), timeout=5.0)
                    self._pending_check.clear()
                except asyncio.TimeoutError:
                    # Periodic check even without price updates
                    pass
                
                await self._tick()
                
            except Exception as e:
                logger.error(f"Maker tick error: {e}", exc_info=True)
                await asyncio.sleep(1)  # Brief pause on error
        
        logger.info("Maker stopped")
    
    async def stop(self):
        """Stop the maker loop."""
        self._running = False
        self._pending_check.set()  # Wake up the loop
    
    async def _tick(self):
        """Single iteration of the maker logic."""
        # Wait for price data
        if self.state.last_price is None:
            logger.debug("Waiting for price data...")
            return
        
        # Step 1: Check position
        if abs(self.state.position) >= self.config.max_position_btc:
            logger.warning(
                f"Position too large: {self.state.position} >= {self.config.max_position_btc}, "
                "pausing market making"
            )
            return
        
        # Step 1.5: Check if should reduce position (> 50% and profitable)
        reduced = await self._check_and_reduce_position()
        if reduced:
            return  # Skip this tick after reducing
        
        # Step 2: Check and cancel orders that are too close or too far
        orders_to_cancel = self.state.get_orders_to_cancel(
            self.config.cancel_distance_bps,
            self.config.rebalance_distance_bps
        )
        
        if orders_to_cancel:
            for order in orders_to_cancel:
                logger.info(f"Cancelling order: {order.cl_ord_id}")
                try:
                    await self.client.cancel_order(order.cl_ord_id)
                    self.state.set_order(order.side, None)
                except Exception as e:
                    logger.error(f"Failed to cancel order {order.cl_ord_id}: {e}")
                    send_notify(
                        "StandX 撤单失败",
                        f"{self.config.symbol} 撤单失败: {e}",
                        priority="high"
                    )
            
            # Don't place new orders this tick
            return
        
        # Step 3: Check volatility
        volatility = self.state.get_volatility_bps()
        if volatility > self.config.volatility_threshold_bps:
            logger.debug(
                f"Volatility too high: {volatility:.2f}bps > {self.config.volatility_threshold_bps}bps"
            )
            return
        
        # Step 4: Place missing orders
        await self._place_missing_orders()
    
    async def _place_missing_orders(self):
        """Place buy and sell orders if missing."""
        last_price = self.state.last_price
        if last_price is None:
            return
        
        # Calculate order prices
        buy_price = last_price * (1 - self.config.order_distance_bps / 10000)
        sell_price = last_price * (1 + self.config.order_distance_bps / 10000)
        
        # Place buy order if missing
        if not self.state.has_order("buy"):
            await self._place_order("buy", buy_price)
        
        # Place sell order if missing
        if not self.state.has_order("sell"):
            await self._place_order("sell", sell_price)
    
    async def _place_order(self, side: str, price: float):
        """Place a single order."""
        import math
        cl_ord_id = f"mm-{side}-{uuid.uuid4().hex[:8]}"
        
        # Different tick sizes for different symbols
        if self.config.symbol.startswith("BTC"):
            tick_size = 0.01
            price_decimals = 2
        else:
            tick_size = 0.1
            price_decimals = 1
        
        # Align price to tick (floor for buy, ceil for sell)
        if side == "buy":
            aligned_price = math.floor(price / tick_size) * tick_size
        else:
            aligned_price = math.ceil(price / tick_size) * tick_size
        price_str = f"{aligned_price:.{price_decimals}f}"
        qty_str = f"{self.config.order_size_btc:.3f}"
        
        logger.info(f"Placing {side} order: {qty_str} @ {price_str} (cl_ord_id: {cl_ord_id})")
        
        try:
            response = await self.client.new_order(
                symbol=self.config.symbol,
                side=side,
                qty=qty_str,
                price=price_str,
                cl_ord_id=cl_ord_id,
            )
            
            if response.get("code") == 0:
                # Update local state
                self.state.set_order(side, OpenOrder(
                    cl_ord_id=cl_ord_id,
                    side=side,
                    price=price,
                    qty=self.config.order_size_btc,
                ))
                logger.info(f"Order placed successfully: {cl_ord_id}")
            else:
                error_msg = response.get("message", str(response))
                logger.error(f"Order failed: {response}")
                send_notify(
                    "StandX 下单失败",
                    f"{self.config.symbol} {side} 下单失败: {error_msg}",
                    priority="high"
                )
                
        except Exception as e:
            logger.error(f"Failed to place {side} order: {e}")
            send_notify(
                "StandX 下单异常",
                f"{self.config.symbol} {side} 下单异常: {e}",
                priority="high"
            )
    
    def set_reduce_log_file(self, filepath: str):
        """Set the file path for reduce position logging."""
        self._reduce_log_file = filepath
    
    def _write_reduce_log(self, action: str, qty_change: float, reason: str):
        """Write reduce position log."""
        if not self._reduce_log_file:
            return
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self._reduce_log_file, "a") as f:
                f.write(f"{timestamp},{action},{qty_change:+.4f},{reason}\n")
        except:
            pass
    
    async def _check_and_reduce_position(self) -> bool:
        """
        Check if position should be reduced and execute.
        
        Logic:
        - If abs(position) > max_position * 0.5 AND uPNL > 0
        - Reduce to max_position * 0.4 using market order
        
        Returns:
            True if reduction was executed, False otherwise
        """
        max_pos = self.config.max_position_btc
        threshold = max_pos * 0.7
        target = max_pos * 0.5
        
        current_pos = abs(self.state.position)
        if current_pos <= threshold:
            return False
        
        # Query current uPNL for this position
        try:
            positions = await self.client.query_positions(self.config.symbol)
            if not positions:
                return False
            
            upnl = positions[0].upnl
            if upnl <= 0:
                logger.debug(f"Position {current_pos:.4f} > threshold but uPNL={upnl:.2f} <= 0, skip reduce")
                return False
            
            # Calculate reduce quantity
            reduce_qty = current_pos - target
            if reduce_qty <= 0:
                return False
            
            # Determine side: if position is long, sell to reduce; if short, buy to reduce
            if self.state.position > 0:
                reduce_side = "sell"
            else:
                reduce_side = "buy"
            
            logger.info(
                f"Reducing position: {self.state.position:+.4f} -> {'+' if self.state.position > 0 else ''}{self.state.position - reduce_qty if self.state.position > 0 else self.state.position + reduce_qty:.4f}, "
                f"qty={reduce_qty:.4f}, side={reduce_side}, uPNL=${upnl:.2f}"
            )
            
            # Place market order to reduce
            import math
            cl_ord_id = f"reduce-{uuid.uuid4().hex[:8]}"
            
            # Format quantity
            qty_str = f"{reduce_qty:.3f}"
            
            response = await self.client.new_order(
                symbol=self.config.symbol,
                side=reduce_side,
                qty=qty_str,
                price="0",  # Market order
                cl_ord_id=cl_ord_id,
                order_type="market",
                reduce_only=True,
            )
            
            if response.get("code") == 0 or "id" in response:
                logger.info(f"Reduce order placed: {cl_ord_id}")
                self._write_reduce_log("REDUCE", -reduce_qty if reduce_side == "sell" else reduce_qty, f"profit_take_upnl_{upnl:.2f}")
                send_notify(
                    "仓位减仓",
                    f"{self.config.symbol} 减仓 {reduce_qty:.4f}，uPNL=${upnl:.2f}",
                    priority="normal"
                )
                return True
            else:
                logger.error(f"Reduce order failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to check/reduce position: {e}")
            return False

