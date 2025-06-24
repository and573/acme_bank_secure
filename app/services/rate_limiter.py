"""Rate limiting service for ACME Bank."""

import time
from collections import defaultdict
from datetime import datetime
import threading
from typing import Dict, List, Tuple


class RateLimiter:
    """Rate limiting implementation."""
    
    def __init__(self):
        self.RATE_LIMITS = {
            'default': (10, 60),     # 10 requests per minute
            'search': (5, 60),       # 5 searches per minute
            'payment': (10, 3600),   # 10 payments per hour
        }
        
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        
        self._cleanup_thread = threading.Thread(target=self._cleanup_old_requests, daemon=True)
        self._cleanup_thread.start()

    def is_allowed(self, key: str, limit_type: str = 'default') -> Tuple[bool, Dict]:
        """Check if request is allowed under rate limit."""
        with self._lock:
            now = time.time()
            max_requests, window = self.RATE_LIMITS.get(limit_type, self.RATE_LIMITS['default'])
            cache_key = f"{key}:{limit_type}"
            
            self._requests[cache_key] = [
                req_time for req_time in self._requests[cache_key]
                if now - req_time < window
            ]
            
            current_requests = len(self._requests[cache_key])
            remaining = max_requests - current_requests
            reset_time = min(self._requests[cache_key] + [now]) + window if self._requests[cache_key] else now + window
            
            if current_requests >= max_requests:
                return False, {
                    'limit': max_requests,
                    'remaining': 0,
                    'reset': datetime.fromtimestamp(reset_time).strftime('%Y-%m-%d %H:%M:%S'),
                    'retry_after': int(reset_time - now)
                }
            
            self._requests[cache_key].append(now)
            
            return True, {
                'limit': max_requests,
                'remaining': remaining - 1,
                'reset': datetime.fromtimestamp(reset_time).strftime('%Y-%m-%d %H:%M:%S')
            }

    def _cleanup_old_requests(self):
        """Periodically clean up old request records."""
        while True:
            time.sleep(60)  # Run cleanup every minute
            with self._lock:
                now = time.time()
                max_window = max(window for _, window in self.RATE_LIMITS.values())
                
                for key in list(self._requests.keys()):
                    self._requests[key] = [
                        req_time for req_time in self._requests[key]
                        if now - req_time < max_window
                    ]
                    if not self._requests[key]:
                        del self._requests[key]
