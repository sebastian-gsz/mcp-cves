# ratelimit.py — limitador de ritmo por ventana fija, thread-safe (NUC-001).
import threading
import time


class TokenBucket:
    """Permite hasta `capacity` adquisiciones por cada ventana de `window_s` segundos.

    Ventana fija (no rodante): aproximación conservadora y sencilla para respetar límites
    del tipo «N peticiones cada M segundos» (NVD: 5/30s sin clave, 50/30s con clave).
    Un mismo bucket compartido entre hilos impone el presupuesto global del proceso.
    """

    def __init__(self, capacity: int, window_s: float = 30.0):
        if capacity < 1 or window_s <= 0:
            raise ValueError("capacity >= 1 y window_s > 0")
        self.capacity = int(capacity)
        self.window_s = float(window_s)
        self._lock = threading.Lock()
        self._window_start = time.monotonic()
        self._used = 0

    def acquire(self, timeout_s: float | None = None) -> bool:
        """Reserva una petición, bloqueando hasta que la ventana renueve presupuesto.

        Devuelve True al reservar; False si se agota timeout_s esperando.
        """
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._window_start
                if elapsed >= self.window_s:
                    self._window_start = now
                    self._used = 0
                    elapsed = 0.0
                if self._used < self.capacity:
                    self._used += 1
                    return True
                wait = self.window_s - elapsed
            if deadline is not None and time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.5))
