"""Optional AI worker. No thread or event loop starts at construction/configuration."""

import asyncio
import threading
from collections.abc import Awaitable, Callable

from PySide6.QtCore import QObject, Qt, QTimer, Signal

from wfdiag.ai.contracts import AiErrorCode, Consent
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.policy import AiFailure
from wfdiag.ai.service import AiSession, Prepared


class AiController(QObject):
    completed = Signal(int, object, str)
    result = Signal(object, str)
    activity = Signal(bool)

    def __init__(self, parent: QObject, session: AiSession | None = None) -> None:
        super().__init__(parent)
        self.session = session if session is not None else AiSession()
        self.generation = 0
        self.worker_thread: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.task: asyncio.Task[object] | None = None
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.completed.connect(self._completed, Qt.ConnectionType.QueuedConnection)

    @property
    def busy(self) -> bool:
        return self.worker_thread is not None

    def launch(self, action: Callable[[], Awaitable[object]]) -> None:
        if self.busy:
            raise AiFailure(AiErrorCode.CONFIGURATION)
        self.stop.clear()
        generation = self.generation

        async def work() -> object:
            with self.lock:
                self.loop = asyncio.get_running_loop()
                self.task = asyncio.current_task()
            if self.stop.is_set():
                raise AiFailure(AiErrorCode.CANCELLED)
            value = await action()
            if self.stop.is_set():
                raise AiFailure(AiErrorCode.CANCELLED)
            return value

        def run() -> None:
            value: object = None
            code = ""
            coroutine = work()
            try:
                value = asyncio.run(coroutine)
            except AiFailure as error:
                code = error.code.value
            except asyncio.CancelledError:
                code = AiErrorCode.CANCELLED.value
            except Exception:  # noqa: BLE001 -- never emit request-bearing exception text.
                code = AiErrorCode.PROVIDER_FAILURE.value
            finally:
                coroutine.close()
                with self.lock:
                    self.loop = None
                    self.task = None
            self.completed.emit(generation, value, code)

        self.worker_thread = threading.Thread(target=run, name="WFDiag-OptionalAI", daemon=False)
        self.activity.emit(True)
        try:
            self.worker_thread.start()
        except RuntimeError:
            self.worker_thread = None
            self.activity.emit(False)
            raise AiFailure(AiErrorCode.PROVIDER_FAILURE) from None

    def review(self, build: Callable[[], Prepared]) -> None:
        self.call(build)

    def call(self, build: Callable[[], object]) -> None:
        async def prepare() -> object:
            return build()

        self.launch(prepare)

    def send(self, prepared: Prepared, consent: Consent, key: KeyMaterial) -> None:
        async def send() -> object:
            return await self.session.send(prepared, consent, key)

        self.launch(send)

    def invalidate(self) -> None:
        self.generation += 1
        self.cancel()

    def cancel(self) -> None:
        if self.stop.is_set():
            return
        self.stop.set()
        with self.lock:
            loop, task = self.loop, self.task
            if loop is not None and task is not None:
                try:
                    loop.call_soon_threadsafe(task.cancel)
                except RuntimeError:
                    pass  # The owned loop finished concurrently.

    def _completed(self, generation: int, value: object, code: str) -> None:
        thread = self.worker_thread
        if thread is not None and thread.is_alive():
            QTimer.singleShot(10, lambda: self._completed(generation, value, code))
            return
        if thread is not None:
            thread.join(timeout=0)
        self.worker_thread = None
        self.activity.emit(False)
        if generation == self.generation:
            self.result.emit(value, code)
        else:
            self.result.emit(None, AiErrorCode.CANCELLED.value)
