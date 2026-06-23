// Shared Vitest setup -- stubs browser globals.

class MockEventSource {
  static CLOSED = 2;
  readyState = 0;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onopen: ((ev: Event) => void) | null = null;
  addEventListener() {}
  removeEventListener() {}
  close() {
    this.readyState = MockEventSource.CLOSED;
  }
}

if (typeof globalThis.EventSource === "undefined") {
  (globalThis as unknown as { EventSource: typeof MockEventSource }).EventSource = MockEventSource;
}