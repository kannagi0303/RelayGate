type BackendEventHandlers = {
  onOpen: () => void;
  onClose: () => void;
  onMessage: (eventName: string, data: unknown) => void;
};

let activeSource: EventSource | null = null;
let activeHandlers: BackendEventHandlers | null = null;

export function connectBackendEvents(handlers: BackendEventHandlers) {
  activeHandlers = handlers;

  if (activeSource && activeSource.readyState !== EventSource.CLOSED) {
    if (activeSource.readyState === EventSource.OPEN) {
      activeHandlers.onOpen();
    }
    return;
  }

  const source = new EventSource("/backend/events");
  activeSource = source;

  source.onopen = () => activeHandlers?.onOpen();
  source.onerror = () => {
    activeHandlers?.onClose();
    if (source.readyState === EventSource.CLOSED && activeSource === source) {
      activeSource = null;
    }
  };
  source.onmessage = (event) => {
    activeHandlers?.onMessage(event.type || "message", parseEventData(event.data));
  };

  source.addEventListener("backend_full", (event) => {
    activeHandlers?.onMessage("backend_full", parseEventData(event.data));
  });
  source.addEventListener("i18n_full", (event) => {
    activeHandlers?.onMessage("i18n_full", parseEventData(event.data));
  });
}

function parseEventData(data: string) {
  try {
    return JSON.parse(data);
  } catch {
    return data;
  }
}
