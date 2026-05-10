type BackendEventHandlers = {
  onOpen: () => void;
  onClose: () => void;
  onMessage: (eventName: string, data: unknown) => void;
};

let activeSource: EventSource | null = null;

export function connectBackendEvents(handlers: BackendEventHandlers) {
  if (activeSource) {
    return;
  }

  const source = new EventSource("/backend/events");
  activeSource = source;

  source.onopen = () => handlers.onOpen();
  source.onerror = () => handlers.onClose();
  source.onmessage = (event) => {
    handlers.onMessage(event.type || "message", parseEventData(event.data));
  };

  source.addEventListener("backend_full", (event) => {
    handlers.onMessage("backend_full", parseEventData(event.data));
  });
  source.addEventListener("i18n_full", (event) => {
    handlers.onMessage("i18n_full", parseEventData(event.data));
  });
}

function parseEventData(data: string) {
  try {
    return JSON.parse(data);
  } catch {
    return data;
  }
}
