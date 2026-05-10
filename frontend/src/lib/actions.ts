export type ActionFeedback = {
  ok: boolean;
  level: string;
  message: string;
};

export async function postBackendAction(
  endpoint: string,
  fields: Record<string, string | number | boolean | null | undefined> = {},
): Promise<ActionFeedback> {
  const payload = Object.fromEntries(
    Object.entries(fields).filter(([, value]) => value !== null && value !== undefined),
  );

  const response = await fetch(endpoint, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/html;q=0.9, */*;q=0.8",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    return {
      ok: false,
      level: "error",
      message: `HTTP ${response.status}`,
    };
  }

  return (await response.json()) as ActionFeedback;
}
