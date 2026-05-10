import DOMPurify from "dompurify";
import MarkdownIt from "markdown-it";

const markdown = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: false,
});

export function renderMarkdown(source: string): string {
  const rendered = markdown.render(source);
  return DOMPurify.sanitize(rendered, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "script"],
    ALLOWED_ATTR: ["href", "target", "rel"],
  });
}
