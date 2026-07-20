import {
  Asterisk,
  Atom,
  Bot,
  Sparkles,
  Waves,
  type LucideIcon,
} from "lucide-react";

const PROVIDER_GLYPHS: Record<string, LucideIcon> = {
  openai: Atom,
  anthropic: Asterisk,
  deepseek: Waves,
  gemini: Sparkles,
  ollama: Bot,
  "ollama-cloud": Bot,
};

// Maps a provider_type to its brand glyph (monochrome, so it inherits the
// surrounding text color). Unknown / generic types (openai-compat, custom)
// fall back to a neutral robot icon.
export function ProviderBrandIcon({ type, size = 16 }: { type: string; size?: number }) {
  const Glyph = PROVIDER_GLYPHS[type] ?? Bot;
  return <Glyph size={size} aria-hidden="true" />;
}
