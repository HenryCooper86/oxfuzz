// Import brand glyphs from their subpaths (not the package barrel): the barrel
// re-exports @lobehub/icons "features" that pull in antd-style/antd, which we
// don't depend on. The per-icon dirs are self-contained React SVG components.
import OpenAI from "@lobehub/icons/es/OpenAI";
import Anthropic from "@lobehub/icons/es/Anthropic";
import DeepSeek from "@lobehub/icons/es/DeepSeek";
import Gemini from "@lobehub/icons/es/Gemini";
import Ollama from "@lobehub/icons/es/Ollama";
import { Bot } from "lucide-react";

// Maps a provider_type to its brand glyph (monochrome, so it inherits the
// surrounding text color). Unknown / generic types (openai-compat, custom)
// fall back to a neutral robot icon.
export function ProviderBrandIcon({ type, size = 16 }: { type: string; size?: number }) {
  switch (type) {
    case "openai":
      return <OpenAI size={size} />;
    case "anthropic":
      return <Anthropic size={size} />;
    case "deepseek":
      return <DeepSeek size={size} />;
    case "gemini":
      return <Gemini size={size} />;
    case "ollama":
      return <Ollama size={size} />;
    default:
      return <Bot size={size} />;
  }
}
